/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { URI } from '../../../../../base/common/uri.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import {
	buildExtensionHostCrashRecord,
	classifyExtensionHostExit,
	crashRecordTelemetryData,
} from '../../common/extensionHostCrashRecord.js';
import {
	analyzeHeapCapturePair,
	decideAutomaticHeapCapture,
	decideTier0Attribution,
	createHeapAttributionRateLimitState,
	createHeapCaptureRateLimitState,
	HEAP_CAPTURE_COOLDOWN_MS,
	HeapDiagnosisCoordinator,
	inspectNearHeapLimitSnapshots,
	markHeapCaptureFinished,
	nearHeapLimitExecArgv,
	refuseHeapDiagnosisCommandIfGatedOff,
	withNearHeapLimitExecArgv,
	type HeapDiagnosisCaptureHooks,
} from '../../common/extensionHostHeapWiring.js';
import type { AllocationSamplingProfile, ExtHostHeapAttributionSafeSummary } from '../../common/extensionHostHeapDiagnosis.js';

suite('extensionHostHeapWiring', () => {

	function leakySamplingProfile(leakyUrl: string, tidyUrl: string): AllocationSamplingProfile {
		return {
			head: {
				id: 1,
				selfSize: 0,
				callFrame: { functionName: '(root)', scriptId: '0', url: '', lineNumber: 0, columnNumber: 0 },
				children: [
					{
						id: 2,
						selfSize: 180 * 1024 * 1024,
						callFrame: { functionName: 'activateEvent', scriptId: '1', url: leakyUrl, lineNumber: 10, columnNumber: 0 },
						children: [],
					},
					{
						id: 3,
						selfSize: 20 * 1024 * 1024,
						callFrame: { functionName: 'activateEvent', scriptId: '2', url: tidyUrl, lineNumber: 10, columnNumber: 0 },
						children: [],
					},
				],
			},
		};
	}

	function makeHooks(args: {
		readonly gateEnabled: boolean;
		readonly emitted: ExtHostHeapAttributionSafeSummary[];
		readonly snapshots: string[];
		readonly nowMs?: () => number;
		readonly pairDelayMs?: number;
	}): HeapDiagnosisCaptureHooks {
		const leakyDir = '/tmp/exts/leaky.ext';
		const tidyDir = '/tmp/exts/tidy.ext';
		const leakyUrl = URI.file(`${leakyDir}/extension.js`).toString(true);
		const tidyUrl = URI.file(`${tidyDir}/extension.js`).toString(true);
		return {
			writeSnapshot: (path) => {
				args.snapshots.push(path);
				return path;
			},
			startSampling: async () => { },
			getSamplingProfile: async () => leakySamplingProfile(leakyUrl, tidyUrl),
			extractClassGroupsFromSnapshot: async (path) => {
				const isBaseline = path.includes('-baseline');
				if (isBaseline) {
					return [
						{ name: 'ArrayBuffer', category: 'arraybuffer', count: 10, selfSize: 10 * 1024 * 1024, retainedSize: 10 * 1024 * 1024 },
					];
				}
				return [
					{ name: 'ArrayBuffer', category: 'arraybuffer', count: 200, selfSize: 200 * 1024 * 1024, retainedSize: 200 * 1024 * 1024 },
					{ name: '(closure)', category: 'closure', count: 50, selfSize: 5 * 1024 * 1024, retainedSize: 40 * 1024 * 1024 },
				];
			},
			delay: async () => { },
			nowMs: args.nowMs ?? (() => 1_000_000),
			listExtensionLocations: () => [
				{ id: 'leaky.ext', location: URI.file(leakyDir) },
				{ id: 'tidy.ext', location: URI.file(tidyDir) },
			],
			artifactDirFsPath: '/tmp/eh-heap-artifacts',
			pid: 4242,
			affinity: 0,
			emitSafeSummary: (summary) => { args.emitted.push(summary); },
			logLocalReport: () => { },
			isGateEnabled: () => args.gateEnabled,
			pairDelayMs: args.pairDelayMs ?? 0,
		};
	}

	test('(a) simulated sampler alert triggers capture+analysis naming leaky fixture + passes guard', async () => {
		const leakyDir = '/tmp/exts/leaky.ext';
		const tidyDir = '/tmp/exts/tidy.ext';
		const leakyUrl = URI.file(`${leakyDir}/extension.js`).toString(true);
		const tidyUrl = URI.file(`${tidyDir}/extension.js`).toString(true);
		const emitted: ExtHostHeapAttributionSafeSummary[] = [];
		const snapshots: string[] = [];
		let reports = '';

		const coordinator = new HeapDiagnosisCoordinator({
			...makeHooks({ gateEnabled: true, emitted, snapshots }),
			logLocalReport: (text) => { reports = text; },
		});
		await coordinator.startContinuousSampling();

		const started = coordinator.onMemoryAlert();
		assert.strictEqual(started.attribution.started, true, 'alert must start Tier-0 attribution');
		assert.strictEqual(started.snapshot.started, true, 'gate ON must start Tier-1 snapshot pair');
		// Allow fire-and-forget async work to finish.
		await new Promise(r => setTimeout(r, 30));

		assert.ok(emitted.length >= 1, 'must emit at least one safe attribution summary');
		assert.ok(snapshots.length >= 2, 'Tier-1 must write baseline+current snapshots when gate ON');
		const summary = emitted[0]!;
		assert.strictEqual(summary.extensions[0]!.extRef, 'ext-1');
		assert.ok(summary.extensions[0]!.sharePct >= 60, `leaky share ${summary.extensions[0]!.sharePct}`);
		assert.ok(reports.includes('leaky.ext'), 'local report names the leaky fixture');
		assert.ok(!JSON.stringify(summary).includes('leaky.ext'), 'safe summary stays opaque');

		const analyzed = analyzeHeapCapturePair({
			before: [{ name: 'ArrayBuffer', category: 'arraybuffer', count: 10, selfSize: 10, retainedSize: 10 }],
			after: [{ name: 'ArrayBuffer', category: 'arraybuffer', count: 200, selfSize: 200, retainedSize: 200 * 1024 * 1024 }],
			profile: leakySamplingProfile(leakyUrl, tidyUrl),
			extensionLocations: [
				{ id: 'leaky.ext', location: URI.file(leakyDir) },
				{ id: 'tidy.ext', location: URI.file(tidyDir) },
			],
			pid: 4242,
			snapshotSeq: 1,
		});
		assert.strictEqual(analyzed.reportMeta.opaqueToExtensionId['ext-1'], 'leaky.ext');

		const guard = detectTelemetryUserData(
			{ ...summary, pluginHostTelemetry: true },
			{
				markers: ['/tmp/exts/leaky.ext', 'leaky.ext'],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostHeapAttribution',
			},
		);
		assert.strictEqual(guard.hit, false, `exthostHeapAttribution must pass guard, got ${JSON.stringify(guard)}`);

		// Rate-limit: second alert within cooldown skips Tier-0 attribution.
		const skipped = coordinator.onMemoryAlert();
		assert.strictEqual(skipped.attribution.started, false);
		if (!skipped.attribution.started) {
			assert.ok(skipped.attribution.reason === 'cooldown' || skipped.attribution.reason === 'in-flight');
		}
	});

	test('(b) near-limit execArgv flag is present in EH launch args when gate ON', () => {
		const diagnosticDir = '/Users/me/logs/window1/exthost';
		const flags = nearHeapLimitExecArgv(diagnosticDir);
		assert.ok(flags.includes('--heapsnapshot-near-heap-limit=1'));
		assert.ok(flags.includes(`--diagnostic-dir=${diagnosticDir}`));

		const withFlags = withNearHeapLimitExecArgv(['--inspect-port=0'], diagnosticDir, true);
		assert.ok(withFlags.includes('--heapsnapshot-near-heap-limit=1'));
		assert.ok(withFlags.includes('--inspect-port=0'));

		const gatedOff = withNearHeapLimitExecArgv(['--inspect-port=0'], diagnosticDir, false);
		assert.deepStrictEqual(gatedOff, ['--inspect-port=0']);
	});

	test('(c) crash record carries numbers-only heapSnapshot fields', () => {
		const scanned = inspectNearHeapLimitSnapshots(
			[
				{ name: 'Heap.2026-08-10.4242.heapsnapshot', sizeBytes: 512 * 1024 * 1024, mtimeMs: 2_000 },
				{ name: 'exthost-stderr.log', sizeBytes: 100, mtimeMs: 2_000 },
			],
			1_000,
		);
		assert.strictEqual(scanned.heapSnapshotCaptured, true);
		assert.strictEqual(scanned.heapSnapshotSizeBucketMb, 512);

		const classification = classifyExtensionHostExit({
			code: 134,
			reason: 'oom',
			stderrOomSeen: true,
			lastRssBucketMb: 6144,
		});
		const record = buildExtensionHostCrashRecord({
			ts: 1_700_000_000_000,
			code: 134,
			signal: 'unknown',
			reason: 'oom',
			classification,
			affinity: 0,
			pid: 4242,
			uptimeSec: 90,
			lastRssBucketMb: 6144,
			lastHeapUsedMb: 5800,
			secondsSinceLastSample: 12,
			secondsSinceLastAlert: 40,
			extensionIds: ['pub.extA'],
			heapSnapshotCaptured: scanned.heapSnapshotCaptured,
			heapSnapshotSizeBucketMb: scanned.heapSnapshotSizeBucketMb,
		});
		assert.strictEqual(record.heapSnapshotCaptured, true);
		assert.strictEqual(record.heapSnapshotSizeBucketMb, 512);
		const json = JSON.stringify(record);
		assert.ok(!json.includes('.heapsnapshot'));
		assert.ok(!json.includes('/Users/'));

		const telemetry = crashRecordTelemetryData(record);
		assert.strictEqual(telemetry.heapSnapshotCaptured, true);
		assert.strictEqual(telemetry.heapSnapshotSizeBucketMb, 512);
		const guard = detectTelemetryUserData(telemetry, {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName: 'exthostCrashRecord',
		});
		assert.strictEqual(guard.hit, false, `crash record+heapSnapshot must pass guard, got ${JSON.stringify(guard)}`);
	});

	test('(d) command refuses when the internal flag is off', () => {
		const refused = refuseHeapDiagnosisCommandIfGatedOff(false);
		assert.ok(refused);
		assert.strictEqual(refused!.ok, false);
		if (refused && !refused.ok) {
			assert.strictEqual(refused.reason, 'internal-diagnostics-disabled');
		}
		assert.strictEqual(refuseHeapDiagnosisCommandIfGatedOff(true), undefined);

		const decision = decideAutomaticHeapCapture(createHeapCaptureRateLimitState(), {
			nowMs: 0,
			gateEnabled: false,
		});
		assert.strictEqual(decision.allow, false);
		if (!decision.allow) {
			assert.strictEqual(decision.reason, 'gate-off');
		}

		const cooled = markHeapCaptureFinished(createHeapCaptureRateLimitState(), {
			nowMs: 1000,
			succeeded: true,
			countTowardSessionLimit: true,
		});
		assert.strictEqual(cooled.nextAllowedMs, 1000 + HEAP_CAPTURE_COOLDOWN_MS);
		assert.strictEqual(cooled.pairsThisSession, 1);
	});

	test('(e) Tier-0 attribution emits with internal flag OFF and passes guard', async () => {
		const emitted: ExtHostHeapAttributionSafeSummary[] = [];
		const snapshots: string[] = [];
		const coordinator = new HeapDiagnosisCoordinator(makeHooks({
			gateEnabled: false,
			emitted,
			snapshots,
		}));
		await coordinator.startContinuousSampling();

		const dispatch = coordinator.onMemoryAlert();
		assert.strictEqual(dispatch.attribution.started, true, 'Tier-0 attribution must start with gate OFF');
		assert.strictEqual(dispatch.snapshot.started, false, 'Tier-1 snapshot must NOT start with gate OFF');
		if (!dispatch.snapshot.started) {
			assert.strictEqual(dispatch.snapshot.reason, 'gate-off');
		}

		await new Promise(r => setTimeout(r, 30));

		assert.strictEqual(emitted.length, 1, 'exactly one Tier-0 attribution emission');
		assert.strictEqual(snapshots.length, 0, 'raw snapshot capture must stay gated OFF');

		const summary = emitted[0]!;
		assert.strictEqual(summary.extensions[0]!.extRef, 'ext-1');
		assert.ok(summary.extensions[0]!.sharePct >= 60);
		assert.ok(['high', 'medium', 'low'].includes(summary.extensions[0]!.confidence));
		assert.strictEqual(typeof summary.extensions[0]!.lanesAgree, 'boolean');
		assert.ok(summary.grownClassGroups.length >= 1, 'enriched class-category enums present');
		assert.ok(typeof summary.grownClassGroups[0]!.category === 'string');
		assert.ok(typeof summary.dominatorDepth === 'number');
		assert.ok(typeof summary.dominatorFanout === 'number');
		assert.ok(typeof summary.retainedTopSharePct === 'number');

		const json = JSON.stringify(summary);
		assert.ok(!json.includes('leaky.ext'), 'no marketplace id');
		assert.ok(!json.includes('/tmp/'), 'no path');
		assert.ok(!json.includes('ArrayBuffer'), 'no constructor name');
		assert.ok(!json.includes('activateEvent'), 'no function name');
		assert.ok(!json.includes('sampled-live'), 'local-only label must not telemeter');

		const guard = detectTelemetryUserData(
			{ ...summary, pluginHostTelemetry: true },
			{
				markers: ['/tmp/exts/leaky.ext', 'leaky.ext', 'activateEvent'],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostHeapAttribution',
			},
		);
		assert.strictEqual(guard.hit, false, `Tier-0 summary must pass guard, got ${JSON.stringify(guard)}`);
	});

	test('(f) Tier-0 decideTier0Attribution ignores the internal gate', () => {
		const allowed = decideTier0Attribution(createHeapAttributionRateLimitState(), { nowMs: 0 });
		assert.strictEqual(allowed.allow, true);
		const blocked = decideTier0Attribution(
			{ nextAllowedMs: 10_000, inFlight: false },
			{ nowMs: 0 },
		);
		assert.strictEqual(blocked.allow, false);
		if (!blocked.allow) {
			assert.strictEqual(blocked.reason, 'cooldown');
		}
	});

	test('(g) raw snapshot capture remains gated OFF without the internal flag', async () => {
		const emitted: ExtHostHeapAttributionSafeSummary[] = [];
		const snapshots: string[] = [];
		const coordinator = new HeapDiagnosisCoordinator(makeHooks({
			gateEnabled: false,
			emitted,
			snapshots,
		}));
		await coordinator.startContinuousSampling();

		const cmd = await coordinator.captureAndDiagnoseCommand();
		assert.strictEqual(cmd.ok, false);
		if (!cmd.ok) {
			assert.strictEqual(cmd.reason, 'internal-diagnostics-disabled');
		}
		assert.strictEqual(snapshots.length, 0, 'command must not write snapshots when gate OFF');

		const alert = coordinator.onMemoryAlert();
		assert.strictEqual(alert.snapshot.started, false);
		await new Promise(r => setTimeout(r, 20));
		assert.strictEqual(snapshots.length, 0, 'alert must not write snapshots when gate OFF');
	});
});
