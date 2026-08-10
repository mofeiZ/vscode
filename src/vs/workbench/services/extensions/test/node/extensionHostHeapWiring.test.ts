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
	createHeapCaptureRateLimitState,
	HEAP_CAPTURE_COOLDOWN_MS,
	HeapDiagnosisCoordinator,
	inspectNearHeapLimitSnapshots,
	markHeapCaptureFinished,
	nearHeapLimitExecArgv,
	refuseHeapDiagnosisCommandIfGatedOff,
	withNearHeapLimitExecArgv,
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

	test('(a) simulated sampler alert triggers capture+analysis naming leaky fixture + passes guard', async () => {
		const leakyDir = '/tmp/exts/leaky.ext';
		const tidyDir = '/tmp/exts/tidy.ext';
		const leakyUrl = URI.file(`${leakyDir}/extension.js`).toString(true);
		const tidyUrl = URI.file(`${tidyDir}/extension.js`).toString(true);
		const emitted: ExtHostHeapAttributionSafeSummary[] = [];
		let reports = '';

		const coordinator = new HeapDiagnosisCoordinator({
			writeSnapshot: (path) => path,
			startSampling: async () => { },
			stopAndGetProfile: async () => leakySamplingProfile(leakyUrl, tidyUrl),
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
			nowMs: () => 1_000_000,
			listExtensionLocations: () => [
				{ id: 'leaky.ext', location: URI.file(leakyDir) },
				{ id: 'tidy.ext', location: URI.file(tidyDir) },
			],
			artifactDirFsPath: '/tmp/eh-heap-artifacts',
			pid: 4242,
			affinity: 0,
			emitSafeSummary: (summary) => { emitted.push(summary); },
			logLocalReport: (text) => { reports = text; },
			isGateEnabled: () => true,
			pairDelayMs: 0,
		});

		const started = coordinator.onMemoryAlert();
		assert.strictEqual(started.started, true, 'alert must start a rate-limited capture');
		// Allow the fire-and-forget async pair to finish.
		await new Promise(r => setTimeout(r, 20));

		assert.strictEqual(emitted.length, 1, 'must emit one safe attribution summary');
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

		// Rate-limit: second alert within cooldown is skipped.
		const skipped = coordinator.onMemoryAlert();
		assert.strictEqual(skipped.started, false);
		if (!skipped.started) {
			assert.ok(skipped.reason === 'cooldown' || skipped.reason === 'in-flight' || skipped.reason === 'max-pairs');
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
});
