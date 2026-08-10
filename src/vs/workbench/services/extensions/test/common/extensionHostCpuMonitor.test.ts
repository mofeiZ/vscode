/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { URI } from '../../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import { checkGuardSafePayload, tryGuardSafeEmit, type GuardSafeTelemetrySink } from '../../../../../platform/telemetry/common/guardSafeEmit.js';
import { SessionEntityIdMap } from '../../../../../platform/telemetry/common/opaqueIds.js';
import type { IV8Profile } from '../../../../../platform/profiling/common/profiling.js';
import {
	distillProfileByUrlCategory,
	rankedSegmentTimes,
} from '../../common/profileDistill.js';
import {
	attributeCpuProfile,
	bucketCpuPct,
	bucketSharePct,
	buildCpuAlertTelemetryPayload,
	buildCpuSampleTelemetryPayload,
	computeCpuPct,
	CPU_PROFILE_MAX_PER_SESSION,
	CPU_PROFILE_MIN_INTERVAL_MS,
	CPU_SUSTAIN_SAMPLES,
	CPU_SUSTAIN_THRESHOLD_PCT,
	CPU_TOP_SHARE_ALERT_PCT,
	createCpuAlertState,
	decideCpuProfileTrigger,
	ExtensionHostCpuMonitor,
} from '../../common/extensionHostCpuMonitor.js';

/**
 * Synthetic busy-loop V8 profile: most sample time under busy.ext's install root,
 * minority under tidy.ext. Shape matches what `_distill` / profileDistill consume.
 *
 * Distill only rewrites `self`→extension on URL match, so JS frames must be
 * siblings of `(program)` under `(root)` (not descendants of `(program)`).
 */
function buildBusyLoopProfile(busyRoot: URI, tidyRoot: URI): IV8Profile {
	// Tree:
	// 0 (root)
	//  ├─ 1 (program)
	//  └─ 2 (anonymous / self) url=""
	//      ├─ 3 busyLoop   url=busyRoot/out/hot.js
	//      └─ 4 tidyWork   url=tidyRoot/out/cool.js
	return {
		startTime: 1_000,
		endTime: 2_000,
		nodes: [
			{
				id: 0,
				callFrame: { functionName: '(root)', scriptId: '0', url: '', lineNumber: -1, columnNumber: -1 },
				children: [1, 2],
			},
			{
				id: 1,
				callFrame: { functionName: '(program)', scriptId: '0', url: '', lineNumber: -1, columnNumber: -1 },
				children: [],
			},
			{
				id: 2,
				callFrame: { functionName: '(anonymous)', scriptId: '1', url: '', lineNumber: 0, columnNumber: 0 },
				children: [3, 4],
			},
			{
				id: 3,
				callFrame: {
					functionName: 'busyLoop',
					scriptId: '2',
					url: URI.joinPath(busyRoot, 'out', 'hot.js').toString(true),
					lineNumber: 10,
					columnNumber: 0,
				},
				children: [],
			},
			{
				id: 4,
				callFrame: {
					functionName: 'tidyWork',
					scriptId: '3',
					url: URI.joinPath(tidyRoot, 'out', 'cool.js').toString(true),
					lineNumber: 2,
					columnNumber: 0,
				},
				children: [],
			},
		],
		// 8 samples on busy, 2 on tidy → 80% / 20%
		samples: [3, 3, 3, 3, 3, 3, 3, 3, 4, 4],
		timeDeltas: [100, 100, 100, 100, 100, 100, 100, 100, 100, 100],
	};
}

suite('extensionHostCpuMonitor (P-B / r15 Category B)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	test('bucketCpuPct / computeCpuPct closed edges', () => {
		assert.strictEqual(bucketCpuPct(0), 0);
		assert.strictEqual(bucketCpuPct(4), 0);
		assert.strictEqual(bucketCpuPct(5), 5);
		assert.strictEqual(bucketCpuPct(49), 25);
		assert.strictEqual(bucketCpuPct(50), 50);
		assert.strictEqual(bucketCpuPct(99), 75);
		assert.strictEqual(bucketCpuPct(100), 100);
		assert.strictEqual(bucketCpuPct(250), 200);
		// 50% of one core over 30s → user+system = 0.5 * 30_000_000 µs
		assert.ok(Math.abs(computeCpuPct({ user: 10_000_000, system: 5_000_000 }, 30_000) - 50) < 0.01);
		assert.strictEqual(bucketSharePct(64), 60);
		assert.strictEqual(bucketSharePct(95), 90);
		assert.strictEqual(bucketSharePct(100), 100);
	});

	test('synthetic busy-loop V8 profile attributes to opaque ext id (never the real id)', () => {
		// Workspace-path marker trap in fixture roots (u28 guard red-team habit).
		const pathTrap = '/Users/alice/secret-fixture/proj';
		const busyRoot = URI.file(`${pathTrap}/extensions/busy.ext`);
		const tidyRoot = URI.file(`${pathTrap}/extensions/tidy.ext`);
		const busyRealId = 'busy.ext';
		const tidyRealId = 'tidy.ext';

		const profile = buildBusyLoopProfile(busyRoot, tidyRoot);
		const categories: Array<[string, string]> = [
			[URI.file(busyRoot.fsPath).toString(true), busyRealId],
			[URI.file(tidyRoot.fsPath).toString(true), tidyRealId],
		];

		const distilled = distillProfileByUrlCategory(profile, categories);
		const ranked = rankedSegmentTimes(distilled.getAggregatedTimes());
		assert.ok(ranked.length >= 1);
		assert.strictEqual(ranked[0]!.segmentId, busyRealId);
		assert.ok(ranked[0]!.sharePct >= CPU_TOP_SHARE_ALERT_PCT, `busy share ${ranked[0]!.sharePct}`);

		const opaqueIds = new SessionEntityIdMap('ext');
		const attribution = attributeCpuProfile(profile, categories, opaqueIds);
		assert.strictEqual(attribution.resultKind, 'extension');
		assert.ok(attribution.topOpaqueExtId);
		assert.ok(/^ext-\d+$/.test(attribution.topOpaqueExtId!), attribution.topOpaqueExtId);
		assert.notStrictEqual(attribution.topOpaqueExtId, busyRealId);
		assert.notStrictEqual(attribution.topOpaqueExtId, tidyRealId);
		assert.strictEqual(attribution.topRealExtId, busyRealId);
		assert.ok(attribution.topSharePct >= CPU_TOP_SHARE_ALERT_PCT);
		assert.strictEqual(attribution.topOpaqueExtId, opaqueIds.opaqueId(busyRealId));

		const alert = buildCpuAlertTelemetryPayload({
			cpuPctBucket: 50,
			sustainedSec: 90,
			attribution,
			profileMs: 5000,
		});
		assert.strictEqual(alert.topOpaqueExtId, attribution.topOpaqueExtId);
		assert.strictEqual(alert.resultKind, 'extension');
		assert.ok(alert.topSharePctBucket >= 60);

		const serialized = JSON.stringify({ attribution, alert, distilled: ranked });
		assert.ok(!serialized.includes(busyRealId) || serialized.includes('topRealExtId'), 'telemetry alert must not rely on real id');
		assert.ok(!JSON.stringify(alert).includes(busyRealId), 'alert payload must never contain real id');
		assert.ok(!JSON.stringify(alert).includes(tidyRealId), 'alert payload must never contain tidy real id');
		assert.ok(!JSON.stringify(alert).includes(pathTrap), 'alert payload must never contain path trap');
		assert.ok(!JSON.stringify(alert).includes('/Users/alice'), 'alert payload must never contain user path');
	});

	test('alert fires at sustained ≥50% over 3 samples; spike and rate-limit honored', () => {
		const now0 = 1_000_000;
		// Single spike — no trigger.
		const spike1 = decideCpuProfileTrigger(80, createCpuAlertState(), now0);
		assert.strictEqual(spike1.trigger, false);
		assert.strictEqual(spike1.nextState.highStreak, 1);

		const spike2 = decideCpuProfileTrigger(10, spike1.nextState, now0 + 30_000);
		assert.strictEqual(spike2.trigger, false);
		assert.strictEqual(spike2.nextState.highStreak, 0, 'below-threshold resets streak');

		// 3× ≥50% → trigger.
		let state = createCpuAlertState();
		let decision = decideCpuProfileTrigger(CPU_SUSTAIN_THRESHOLD_PCT, state, now0);
		assert.strictEqual(decision.trigger, false);
		state = decision.nextState;
		decision = decideCpuProfileTrigger(60, state, now0 + 30_000);
		assert.strictEqual(decision.trigger, false);
		state = decision.nextState;
		decision = decideCpuProfileTrigger(75, state, now0 + 60_000);
		assert.strictEqual(decision.trigger, true, '3rd sustained sample must trigger');
		assert.strictEqual(decision.sustainedSec, CPU_SUSTAIN_SAMPLES * 30);
		assert.strictEqual(decision.nextState.profilesThisSession, 1);
		assert.strictEqual(decision.nextState.profileInFlight, true);
		assert.ok(decision.nextState.nextProfileAllowedMs >= now0 + 60_000 + CPU_PROFILE_MIN_INTERVAL_MS);

		// Rate-limit: even with fresh sustain, blocked until interval elapses.
		state = { ...decision.nextState, profileInFlight: false, highStreak: 0 };
		let blocked = decideCpuProfileTrigger(90, state, now0 + 60_000 + 1_000);
		// need 3 samples again
		state = blocked.nextState;
		blocked = decideCpuProfileTrigger(90, state, now0 + 60_000 + 31_000);
		state = blocked.nextState;
		blocked = decideCpuProfileTrigger(90, state, now0 + 60_000 + 61_000);
		assert.strictEqual(blocked.trigger, false, 'within 10min window must not re-profile');

		// Session cap: after max profiles, never trigger.
		state = {
			highStreak: CPU_SUSTAIN_SAMPLES - 1,
			profilesThisSession: CPU_PROFILE_MAX_PER_SESSION,
			nextProfileAllowedMs: 0,
			profileInFlight: false,
		};
		const capped = decideCpuProfileTrigger(99, state, now0 + 10_000_000);
		assert.strictEqual(capped.trigger, false);
	});

	test('exthostCpuSample / exthostCpuAlert payloads PASS detectTelemetryUserData({boundMeasurements:true})', () => {
		const pathTrap = '/Users/alice/secret-fixture/proj';
		const busyRoot = URI.file(`${pathTrap}/extensions/busy.ext`);
		const tidyRoot = URI.file(`${pathTrap}/extensions/tidy.ext`);
		const profile = buildBusyLoopProfile(busyRoot, tidyRoot);
		const categories: Array<[string, string]> = [
			[URI.file(busyRoot.fsPath).toString(true), 'busy.ext'],
			[URI.file(tidyRoot.fsPath).toString(true), 'tidy.ext'],
		];

		const monitor = new ExtensionHostCpuMonitor();
		// Baseline absolute, then three high-CPU deltas over 30s walls.
		const usPerSample = 20_000_000; // ~67% of one core over 30s
		let absUser = 0;
		let absSys = 0;
		let wall = 0;
		monitor.onCpuSample({ cpuUsage: { user: absUser, system: absSys }, wallMs: wall, uptimeSec: 0 });
		const ticks = [];
		for (let i = 0; i < 3; i++) {
			absUser += usPerSample;
			wall += 30_000;
			ticks.push(monitor.onCpuSample({
				cpuUsage: { user: absUser, system: absSys },
				wallMs: wall,
				uptimeSec: wall / 1000,
			}));
		}
		assert.ok(ticks[2]!.shouldProfile, 'third high sample must request a profile');
		assert.ok(ticks[2]!.sample);
		assert.ok(ticks[2]!.sample!.cpuPctBucket >= 50);

		const { alertPayload, attribution } = monitor.completeProfile({
			profile,
			categories,
			profileMs: 5000,
			cpuPctBucket: ticks[2]!.sample!.cpuPctBucket,
			sustainedSec: ticks[2]!.sustainedSec,
		});
		assert.strictEqual(attribution.resultKind, 'extension');
		assert.ok(alertPayload.topOpaqueExtId);
		assert.ok(/^ext-\d+$/.test(alertPayload.topOpaqueExtId!));

		const samplePayload = buildCpuSampleTelemetryPayload(ticks[2]!.sample!);
		const sampleGuard = detectTelemetryUserData(
			{ ...samplePayload, affinity: 1, pluginHostTelemetry: true },
			{
				markers: [pathTrap, 'busy.ext', 'tidy.ext'],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostCpuSample',
			},
		);
		assert.strictEqual(sampleGuard.hit, false, `exthostCpuSample must pass guard, got ${JSON.stringify(sampleGuard)}`);

		const alertGuard = detectTelemetryUserData(
			{ ...alertPayload, affinity: 1, pluginHostTelemetry: true },
			{
				markers: [pathTrap, 'busy.ext', 'tidy.ext', '/Users/alice'],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostCpuAlert',
			},
		);
		assert.strictEqual(alertGuard.hit, false, `exthostCpuAlert must pass guard, got ${JSON.stringify(alertGuard)}`);

		assert.strictEqual(checkGuardSafePayload(samplePayload, 'exthostCpuSample', { boundMeasurements: true }).hit, false);
		assert.strictEqual(checkGuardSafePayload(alertPayload, 'exthostCpuAlert', { boundMeasurements: true }).hit, false);
	});

	test('tryGuardSafeEmit emits cpu sample/alert and drops path-bearing payloads', () => {
		const emitted: Array<{ name: string; data: Record<string, unknown> }> = [];
		const sink: GuardSafeTelemetrySink = {
			publicLog: (name, data) => emitted.push({ name, data: data ?? {} }),
			publicLog2: (name, data) => emitted.push({ name, data: (data ?? {}) as Record<string, unknown> }),
		};

		const pathTrap = '/Users/alice/secret-fixture/proj';
		const busyRoot = URI.file(`${pathTrap}/extensions/busy.ext`);
		const tidyRoot = URI.file(`${pathTrap}/extensions/tidy.ext`);
		const monitor = new ExtensionHostCpuMonitor();

		let abs = 0;
		let wall = 0;
		monitor.onCpuSample({ cpuUsage: { user: 0, system: 0 }, wallMs: 0, uptimeSec: 0, sink });
		for (let i = 0; i < 3; i++) {
			abs += 18_000_000;
			wall += 30_000;
			monitor.onCpuSample({
				cpuUsage: { user: abs, system: 0 },
				wallMs: wall,
				uptimeSec: wall / 1000,
				sink,
			});
		}
		monitor.completeProfile({
			profile: buildBusyLoopProfile(busyRoot, tidyRoot),
			categories: [
				[URI.file(busyRoot.fsPath).toString(true), 'busy.ext'],
				[URI.file(tidyRoot.fsPath).toString(true), 'tidy.ext'],
			],
			sink,
			sustainedSec: 90,
			cpuPctBucket: 50,
		});

		assert.ok(emitted.some(e => e.name === 'exthostCpuSample'));
		const alertEvt = emitted.find(e => e.name === 'exthostCpuAlert');
		assert.ok(alertEvt, 'exthostCpuAlert must be emitted');
		assert.strictEqual(alertEvt!.data['resultKind'], 'extension');
		assert.ok(typeof alertEvt!.data['topOpaqueExtId'] === 'string' && /^ext-\d+$/.test(alertEvt!.data['topOpaqueExtId'] as string));
		for (const e of emitted) {
			assert.ok(!JSON.stringify(e.data).includes('busy.ext'));
			assert.ok(!JSON.stringify(e.data).includes(pathTrap));
			assert.ok(!JSON.stringify(e.data).includes('/Users/alice'));
		}

		const blocked = tryGuardSafeEmit(sink, 'exthostCpuAlert', {
			cpuPctBucket: 50,
			sustainedSecBucket: 90,
			topSharePctBucket: 80,
			profileMs: 5000,
			resultKind: 'extension',
			topOpaqueExtId: '/Users/alice/secret-fixture/x',
		}, { boundMeasurements: true });
		assert.strictEqual(blocked.emitted, false);
	});

	test('gc-dominated profile maps to resultKind=gc (memory lane, not extension blame)', () => {
		const profile: IV8Profile = {
			startTime: 0,
			endTime: 1000,
			nodes: [
				{
					id: 0,
					callFrame: { functionName: '(root)', scriptId: '0', url: '', lineNumber: -1, columnNumber: -1 },
					children: [1],
				},
				{
					id: 1,
					callFrame: { functionName: '(garbage collector)', scriptId: '0', url: '', lineNumber: -1, columnNumber: -1 },
					children: [],
				},
			],
			samples: [1, 1, 1, 1, 1],
			timeDeltas: [200, 200, 200, 200, 200],
		};
		const attribution = attributeCpuProfile(profile, [], new SessionEntityIdMap('ext'));
		assert.strictEqual(attribution.resultKind, 'gc');
		assert.strictEqual(attribution.topOpaqueExtId, undefined);
		const alert = buildCpuAlertTelemetryPayload({
			cpuPctBucket: 75,
			sustainedSec: 90,
			attribution,
		});
		assert.strictEqual(alert.resultKind, 'gc');
		assert.strictEqual(alert.topOpaqueExtId, undefined);
		assert.strictEqual(checkGuardSafePayload(alert, 'exthostCpuAlert', { boundMeasurements: true }).hit, false);
	});
});
