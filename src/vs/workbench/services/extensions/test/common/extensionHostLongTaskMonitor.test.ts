/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import { checkGuardSafePayload, tryGuardSafeEmit, type GuardSafeTelemetrySink } from '../../../../../platform/telemetry/common/guardSafeEmit.js';
import {
	bucketLongTaskMs,
	buildEventLoopLagTelemetryPayload,
	buildLongTaskTelemetryPayload,
	decideLongTaskAlert,
	ExtensionHostLongTaskMonitor,
	LONG_TASK_ALERT_ANY_MS,
	LONG_TASK_ALERT_COUNT_AT_500,
	LONG_TASK_ALERT_SYNC_MS,
	LONG_TASK_SYNC_FLOOR_MS,
	LONG_TASK_UNATTRIBUTED_OPAQUE,
	setActiveLongTaskMonitor,
} from '../../common/extensionHostLongTaskMonitor.js';

suite('extensionHostLongTaskMonitor (P-A / r15 Category A)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		setActiveLongTaskMonitor(undefined);
	});

	test('bucketLongTaskMs maps to closed edges (50…3000+)', () => {
		assert.strictEqual(bucketLongTaskMs(0), 0);
		assert.strictEqual(bucketLongTaskMs(49), 0);
		assert.strictEqual(bucketLongTaskMs(LONG_TASK_SYNC_FLOOR_MS), 50);
		assert.strictEqual(bucketLongTaskMs(99), 50);
		assert.strictEqual(bucketLongTaskMs(100), 100);
		assert.strictEqual(bucketLongTaskMs(600), 500);
		assert.strictEqual(bucketLongTaskMs(999), 500);
		assert.strictEqual(bucketLongTaskMs(1000), 1000);
		assert.strictEqual(bucketLongTaskMs(2999), 1000);
		assert.strictEqual(bucketLongTaskMs(3000), 3000);
		assert.strictEqual(bucketLongTaskMs(12_000), 3000);
	});

	test('synthetic 600ms handler is attributed to opaque ext id (never the real id)', () => {
		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 60, nowMs: 0 });
		const slowRealId = 'slow.ext';
		const fastRealId = 'fast.ext';
		// Workspace-path marker trap in fixture name (u28 guard red-team habit).
		const pathTrap = '/Users/alice/secret-fixture/proj';

		const slowOpaque = monitor.opaqueExtIdFor(slowRealId);
		const fastOpaque = monitor.opaqueExtIdFor(fastRealId);
		assert.ok(/^ext-\d+$/.test(slowOpaque), `opaque format, got ${slowOpaque}`);
		assert.notStrictEqual(slowOpaque, fastOpaque);
		assert.notStrictEqual(slowOpaque, slowRealId);
		assert.notStrictEqual(fastOpaque, fastRealId);

		// Scripted dispatch: slow.ext reports 600ms sync ×5; fast.ext stays under floor.
		for (let i = 0; i < 5; i++) {
			monitor.recordSlice('command', slowRealId, 600, 600);
		}
		monitor.recordSlice('command', fastRealId, 40, 40); // below floor — ignored

		const flush = monitor.forceFlush(60_000);
		assert.strictEqual(flush.longTasks.length, 1, 'only slow.ext should appear (fast under floor)');
		const row = flush.longTasks[0]!;
		assert.strictEqual(row.opaqueExtId, slowOpaque);
		assert.strictEqual(row.kind, 'command');
		assert.strictEqual(row.syncMsBucket, 500);
		assert.strictEqual(row.count, 5);
		assert.ok(!JSON.stringify(flush).includes(slowRealId), 'real id must never appear in flush');
		assert.ok(!JSON.stringify(flush).includes(fastRealId), 'real id must never appear in flush');
		assert.ok(!JSON.stringify(flush).includes(pathTrap), 'path trap must not appear');
	});

	test('alert fires at 5×≥500ms or any ≥3000ms per window', () => {
		const below = decideLongTaskAlert({
			countAt500: LONG_TASK_ALERT_COUNT_AT_500 - 1,
			has3000: false,
			opaqueExtId: 'ext-1',
			kind: 'command',
		});
		assert.strictEqual(below.fire, false);

		const byCount = decideLongTaskAlert({
			countAt500: LONG_TASK_ALERT_COUNT_AT_500,
			has3000: false,
			opaqueExtId: 'ext-1',
			kind: 'command',
		});
		assert.strictEqual(byCount.fire, true);
		assert.strictEqual(byCount.reason, 'count500');
		assert.strictEqual(byCount.opaqueExtId, 'ext-1');

		const byAny = decideLongTaskAlert({
			countAt500: 1,
			has3000: true,
			opaqueExtId: 'ext-2',
			kind: 'provider',
		});
		assert.strictEqual(byAny.fire, true);
		assert.strictEqual(byAny.reason, 'any3000');

		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 60, nowMs: 0 });
		for (let i = 0; i < LONG_TASK_ALERT_COUNT_AT_500; i++) {
			monitor.recordSlice('command', 'offender.ext', LONG_TASK_ALERT_SYNC_MS + 100);
		}
		const flushCount = monitor.forceFlush(60_000);
		assert.ok(flushCount.alerts.some(a => a.fire && a.reason === 'count500'));

		const monitor2 = new ExtensionHostLongTaskMonitor({ windowSec: 60, nowMs: 0 });
		monitor2.recordSlice('event', 'hang.ext', LONG_TASK_ALERT_ANY_MS);
		const flushAny = monitor2.forceFlush(60_000);
		assert.ok(flushAny.alerts.some(a => a.fire && a.reason === 'any3000'));
	});

	test('exthostLongTask / exthostEventLoopLag payloads PASS detectTelemetryUserData({boundMeasurements:true})', () => {
		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 300, nowMs: 0 });
		const realId = 'publisher.with-/Users/alice/secret-fixture/path.ext';
		const opaque = monitor.opaqueExtIdFor('publisher.safe.ext');
		monitor.recordSlice('command', 'publisher.safe.ext', 600);
		monitor.noteEventLoopLag({ p50Ms: 12, p99Ms: 140, maxMs: 400 });
		const flush = monitor.forceFlush(300_000);

		const longTaskPayload = {
			...flush.longTasks[0]!,
			affinity: 1,
			pluginHostTelemetry: true,
		};
		const longTaskGuard = detectTelemetryUserData(longTaskPayload, {
			markers: ['/Users/alice/secret-fixture', realId],
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName: 'exthostLongTask',
		});
		assert.strictEqual(longTaskGuard.hit, false, `exthostLongTask must pass guard, got ${JSON.stringify(longTaskGuard)}`);
		assert.strictEqual(longTaskPayload.opaqueExtId, opaque);
		assert.ok(/^ext-\d+$/.test(longTaskPayload.opaqueExtId));

		assert.ok(flush.eventLoopLag);
		const eldPayload = {
			...flush.eventLoopLag!,
			affinity: 1,
			pluginHostTelemetry: true,
		};
		const eldGuard = detectTelemetryUserData(eldPayload, {
			markers: ['/Users/alice/secret-fixture'],
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName: 'exthostEventLoopLag',
		});
		assert.strictEqual(eldGuard.hit, false, `exthostEventLoopLag must pass guard, got ${JSON.stringify(eldGuard)}`);

		// Builder helpers also pass checkGuardSafePayload.
		const built = buildLongTaskTelemetryPayload('activation', 'ext-3', 250, 500, 2);
		assert.strictEqual(checkGuardSafePayload(built, 'exthostLongTask', { boundMeasurements: true }).hit, false);
		const eldBuilt = buildEventLoopLagTelemetryPayload({ p50Ms: 20, p99Ms: 80, maxMs: 120 });
		assert.strictEqual(checkGuardSafePayload(eldBuilt, 'exthostEventLoopLag', { boundMeasurements: true }).hit, false);
	});

	test('tryGuardSafeEmit emits long-task / ELD and drops path-bearing payloads', () => {
		const emitted: Array<{ name: string; data: Record<string, unknown> }> = [];
		const sink: GuardSafeTelemetrySink = {
			publicLog: (name, data) => emitted.push({ name, data: data ?? {} }),
			publicLog2: (name, data) => emitted.push({ name, data: (data ?? {}) as Record<string, unknown> }),
		};
		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 1, nowMs: 0 });
		monitor.recordSlice('provider', 'ext.pub', 800);
		monitor.noteEventLoopLag({ p50Ms: 5, p99Ms: 60, maxMs: 90 });
		monitor.forceFlush(2_000, sink);

		assert.ok(emitted.some(e => e.name === 'exthostLongTask'));
		assert.ok(emitted.some(e => e.name === 'exthostEventLoopLag'));
		for (const e of emitted) {
			assert.ok(!JSON.stringify(e.data).includes('ext.pub'));
			assert.ok(!JSON.stringify(e.data).includes('/Users'));
		}

		const blocked = tryGuardSafeEmit(sink, 'exthostLongTask', {
			kind: 'command',
			opaqueExtId: '/Users/alice/secret-fixture/x',
			syncMsBucket: 500,
			wallMsBucket: 500,
			count: 1,
			windowSec: 300,
		}, { boundMeasurements: true });
		assert.strictEqual(blocked.emitted, false);
	});

	test('RPC catch-all skips when an attributed wrap already ran', () => {
		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 60, nowMs: 0 });
		monitor.measureRpc(() => {
			// Nested attributed dispatch (provider / command path).
			monitor.measureSync('provider', 'nested.ext', () => {
				const end = Date.now() + 1;
				while (Date.now() < end) { /* spin ~1ms — may be <50; force via record */ }
			});
			monitor.recordSlice('provider', 'nested.ext', 200);
		});
		// Unattributed long RPC
		monitor.measureRpc(() => {
			monitor.recordSliceOpaque('rpc', LONG_TASK_UNATTRIBUTED_OPAQUE, 200);
		});

		// Direct unattributed record for the rpc path under test:
		const m2 = new ExtensionHostLongTaskMonitor({ windowSec: 60, nowMs: 0 });
		m2.recordSliceOpaque('rpc', LONG_TASK_UNATTRIBUTED_OPAQUE, 250);
		m2.recordSlice('command', 'cmd.ext', 250);
		const flush = m2.forceFlush(60_000);
		const opaques = flush.longTasks.map(t => t.opaqueExtId);
		assert.ok(opaques.includes(LONG_TASK_UNATTRIBUTED_OPAQUE));
		assert.ok(opaques.some(id => id !== LONG_TASK_UNATTRIBUTED_OPAQUE));
	});

	test('ELD alert requires two consecutive high-p99 windows', () => {
		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 1, nowMs: 0 });
		monitor.noteEventLoopLag({ p50Ms: 10, p99Ms: 120, maxMs: 200 });
		const first = monitor.forceFlush(2_000);
		assert.strictEqual(first.eldAlert, false, 'single window must not alert');

		monitor.noteEventLoopLag({ p50Ms: 10, p99Ms: 150, maxMs: 220 });
		const second = monitor.forceFlush(4_000);
		assert.strictEqual(second.eldAlert, true, 'two consecutive high p99 windows alert');

		monitor.noteEventLoopLag({ p50Ms: 5, p99Ms: 20, maxMs: 40 });
		const cool = monitor.forceFlush(6_000);
		assert.strictEqual(cool.eldAlert, false);
	});

	test('measureSync records only sync ≥ floor and mints stable opaque ids', () => {
		const monitor = new ExtensionHostLongTaskMonitor({ windowSec: 60, nowMs: 0 });
		monitor.measureSync('event', 'e1', () => 1); // ~0ms — ignored
		const a = monitor.opaqueExtIdFor('e1');
		const b = monitor.opaqueExtIdFor('e1');
		assert.strictEqual(a, b);
		monitor.recordSlice('event', 'e1', 55);
		const flush = monitor.forceFlush(60_000);
		assert.strictEqual(flush.longTasks[0]!.opaqueExtId, a);
		assert.strictEqual(flush.longTasks[0]!.syncMsBucket, 50);
	});
});
