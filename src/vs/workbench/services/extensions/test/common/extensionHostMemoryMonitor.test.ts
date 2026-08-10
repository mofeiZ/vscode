/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import {
	bucketRssMb,
	buildMemoryAlertTelemetryPayload,
	buildMemorySample,
	buildMemoryTelemetryPayload,
	computeGrowthMbPerMin,
	createMemoryAlertState,
	decideMemoryAlert,
	DEFAULT_GROWTH_THRESHOLD_MB_PER_MIN,
	DEFAULT_LEVEL_THRESHOLD_BUCKET_MB,
	MemorySampleRing,
	previousRssBucketEdge,
	shouldEmitMemorySampleTelemetry,
} from '../../common/extensionHostMemoryMonitor.js';

suite('extensionHostMemoryMonitor', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	test('bucketRssMb maps to highest edge ≤ RSS', () => {
		assert.strictEqual(bucketRssMb(0), 0);
		assert.strictEqual(bucketRssMb(127), 0);
		assert.strictEqual(bucketRssMb(128), 128);
		assert.strictEqual(bucketRssMb(3000), 2048);
		assert.strictEqual(bucketRssMb(3072), 3072);
		assert.strictEqual(bucketRssMb(5000), 4096);
		assert.strictEqual(bucketRssMb(9000), 8192);
	});

	test('previousRssBucketEdge supports hysteresis floor', () => {
		assert.strictEqual(previousRssBucketEdge(DEFAULT_LEVEL_THRESHOLD_BUCKET_MB), 2048);
		assert.strictEqual(previousRssBucketEdge(128), 0);
		assert.strictEqual(previousRssBucketEdge(999), 0);
	});

	test('computeGrowthMbPerMin catches u7-scale leak (+8157MB / 59s)', () => {
		const growth = computeGrowthMbPerMin([
			{ rssMb: 500, tsMs: 0 },
			{ rssMb: 500 + 8157, tsMs: 59_000 },
		]);
		// ~8290 MB/min — far above the 256 MB/min default threshold
		assert.ok(growth > DEFAULT_GROWTH_THRESHOLD_MB_PER_MIN);
		assert.ok(growth > 8000);
		assert.ok(growth < 8500);
	});

	test('decideMemoryAlert level trigger fires once per crossing with hysteresis', () => {
		let state = createMemoryAlertState();

		const below = decideMemoryAlert({ rssBucketMb: 2048, growthMbPerMin: 0 }, state, { nowMs: 0 });
		assert.strictEqual(below.fire, false);
		state = below.nextState;

		const cross = decideMemoryAlert({ rssBucketMb: 3072, growthMbPerMin: 0 }, state, { nowMs: 1 });
		assert.strictEqual(cross.fire, true);
		assert.strictEqual(cross.trigger, 'level');
		assert.strictEqual(cross.thresholdBucketMb, 3072);
		state = cross.nextState;
		assert.strictEqual(state.levelArmed, false);

		// Still high — must not flap
		const stillHigh = decideMemoryAlert({ rssBucketMb: 4096, growthMbPerMin: 0 }, state, { nowMs: 2 });
		assert.strictEqual(stillHigh.fire, false);
		state = stillHigh.nextState;

		// Drop to threshold edge but not below hysteresis floor (2048) — still disarmed
		const atThreshold = decideMemoryAlert({ rssBucketMb: 3072, growthMbPerMin: 0 }, state, { nowMs: 3 });
		assert.strictEqual(atThreshold.fire, false);
		state = atThreshold.nextState;

		// Drop below previous bucket → re-arm
		const dropped = decideMemoryAlert({ rssBucketMb: 1024, growthMbPerMin: 0 }, state, { nowMs: 4 });
		assert.strictEqual(dropped.fire, false);
		state = dropped.nextState;
		assert.strictEqual(state.levelArmed, true);

		const crossAgain = decideMemoryAlert({ rssBucketMb: 3072, growthMbPerMin: 0 }, state, { nowMs: 5 });
		assert.strictEqual(crossAgain.fire, true);
		assert.strictEqual(crossAgain.trigger, 'level');
	});

	test('decideMemoryAlert growth trigger fires on u7 leak and backs off exponentially', () => {
		let state = createMemoryAlertState();
		const u7Growth = computeGrowthMbPerMin([
			{ rssMb: 500, tsMs: 0 },
			{ rssMb: 500 + 8157, tsMs: 59_000 },
		]);

		const first = decideMemoryAlert(
			{ rssBucketMb: 1024, growthMbPerMin: u7Growth },
			state,
			{ nowMs: 59_000 },
		);
		assert.strictEqual(first.fire, true, 'u7 leak must fire growth alert');
		assert.strictEqual(first.trigger, 'growth');
		state = first.nextState;
		assert.strictEqual(state.growthNextAllowedMs, 59_000 + 60_000);
		assert.strictEqual(state.growthBackoffMs, 120_000);

		// Immediate re-sample while sustained — suppressed by backoff
		const suppressed = decideMemoryAlert(
			{ rssBucketMb: 1024, growthMbPerMin: u7Growth },
			state,
			{ nowMs: 59_000 + 30_000 },
		);
		assert.strictEqual(suppressed.fire, false);
		state = suppressed.nextState;

		// After backoff window — fires again with doubled wait
		const second = decideMemoryAlert(
			{ rssBucketMb: 1024, growthMbPerMin: u7Growth },
			state,
			{ nowMs: 59_000 + 60_000 },
		);
		assert.strictEqual(second.fire, true);
		assert.strictEqual(second.trigger, 'growth');
		state = second.nextState;
		assert.strictEqual(state.growthBackoffMs, 240_000);

		// Growth cools → backoff resets
		const cooled = decideMemoryAlert(
			{ rssBucketMb: 1024, growthMbPerMin: 10 },
			state,
			{ nowMs: 59_000 + 120_000 },
		);
		assert.strictEqual(cooled.fire, false);
		assert.strictEqual(cooled.nextState.growthBackoffMs, 60_000);
		assert.strictEqual(cooled.nextState.growthNextAllowedMs, 0);
	});

	test('shouldEmitMemorySampleTelemetry: baseline + every 10th', () => {
		assert.strictEqual(shouldEmitMemorySampleTelemetry(1), true);
		assert.strictEqual(shouldEmitMemorySampleTelemetry(2), false);
		assert.strictEqual(shouldEmitMemorySampleTelemetry(10), true);
		assert.strictEqual(shouldEmitMemorySampleTelemetry(11), false);
		assert.strictEqual(shouldEmitMemorySampleTelemetry(20), true);
	});

	test('buildMemorySample + telemetry payload are numbers-only', () => {
		const ring = new MemorySampleRing();
		const sample = buildMemorySample({
			usage: {
				rss: 1500 * 1024 * 1024,
				heapUsed: 312 * 1024 * 1024,
				heapTotal: 400 * 1024 * 1024,
				external: 20 * 1024 * 1024,
			},
			uptimeSec: 42.7,
			sampleSeq: 1,
			pid: 4242,
			tsMs: 1_000,
			ring,
		});
		assert.strictEqual(sample.rssMb, 1500);
		assert.strictEqual(sample.rssBucketMb, 1024);
		assert.strictEqual(sample.heapUsedMb, 312);
		assert.strictEqual(sample.uptimeSec, 43);

		const payload = buildMemoryTelemetryPayload(sample);
		for (const [k, v] of Object.entries(payload)) {
			assert.strictEqual(typeof v, 'number', `${k} must be number`);
		}
	});

	test('exthostMemorySample / exthostMemoryAlert payloads PASS telemetry data guard (Path A)', () => {
		const ring = new MemorySampleRing();
		ring.push(500, 0);
		const sample = buildMemorySample({
			usage: {
				rss: (500 + 8157) * 1024 * 1024,
				heapUsed: 900 * 1024 * 1024,
				heapTotal: 1100 * 1024 * 1024,
				external: 40 * 1024 * 1024,
			},
			uptimeSec: 120,
			sampleSeq: 3,
			pid: 77,
			tsMs: 59_000,
			ring,
		});

		const samplePayload = {
			...buildMemoryTelemetryPayload(sample),
			// Main-thread stamp (u25 affinity) — also a number
			affinity: 1,
			pluginHostTelemetry: true,
		};
		const sampleGuard = detectTelemetryUserData(samplePayload, {
			markers: ['/Users/alice/proj'],
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName: 'exthostMemorySample',
		});
		assert.strictEqual(sampleGuard.hit, false, `exthostMemorySample must pass guard, got ${JSON.stringify(sampleGuard)}`);

		const alertPayload = {
			...buildMemoryAlertTelemetryPayload(sample, 'growth', DEFAULT_LEVEL_THRESHOLD_BUCKET_MB),
			affinity: 1,
			pluginHostTelemetry: true,
		};
		const alertGuard = detectTelemetryUserData(alertPayload, {
			markers: ['/Users/alice/proj'],
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName: 'exthostMemoryAlert',
		});
		assert.strictEqual(alertGuard.hit, false, `exthostMemoryAlert must pass guard, got ${JSON.stringify(alertGuard)}`);
	});
});
