/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import {
	FlightRecorderRing,
	setActiveFlightRecorder,
} from '../../../../../platform/telemetry/common/flightRecorder.js';
import { checkGuardSafePayload } from '../../../../../platform/telemetry/common/guardSafeEmit.js';
import { SessionFileIdMap } from '../../../../../platform/telemetry/common/opaqueIds.js';
import {
	crashRecordTelemetryData,
	type ExtensionHostCrashRecord,
} from '../../common/extensionHostCrashRecord.js';
import {
	MemorySampleRing,
	buildMemoryAlertDiagnosticPayload,
	buildMemorySample,
} from '../../common/extensionHostMemoryMonitor.js';

suite('Flight recorder diagnostic carriers (u45)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		setActiveFlightRecorder(undefined);
	});

	test('crashRecordTelemetryData attaches the active ring', () => {
		const files = new SessionFileIdMap();
		const ring = new FlightRecorderRing(8);
		ring.record({ kind: 'open', opaqueId: files.opaqueId('/Users/alice/secret-fixture/a.ts'), tBucket: 0 });
		ring.record({ kind: 'edit', opaqueId: files.opaqueId('/Users/alice/secret-fixture/a.ts'), tBucket: 5 });
		setActiveFlightRecorder(ring);

		const record: ExtensionHostCrashRecord = {
			schema: 1,
			ts: 1_700_000_000_000,
			code: 134,
			signal: '',
			reason: 'oom',
			exitClass: 'oom',
			oomSuspected: true,
			oomHeuristic: false,
			affinity: 0,
			pid: 4242,
			uptimeSec: 120,
			lastRssBucketMb: 3072,
			lastHeapUsedMb: 512,
			secondsSinceLastSample: 5,
			secondsSinceLastAlert: 10,
			activatedExtensionCount: 1,
			extensionIds: ['publisher.ext'],
			heapSnapshotCaptured: false,
			heapSnapshotSizeBucketMb: null,
		};

		const payload = crashRecordTelemetryData(record);
		assert.strictEqual(payload.frRingLen, 2);
		assert.strictEqual(payload.fr0_id, 'file-1');
		assert.strictEqual(payload.fr1_kind, 'edit');

		const guard = checkGuardSafePayload(payload, 'exthostCrashRecord', {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
		});
		assert.strictEqual(guard.hit, false, `crash+ring must pass guard, got ${JSON.stringify(guard)}`);
		assert.ok(!JSON.stringify(payload).includes('/Users'));
	});

	test('buildMemoryAlertDiagnosticPayload attaches the active ring', () => {
		const files = new SessionFileIdMap();
		const ring = new FlightRecorderRing(8);
		ring.record({ kind: 'save', opaqueId: files.opaqueId('/Users/alice/secret-fixture/b.ts'), tBucket: 30 });
		setActiveFlightRecorder(ring);

		const sampleRing = new MemorySampleRing();
		const sample = buildMemorySample({
			usage: {
				rss: 3072 * 1024 * 1024,
				heapUsed: 512 * 1024 * 1024,
				heapTotal: 600 * 1024 * 1024,
				external: 0,
			},
			uptimeSec: 120,
			sampleSeq: 4,
			pid: 4242,
			tsMs: 1_700_000_000_000,
			ring: sampleRing,
		});

		const alertPayload = buildMemoryAlertDiagnosticPayload(sample, 'growth', 3072);
		assert.strictEqual(alertPayload.frRingLen, 1);
		assert.strictEqual(alertPayload.fr0_kind, 'save');
		assert.strictEqual(alertPayload.fr0_id, 'file-1');
		assert.strictEqual(alertPayload.trigger, 'growth');

		const guard = checkGuardSafePayload(alertPayload, 'exthostMemoryAlert', {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
		});
		assert.strictEqual(guard.hit, false, `memory alert+ring must pass guard, got ${JSON.stringify(guard)}`);
	});
});
