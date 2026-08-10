/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import {
	FlightRecorderRing,
	flushActiveFlightRecorderInto,
	setActiveFlightRecorder,
} from '../../common/flightRecorder.js';
import { checkGuardSafePayload, tryGuardSafeEmit } from '../../common/guardSafeEmit.js';
import { SessionFileIdMap } from '../../common/opaqueIds.js';

suite('FlightRecorderRing (u45)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		setActiveFlightRecorder(undefined);
	});

	test('ring is bounded — oldest entries drop past cap', () => {
		const ring = new FlightRecorderRing(3);
		ring.record({ kind: 'open', opaqueId: 'file-1', tBucket: 0 });
		ring.record({ kind: 'edit', opaqueId: 'file-1', tBucket: 5 });
		ring.record({ kind: 'save', opaqueId: 'file-1', tBucket: 15 });
		ring.record({ kind: 'switch', opaqueId: 'file-2', tBucket: 30 });
		assert.strictEqual(ring.length, 3);
		assert.strictEqual(ring.cap, 3);
		const snap = ring.snapshot();
		assert.deepStrictEqual(snap.map(e => e.kind), ['edit', 'save', 'switch']);
		assert.deepStrictEqual(snap.map(e => e.opaqueId), ['file-1', 'file-1', 'file-2']);
	});

	test('flushInto attaches recent entries as flat leaves', () => {
		const files = new SessionFileIdMap();
		const ring = new FlightRecorderRing(32);
		ring.record({ kind: 'open', opaqueId: files.opaqueId('/Users/alice/proj/a.ts'), tBucket: 0 });
		ring.record({ kind: 'edit', opaqueId: files.opaqueId('/Users/alice/proj/a.ts'), tBucket: 5 });
		ring.record({ kind: 'switch', opaqueId: files.opaqueId('/Users/alice/proj/b.ts'), tBucket: 15 });

		const diagnostic: Record<string, unknown> = { exitClass: 'oom', affinity: 0 };
		ring.flushInto(diagnostic);

		assert.strictEqual(diagnostic.frRingLen, 3);
		assert.strictEqual(diagnostic.frRingCap, 32);
		assert.strictEqual(diagnostic.fr0_kind, 'open');
		assert.strictEqual(diagnostic.fr0_id, 'file-1');
		assert.strictEqual(diagnostic.fr0_t, 0);
		assert.strictEqual(diagnostic.fr1_kind, 'edit');
		assert.strictEqual(diagnostic.fr2_id, 'file-2');
		const serialized = JSON.stringify(diagnostic);
		assert.ok(!serialized.includes('/Users'));
		assert.ok(!serialized.includes('alice'));
	});

	test('synthetic diagnostic flush payload passes the telemetry data guard', () => {
		const files = new SessionFileIdMap();
		const ring = new FlightRecorderRing(8);
		// Fixture path marker stays in test locals only (u28 red-team habit).
		ring.record({ kind: 'open', opaqueId: files.opaqueId('/Users/alice/secret-fixture/a.ts'), tBucket: 0 });
		ring.record({ kind: 'save', opaqueId: files.opaqueId('/Users/alice/secret-fixture/a.ts'), tBucket: 60 });

		const diagnostic: Record<string, unknown> = {
			schema: 1,
			exitClass: 'oom',
			oomSuspected: true,
			affinity: 0,
			pid: 4242,
			uptimeSec: 120,
			lastRssBucketMb: 3072,
			activatedExtensionCount: 1,
			extensionIds: ['publisher.ext'],
			heapSnapshotCaptured: false,
		};
		ring.flushInto(diagnostic);

		assert.strictEqual(diagnostic.frRingLen, 2);
		assert.strictEqual(diagnostic.fr0_id, 'file-1');
		assert.strictEqual(diagnostic.fr1_kind, 'save');

		const guard = checkGuardSafePayload(diagnostic, 'exthostCrashRecord', {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
		});
		assert.strictEqual(guard.hit, false, `expected guard miss, got ${JSON.stringify(guard)}`);

		const bad = { ...diagnostic, path: '/Users/alice/secret-fixture/a.ts' };
		const badGuard = checkGuardSafePayload(bad, 'exthostCrashRecord');
		assert.strictEqual(badGuard.hit, true);
	});

	test('tryGuardSafeEmit drops on guard hit and emits on miss', () => {
		const events: { name: string; data: Record<string, unknown> }[] = [];
		const sink = {
			publicLog(name: string, data?: Record<string, unknown>) {
				events.push({ name, data: data ?? {} });
			},
			publicLog2(name: string, data?: Record<string, unknown>) {
				events.push({ name, data: data ?? {} });
			},
		};

		const blocked: string[] = [];
		const bad = tryGuardSafeEmit(sink, 'testEvent', { path: '/Users/alice/x.ts' }, {
			onBlocked: (n) => blocked.push(n),
		});
		assert.strictEqual(bad.emitted, false);
		assert.deepStrictEqual(blocked, ['testEvent']);
		assert.strictEqual(events.length, 0);

		const ok = tryGuardSafeEmit(sink, 'testEvent', {
			exitClass: 'oom',
			fr0_kind: 'save',
			fr0_id: 'file-1',
			fr0_t: 5,
			frRingLen: 1,
			frRingCap: 32,
		});
		assert.strictEqual(ok.emitted, true);
		assert.strictEqual(events.length, 1);
		assert.strictEqual(events[0]!.name, 'testEvent');
	});

	test('flushActiveFlightRecorderInto is a no-op without an active ring', () => {
		const diagnostic: Record<string, unknown> = { exitClass: 'crash' };
		flushActiveFlightRecorderInto(diagnostic);
		assert.deepStrictEqual(diagnostic, { exitClass: 'crash' });
	});
});
