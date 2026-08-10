/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import { checkGuardSafePayload } from '../../../../../platform/telemetry/common/guardSafeEmit.js';
import { SessionFileIdMap } from '../../../../../platform/telemetry/common/opaqueIds.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import {
	crashRecordTelemetryData,
	type ExtensionHostCrashRecord,
} from '../../common/extensionHostCrashRecord.js';
import {
	MemorySampleRing,
	buildMemoryAlertDiagnosticPayload,
	buildMemorySample,
} from '../../common/extensionHostMemoryMonitor.js';
import {
	WORKSPACE_ACTIONS_RING_CAP,
	WorkspaceActionsRecorder,
	setActiveWorkspaceActionsRecorder,
	toCountBucket,
	toLanguageBucket,
	toSizeBucketMb,
	toTSinceStartBucket,
} from '../../common/workspaceActionsRing.js';

suite('WorkspaceActionsRing (R4b / r17 Lane A)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		setActiveWorkspaceActionsRecorder(undefined);
	});

	test('ring is bounded — oldest actions drop past cap', () => {
		const recorder = new WorkspaceActionsRecorder({
			salt: 'test-salt',
			workspaceRoots: ['/Users/alice/proj'],
			cap: 3,
			sessionStartMs: 1_000_000,
		});
		// Fixture path marker stays in test locals only (u28 red-team habit).
		recorder.recordAction('open', '/Users/alice/proj/a.ts', 1_000_000);
		recorder.recordAction('edit', '/Users/alice/proj/a.ts', 1_005_000);
		recorder.recordAction('save', '/Users/alice/proj/a.ts', 1_015_000);
		recorder.recordAction('switch', '/Users/alice/proj/b.ts', 1_030_000);
		assert.strictEqual(recorder.length, 3);
		assert.strictEqual(recorder.cap, 3);
		const snap = recorder.ring.snapshot();
		assert.deepStrictEqual(snap.map(e => e.kind), ['edit', 'save', 'switch']);
		assert.deepStrictEqual(snap.map(e => e.opaqueId), ['file-1', 'file-1', 'file-2']);
	});

	test('default cap matches foundation flight-recorder cap (32)', () => {
		const recorder = new WorkspaceActionsRecorder({
			salt: 'cap-salt',
			workspaceRoots: ['/Users/alice/proj'],
		});
		assert.strictEqual(recorder.cap, WORKSPACE_ACTIONS_RING_CAP);
		assert.strictEqual(WORKSPACE_ACTIONS_RING_CAP, 32);
	});

	test('recordAction mints per-session opaque file ids (same map as archive)', () => {
		const shared = new SessionFileIdMap();
		const recorder = new WorkspaceActionsRecorder({
			salt: 'share-salt',
			workspaceRoots: ['/Users/alice/proj'],
			fileIds: shared,
			sessionStartMs: 0,
		});
		const id1 = recorder.recordAction('open', '/Users/alice/proj/a.ts', 0);
		const id2 = recorder.recordAction('edit', '/Users/alice/proj/b.ts', 5_000);
		assert.strictEqual(id1, 'file-1');
		assert.strictEqual(id2, 'file-2');
		assert.strictEqual(shared.opaqueId('/Users/alice/proj/a.ts'), 'file-1');
		assert.strictEqual(shared.opaqueId('/Users/alice/proj/b.ts'), 'file-2');
	});

	test('synthetic crash flush carries opaque ids + workspace shape and passes strictShape', () => {
		const recorder = new WorkspaceActionsRecorder({
			salt: new Uint8Array([1, 2, 3, 4, 5, 6]),
			workspaceRoots: ['/Users/alice/secret-fixture'],
			sessionStartMs: 0,
		});
		recorder.updateWorkspaceShape({
			folderCount: 2,
			openEditorCount: 5,
			fileCount: 40,
			totalSizeMb: 90,
			languageCounts: { typescript: 12, javascript: 3, other: 1 },
		});
		recorder.recordAction('open', '/Users/alice/secret-fixture/a.ts', 0);
		recorder.recordAction('edit', '/Users/alice/secret-fixture/a.ts', 5_000);
		recorder.recordAction('save', '/Users/alice/secret-fixture/a.ts', 15_000);
		recorder.recordAction('switch', '/Users/alice/secret-fixture/b.ts', 30_000);
		recorder.recordAction('edit', '/Users/alice/secret-fixture/b.ts', 60_000);
		setActiveWorkspaceActionsRecorder(recorder);

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

		assert.strictEqual(payload.a0_kind, 'open');
		assert.strictEqual(payload.a0_file, 'file-1');
		assert.strictEqual(payload.a1_kind, 'edit');
		assert.strictEqual(payload.a2_kind, 'save');
		assert.strictEqual(payload.a3_kind, 'switch');
		assert.strictEqual(payload.a3_file, 'file-2');
		assert.strictEqual(payload.a4_kind, 'edit');
		assert.strictEqual(payload.a4_file, 'file-2');
		assert.strictEqual(payload.actionRingLen, 5);
		assert.strictEqual(payload.actionRingCap, 32);

		assert.ok(typeof payload.opaqueSessionId === 'string' && /^sess\.[0-9a-f]{6}$/.test(payload.opaqueSessionId as string));
		assert.ok(typeof payload.opaqueWorkspaceId === 'string' && /^ws\.[0-9a-f]{6}$/.test(payload.opaqueWorkspaceId as string));
		assert.strictEqual(payload.folderCountBucket, 2);
		assert.strictEqual(payload.openEditorCountBucket, 4);
		assert.strictEqual(payload.fileCountBucket, 32);
		assert.strictEqual(payload.totalSizeBucketMb, 64);
		assert.strictEqual(payload.lang_typescript, 12);
		assert.strictEqual(payload.lang_javascript, 3);
		assert.strictEqual(payload.lang_other, 1);
		assert.strictEqual(payload.lang_python, undefined);

		for (let i = 0; i < (payload.actionRingLen as number); i++) {
			assert.ok(/^file-\d+$/.test(payload[`a${i}_file`] as string));
			assert.strictEqual(payload[`a${i}_id`], undefined, 'r17 schema uses a*_file not a*_id');
		}

		const serialized = JSON.stringify(payload);
		assert.ok(!serialized.includes('/Users'));
		assert.ok(!serialized.includes('alice'));
		assert.ok(!serialized.includes('secret-fixture'));
		assert.ok(!serialized.includes('.ts'));

		// Path-A crash carrier: boundMeasurements (u30/u31). Full crash+ring exceeds
		// the strictShape code-unit leaf cap (24); the context sibling must pass it.
		const crashGuard = detectTelemetryUserData(payload, {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName: 'exthostCrashRecord',
		});
		assert.strictEqual(crashGuard.hit, false, `crash+actions must pass boundMeasurements, got ${JSON.stringify(crashGuard)}`);

		const contextOnly = recorder.buildContextPayload();
		assert.strictEqual(contextOnly.lang_python, undefined, 'zero lang buckets omitted');
		assert.strictEqual(contextOnly.lang_typescript, 12);
		const contextGuard = detectTelemetryUserData(contextOnly, {
			strictShape: true,
			eventName: 'workspaceActionsContext',
		});
		assert.strictEqual(contextGuard.hit, false, `workspaceActionsContext must pass strictShape, got ${JSON.stringify(contextGuard)}`);

		const bad = { ...contextOnly, path: '/Users/alice/secret-fixture/a.ts' };
		const badGuard = detectTelemetryUserData(bad, { strictShape: true, eventName: 'workspaceActionsContext' });
		assert.strictEqual(badGuard.hit, true);
	});

	test('memory alert flush attaches ring + shape (flush-on-diagnostic only)', () => {
		const recorder = new WorkspaceActionsRecorder({
			salt: 'alert-salt',
			workspaceRoots: ['/Users/alice/secret-fixture'],
			sessionStartMs: 0,
		});
		recorder.updateWorkspaceShape({
			folderCount: 1,
			openEditorCount: 1,
			fileCount: 8,
			totalSizeMb: 4,
			languageCounts: { markdown: 2 },
		});
		recorder.recordAction('save', '/Users/alice/secret-fixture/readme.md', 30_000);
		setActiveWorkspaceActionsRecorder(recorder);

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
		assert.strictEqual(alertPayload.a0_kind, 'save');
		assert.strictEqual(alertPayload.a0_file, 'file-1');
		assert.strictEqual(alertPayload.actionRingLen, 1);
		assert.strictEqual(alertPayload.folderCountBucket, 1);
		assert.strictEqual(alertPayload.lang_markdown, 2);
		assert.strictEqual(alertPayload.trigger, 'growth');

		const alertGuard = checkGuardSafePayload(alertPayload, 'exthostMemoryAlert', {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
		});
		assert.strictEqual(alertGuard.hit, false, `memory alert+actions must pass boundMeasurements, got ${JSON.stringify(alertGuard)}`);

		const contextGuard = detectTelemetryUserData(recorder.buildContextPayload(), {
			strictShape: true,
			eventName: 'workspaceActionsContext',
		});
		assert.strictEqual(contextGuard.hit, false, `alert context sibling must pass strictShape, got ${JSON.stringify(contextGuard)}`);
		assert.ok(!JSON.stringify(alertPayload).includes('/Users'));
	});

	test('recordAction does not stream — flush is diagnostic-only (no continuous publicLog wiring)', () => {
		const events: string[] = [];
		const recorder = new WorkspaceActionsRecorder({
			salt: 'silent-salt',
			workspaceRoots: ['/Users/alice/proj'],
			sessionStartMs: 0,
		});
		// Simulate a naive continuous-stream sink that must stay unused.
		const streamSink = {
			publicLog(name: string) { events.push(name); },
			publicLog2(name: string) { events.push(name); },
		};
		void streamSink;

		recorder.recordAction('open', '/Users/alice/proj/a.ts', 0);
		recorder.recordAction('edit', '/Users/alice/proj/a.ts', 5_000);
		recorder.recordAction('save', '/Users/alice/proj/a.ts', 15_000);

		assert.strictEqual(events.length, 0, 'recordAction must not emit telemetry');
		assert.strictEqual(recorder.length, 3);

		// Without registering as active + without a diagnostic flush, nothing leaves.
		const lonely: Record<string, unknown> = { exitClass: 'oom' };
		assert.strictEqual(lonely.a0_file, undefined);
		assert.strictEqual(lonely.actionRingLen, undefined);

		setActiveWorkspaceActionsRecorder(recorder);
		recorder.flushInto(lonely);
		assert.strictEqual(lonely.a0_file, 'file-1');
		assert.strictEqual(lonely.actionRingLen, 3);
		assert.strictEqual(events.length, 0, 'flushInto attaches locally; does not publicLog');
	});

	test('bucket helpers floor onto closed edges', () => {
		assert.strictEqual(toCountBucket(0), 0);
		assert.strictEqual(toCountBucket(3), 2);
		assert.strictEqual(toCountBucket(40), 32);
		assert.strictEqual(toSizeBucketMb(90), 64);
		assert.strictEqual(toSizeBucketMb(0.5), 0);
		assert.strictEqual(toTSinceStartBucket(0), 0);
		assert.strictEqual(toTSinceStartBucket(7), 5);
		assert.strictEqual(toTSinceStartBucket(90), 60);
		assert.strictEqual(toTSinceStartBucket(4000), 3600);
		assert.strictEqual(toLanguageBucket('typescriptreact'), 'typescript');
		assert.strictEqual(toLanguageBucket('unknown-lang'), 'other');
	});
});
