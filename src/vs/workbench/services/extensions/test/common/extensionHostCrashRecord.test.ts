/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { DisposableStore } from '../../../../../base/common/lifecycle.js';
import { URI } from '../../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import { FileService } from '../../../../../platform/files/common/fileService.js';
import { InMemoryFileSystemProvider } from '../../../../../platform/files/common/inMemoryFilesystemProvider.js';
import { NullLogService } from '../../../../../platform/log/common/log.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import { ExtensionHostExitCode } from '../../common/extensionHostProtocol.js';
import {
	buildExtensionHostCrashRecord,
	classifyExtensionHostExit,
	clearExtensionHostExitContextsForTests,
	crashRecordFileName,
	crashRecordTelemetryData,
	flushPendingExtensionHostCrashRecords,
	HIGH_RSS_BUCKET_MB,
	markPendingCrashRecordSentInSession,
	MAX_PENDING_ERROR_RECORDS,
	pendingErrorsDir,
	publishExtensionHostExitContext,
	consumeExtensionHostExitContext,
	stderrLooksLikeOom,
	writePendingExtensionHostCrashRecord,
	type ExtensionHostCrashRecord,
} from '../../common/extensionHostCrashRecord.js';

suite('ExtensionHostCrashRecord', () => {

	const store = ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		clearExtensionHostExitContextsForTests();
	});

	suite('stderrLooksLikeOom', () => {
		test('matches V8 heap-limit fatal error text', () => {
			assert.strictEqual(
				stderrLooksLikeOom('FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory'),
				true,
			);
			assert.strictEqual(stderrLooksLikeOom('JavaScript heap out of memory'), true);
			assert.strictEqual(stderrLooksLikeOom('Reached heap limit'), true);
		});

		test('does not match clean / unrelated stderr', () => {
			assert.strictEqual(stderrLooksLikeOom('Extension host started'), false);
			assert.strictEqual(stderrLooksLikeOom('Error: ENOENT'), false);
		});
	});

	suite('classifyExtensionHostExit', () => {
		test('Electron reason oom → exitClass oom', () => {
			const c = classifyExtensionHostExit({
				code: 1,
				reason: 'oom',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'oom');
			assert.strictEqual(c.oomSuspected, true);
			assert.strictEqual(c.electronOom, true);
			assert.strictEqual(c.oomHeuristic, false);
		});

		test('Electron reason memory-eviction → oom', () => {
			const c = classifyExtensionHostExit({
				code: 1,
				reason: 'memory-eviction',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'oom');
			assert.strictEqual(c.oomSuspected, true);
		});

		test('stderr OOM flag alone → oom', () => {
			const c = classifyExtensionHostExit({
				code: 1,
				reason: 'crashed',
				stderrOomSeen: true,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'oom');
			assert.strictEqual(c.oomSuspected, true);
			assert.strictEqual(c.stderrOom, true);
		});

		test('signal-exit + high RSS heuristic → oom (marked heuristic)', () => {
			const c = classifyExtensionHostExit({
				code: 134, // >128 signal exit
				reason: 'unknown',
				stderrOomSeen: false,
				lastRssBucketMb: HIGH_RSS_BUCKET_MB,
			});
			assert.strictEqual(c.exitClass, 'oom');
			assert.strictEqual(c.oomSuspected, true);
			assert.strictEqual(c.oomHeuristic, true);
		});

		test('signal-exit without high RSS is not oom', () => {
			const c = classifyExtensionHostExit({
				code: 134,
				reason: 'unknown',
				stderrOomSeen: false,
				lastRssBucketMb: 512,
			});
			assert.strictEqual(c.oomSuspected, false);
			assert.strictEqual(c.exitClass, 'unknown');
		});

		test('clean exit', () => {
			const c = classifyExtensionHostExit({
				code: 0,
				reason: 'clean-exit',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'clean');
			assert.strictEqual(c.oomSuspected, false);
		});

		test('code 0 without reason still clean', () => {
			const c = classifyExtensionHostExit({
				code: 0,
				reason: undefined,
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'clean');
		});

		test('VersionMismatch=55 wins over oom flags', () => {
			const c = classifyExtensionHostExit({
				code: ExtensionHostExitCode.VersionMismatch,
				reason: 'oom',
				stderrOomSeen: true,
				lastRssBucketMb: HIGH_RSS_BUCKET_MB,
			});
			assert.strictEqual(c.exitClass, 'versionMismatch');
			// oomSuspected still true (OR of signals) but exitClass prioritizes version mismatch
			assert.strictEqual(c.oomSuspected, true);
		});

		test('UnexpectedError=81 without oom → unexpectedError', () => {
			const c = classifyExtensionHostExit({
				code: ExtensionHostExitCode.UnexpectedError,
				reason: 'abnormal-exit',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'unexpectedError');
		});

		test('UnexpectedError=81 with stderr oom → oom', () => {
			const c = classifyExtensionHostExit({
				code: ExtensionHostExitCode.UnexpectedError,
				reason: 'abnormal-exit',
				stderrOomSeen: true,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'oom');
		});

		test('reason crashed → crash', () => {
			const c = classifyExtensionHostExit({
				code: 1,
				reason: 'crashed',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'crash');
		});

		test('reason killed → killed', () => {
			const c = classifyExtensionHostExit({
				code: 1,
				reason: 'killed',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			assert.strictEqual(c.exitClass, 'killed');
		});
	});

	suite('crash record shape + telemetry guard', () => {
		function sampleRecord(): ExtensionHostCrashRecord {
			const classification = classifyExtensionHostExit({
				code: 134,
				reason: 'oom',
				stderrOomSeen: true,
				lastRssBucketMb: 6144,
			});
			return buildExtensionHostCrashRecord({
				ts: 1_700_000_000_000,
				code: 134,
				signal: 'unknown',
				reason: 'oom',
				classification,
				affinity: 1,
				pid: 4242,
				uptimeSec: 90,
				lastRssBucketMb: 6144,
				lastHeapUsedMb: 5800,
				secondsSinceLastSample: 12,
				secondsSinceLastAlert: 40,
				extensionIds: ['pub.extA', 'pub.extB'],
			});
		}

		test('record is numbers/enums/opaque-ids only', () => {
			const record = sampleRecord();
			assert.strictEqual(record.schema, 1);
			assert.strictEqual(record.exitClass, 'oom');
			assert.strictEqual(record.oomSuspected, true);
			assert.strictEqual(record.activatedExtensionCount, 2);
			const json = JSON.stringify(record);
			assert.ok(!json.includes('/Users/'));
			assert.ok(!json.includes('heap out of memory'));
			assert.ok(!json.includes('FATAL ERROR'));
		});

		test('exthostCrashRecord payload passes detectTelemetryUserData (boundMeasurements)', () => {
			const data = crashRecordTelemetryData(sampleRecord());
			const result = detectTelemetryUserData(data, {
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostCrashRecord',
			});
			assert.strictEqual(result.hit, false, `guard hit: ${result.hit ? result.layer + ' ' + result.detail : ''}`);
		});

		test('exthostCrashFlush payload passes detectTelemetryUserData', () => {
			const data = crashRecordTelemetryData(sampleRecord(), { flushDelaySec: 3600 });
			const result = detectTelemetryUserData(data, {
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostCrashFlush',
			});
			assert.strictEqual(result.hit, false, `guard hit: ${result.hit ? result.layer + ' ' + result.detail : ''}`);
		});

		test('filename is path-safe and encodes affinity+pid', () => {
			const name = crashRecordFileName(1_700_000_000_000, 2, 99);
			assert.ok(name.endsWith('-eh2-99.json'));
			assert.ok(!name.includes(':'));
			assert.ok(!name.includes('/'));
		});
	});

	suite('pending-errors write / flush / delete lifecycle', () => {
		const ROOT = URI.from({ scheme: 'vscode-tests', path: '/userdata' });
		let fileService: FileService;
		let disposables: DisposableStore;

		setup(() => {
			disposables = new DisposableStore();
			store.add(disposables);
			fileService = disposables.add(new FileService(new NullLogService()));
			disposables.add(fileService.registerProvider(ROOT.scheme, disposables.add(new InMemoryFileSystemProvider())));
		});

		function userDataHome(): URI {
			return ROOT;
		}

		function makeRecord(pid: number, ts: number): ExtensionHostCrashRecord {
			const classification = classifyExtensionHostExit({
				code: 1,
				reason: 'oom',
				stderrOomSeen: false,
				lastRssBucketMb: null,
			});
			return buildExtensionHostCrashRecord({
				ts,
				code: 1,
				signal: 'unknown',
				reason: 'oom',
				classification,
				affinity: 0,
				pid,
				uptimeSec: 10,
				lastRssBucketMb: null,
				lastHeapUsedMb: null,
				secondsSinceLastSample: null,
				secondsSinceLastAlert: null,
				extensionIds: ['pub.ext'],
			});
		}

		test('write then flush emits and deletes', async () => {
			const record = makeRecord(111, 1_700_000_000_000);
			const resource = await writePendingExtensionHostCrashRecord(fileService, userDataHome(), record);
			assert.strictEqual(await fileService.exists(resource), true);

			const emitted: { flushDelaySec: number; pid: number }[] = [];
			const result = await flushPendingExtensionHostCrashRecords(
				fileService,
				userDataHome(),
				1_700_000_003_600,
				(r, flushDelaySec) => {
					emitted.push({ flushDelaySec, pid: r.pid });
				},
			);

			assert.strictEqual(result.flushed, 1);
			assert.strictEqual(result.deletedAlreadySent, 0);
			assert.strictEqual(emitted.length, 1);
			assert.strictEqual(emitted[0]!.pid, 111);
			assert.strictEqual(emitted[0]!.flushDelaySec, 4);
			assert.strictEqual(await fileService.exists(resource), false);
		});

		test('sentInSession records are deleted without flush emit', async () => {
			const record = makeRecord(222, 1_700_000_000_000);
			const resource = await writePendingExtensionHostCrashRecord(fileService, userDataHome(), record);
			await markPendingCrashRecordSentInSession(fileService, resource, record);

			const emitted: unknown[] = [];
			const result = await flushPendingExtensionHostCrashRecords(
				fileService,
				userDataHome(),
				Date.now(),
				(r) => emitted.push(r),
			);

			assert.strictEqual(result.flushed, 0);
			assert.strictEqual(result.deletedAlreadySent, 1);
			assert.strictEqual(emitted.length, 0);
			assert.strictEqual(await fileService.exists(resource), false);
		});

		test('caps directory at MAX_PENDING_ERROR_RECORDS', async () => {
			const dir = pendingErrorsDir(userDataHome());
			for (let i = 0; i < MAX_PENDING_ERROR_RECORDS + 5; i++) {
				await writePendingExtensionHostCrashRecord(
					fileService,
					userDataHome(),
					makeRecord(1000 + i, 1_700_000_000_000 + i * 1000),
				);
			}
			const stat = await fileService.resolve(dir);
			const jsonFiles = (stat.children ?? []).filter(c => c.name.endsWith('.json'));
			assert.strictEqual(jsonFiles.length, MAX_PENDING_ERROR_RECORDS);
		});

		test('pending dir is under userDataPath not logs', async () => {
			const dir = pendingErrorsDir(userDataHome());
			assert.ok(dir.path.endsWith('/pending-errors'));
			assert.ok(!dir.path.includes('/logs/'));
			const resource = await writePendingExtensionHostCrashRecord(fileService, userDataHome(), makeRecord(1, Date.now()));
			assert.strictEqual(resource.scheme, ROOT.scheme);
			assert.ok(resource.path.startsWith(dir.path));
		});
	});

	suite('exit context publish/consume', () => {
		test('round-trips by pid', () => {
			publishExtensionHostExitContext({
				code: 1,
				signal: 'unknown',
				reason: 'oom',
				stderrOomSeen: true,
				affinity: 3,
				pid: 555,
				uptimeSec: 12,
				lastRssBucketMb: null,
				lastHeapUsedMb: null,
				secondsSinceLastSample: null,
				secondsSinceLastAlert: null,
				exitClass: 'oom',
				oomSuspected: true,
				oomHeuristic: false,
			});
			const ctx = consumeExtensionHostExitContext(555);
			assert.ok(ctx);
			assert.strictEqual(ctx!.reason, 'oom');
			assert.strictEqual(ctx!.affinity, 3);
			assert.strictEqual(consumeExtensionHostExitContext(555), undefined);
		});
	});
});
