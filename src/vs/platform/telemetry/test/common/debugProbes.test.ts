/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import {
	DEBUG_PROBE_MAX_TTL_DAYS,
	defineDebugProbe,
	hashOpaque,
	isDebugProbeExpired,
	logDebugProbe,
	opaque,
	setDebugProbeNowMs,
	setDebugProbeViolationSink,
	type OpaqueId,
	type SafeProbeLeaf,
} from '../../common/debugProbes/logDebugProbe.js';
import { DbgScaffoldSmoke } from '../../common/debugProbes/probes/dbg-scaffold-smoke.js';
import { ITelemetryService, TelemetryLevel } from '../../common/telemetry.js';

// ---- compile-time SafeProbePayload exclusions (fail tsc if regressing) ----
type ExpectTrue<T extends true> = T;
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type _freeFormStringRejected = ExpectTrue<Equal<SafeProbeLeaf<string>, never>>;
type _enumLiteralOk = ExpectTrue<Equal<SafeProbeLeaf<'warn'>, 'warn'>>;
type _numberOk = ExpectTrue<Equal<SafeProbeLeaf<number>, number>>;
type _opaqueOk = ExpectTrue<Equal<SafeProbeLeaf<OpaqueId>, OpaqueId>>;
type _compileTimeChecks = [_freeFormStringRejected, _enumLiteralOk, _numberOk, _opaqueOk];
const _checks: _compileTimeChecks | undefined = undefined;
void _checks;

function makeRecordingTelemetry(): ITelemetryService & { events: { name: string; data: unknown }[] } {
	const events: { name: string; data: unknown }[] = [];
	const svc: ITelemetryService & { events: { name: string; data: unknown }[] } = {
		_serviceBrand: undefined,
		telemetryLevel: TelemetryLevel.USAGE,
		sessionId: 's',
		machineId: 'm',
		sqmId: 'q',
		devDeviceId: 'd',
		firstSessionDate: '2026-01-01',
		sendErrorTelemetry: false,
		events,
		publicLog(eventName, data) { events.push({ name: eventName, data }); },
		publicLog2(eventName, data) { events.push({ name: eventName, data }); },
		publicLogError() { },
		publicLogError2() { },
		setExperimentProperty() { },
		setCommonProperty() { },
		setDataGuardMarkers() { },
	};
	return svc;
}

function activeProbe() {
	// `as const` keeps probeId a string literal (defineDebugProbe rejects widened `string`).
	return defineDebugProbe({
		probeId: 'dbg-4711-exthost-rss-spike',
		owner: 'agent:u33',
		createdAt: '2026-08-01',
		issueRef: 'anyarchive#4711',
		issue: 'anyarchive#4711',
		ttlDays: 60,
		expiresAt: '2026-09-30',
		comment: 'unit-test probe',
		gdpr: {
			owner: 'agent:u33',
			comment: 'test',
			rssMb: { classification: 'SystemMetaData', purpose: 'PerformanceAndHealth', comment: 'RSS', isMeasurement: true },
			bucket: { classification: 'SystemMetaData', purpose: 'PerformanceAndHealth', comment: 'bucket' },
		},
	} as const);
}

suite('DebugProbes', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		setDebugProbeViolationSink(undefined);
		setDebugProbeNowMs(undefined);
	});

	test('SafeProbePayload: free-form string does not type-check (@ts-expect-error)', () => {
		const svc = makeRecordingTelemetry();
		const probe = activeProbe();
		const freeForm: string = '/Users/alice/secret.ts';
		// @ts-expect-error free-form string is not a SafeProbeLeaf
		logDebugProbe(svc, probe, { path: freeForm });
		// Even if cast past the type system, runtime guard must drop it (covered below).
		assert.ok(true);
	});

	test('path/secret payload via as-any is refused: dropped + violation logged, not sent', () => {
		const svc = makeRecordingTelemetry();
		const probe = activeProbe();
		const violations: string[] = [];
		setDebugProbeViolationSink(line => violations.push(line));

		logDebugProbe(svc, probe, { filePath: '/Users/alice/secret.ts' } as any);

		assert.strictEqual(svc.events.length, 0, 'leaky payload must not be sent');
		assert.strictEqual(violations.length, 1);
		const parsed = JSON.parse(violations[0]);
		assert.strictEqual(parsed.action, 'blocked');
		assert.strictEqual(parsed.layer, 'path');
		assert.ok(String(parsed.event).includes('dbg-4711-exthost-rss-spike'));
	});

	test('secret-shaped as-any payload is refused', () => {
		const svc = makeRecordingTelemetry();
		const probe = activeProbe();
		const violations: string[] = [];
		setDebugProbeViolationSink(line => violations.push(line));

		logDebugProbe(svc, probe, { token: 'ghp_012345678901234567890123456789012345' } as any);

		assert.strictEqual(svc.events.length, 0);
		assert.strictEqual(violations.length, 1);
		assert.strictEqual(JSON.parse(violations[0]).layer, 'secret');
	});

	test('numbers/enum/opaqueId payload is accepted and routed via publicLog2', () => {
		const svc = makeRecordingTelemetry();
		const probe = activeProbe();
		const violations: string[] = [];
		setDebugProbeViolationSink(line => violations.push(line));

		const fileId = opaque('fid.a1b2c3');
		const pathHash = hashOpaque('/Users/alice/secret.ts', 16);
		logDebugProbe(svc, probe, {
			rssMb: 512,
			ok: true,
			bucket: 'warn',
			fileId,
			pathHash,
		});

		assert.strictEqual(violations.length, 0, violations[0] ?? 'no violation');
		assert.strictEqual(svc.events.length, 1);
		assert.strictEqual(svc.events[0].name, 'debugProbe/dbg-4711-exthost-rss-spike');
		const data = svc.events[0].data as Record<string, unknown>;
		assert.strictEqual(data['rssMb'], 512);
		assert.strictEqual(data['ok'], true);
		assert.strictEqual(data['bucket'], 'warn');
		assert.strictEqual(data['fileId'], 'fid.a1b2c3');
		assert.strictEqual(typeof data['pathHash'], 'string');
		assert.ok(String(data['pathHash']).startsWith('h.'), 'hashOpaque prefixes h. for guard-safe shape');
		assert.strictEqual((data['pathHash'] as string).length, 2 + 16);
		assert.strictEqual(data['probeId'], 'dbg-4711-exthost-rss-spike');
	});

	test('expired probe (ttl elapsed) does not emit', () => {
		const svc = makeRecordingTelemetry();
		const probe = defineDebugProbe({
			probeId: 'dbg-4711-exthost-rss-spike',
			owner: 'agent:u33',
			createdAt: '2026-01-01',
			issueRef: 'anyarchive#4711',
			issue: 'anyarchive#4711',
			ttlDays: 30,
			expiresAt: '2026-01-31',
			comment: 'unit-test probe',
			gdpr: {
				owner: 'agent:u33',
				comment: 'test',
				rssMb: { classification: 'SystemMetaData', purpose: 'PerformanceAndHealth', comment: 'RSS', isMeasurement: true },
				bucket: { classification: 'SystemMetaData', purpose: 'PerformanceAndHealth', comment: 'bucket' },
			},
		} as const);
		assert.strictEqual(isDebugProbeExpired(probe, Date.parse('2026-02-01')), true);

		setDebugProbeNowMs(() => Date.parse('2026-08-10T12:00:00.000Z'));
		logDebugProbe(svc, probe, { rssMb: 1, bucket: 'ok' });
		assert.strictEqual(svc.events.length, 0);
	});

	test('defineDebugProbe rejects ttl > 90 days', () => {
		assert.throws(() => defineDebugProbe({
			probeId: 'dbg-too-long',
			owner: 'agent:u33',
			createdAt: '2026-08-10',
			issueRef: 'anyarchive#1',
			ttlDays: DEBUG_PROBE_MAX_TTL_DAYS + 1,
			comment: 'too long',
			gdpr: { owner: 'agent:u33', comment: 'x' },
		} as const), /exceeds max/);
	});

	test('enumerate script lists probes with owner/expiry/status', () => {
		// npm run test-node runs with cwd = repo root (worktree).
		const repoRoot = process.cwd();
		const script = join(repoRoot, 'scripts/debug-probes/enumerate.mjs');
		assert.ok(existsSync(script), `enumerate script missing: ${script}`);
		assert.ok(
			existsSync(join(repoRoot, 'src/vs/platform/telemetry/common/debugProbes/probes/dbg-scaffold-smoke.ts')),
			'probe module missing under cwd',
		);

		const result = spawnSync(process.execPath, [script, '--repo', repoRoot], {
			encoding: 'utf8',
			timeout: 30_000,
		});
		assert.strictEqual(result.status, 0, result.stderr || result.stdout);
		const json = JSON.parse(result.stdout);
		assert.ok(Array.isArray(json.probes));
		const smoke = json.probes.find((p: { probeId: string }) => p.probeId === 'dbg-scaffold-smoke');
		assert.ok(smoke, 'dbg-scaffold-smoke must appear in enumerate output');
		assert.strictEqual(smoke.owner, 'agent:u33');
		assert.strictEqual(smoke.issue, 'anyarchive#u33');
		assert.strictEqual(smoke.issueRef, 'anyarchive#u33');
		assert.strictEqual(smoke.ttlDays, 90);
		assert.strictEqual(smoke.expiresAt, '2026-11-08');
		assert.strictEqual(typeof smoke.expired, 'boolean');
		assert.strictEqual(smoke.expired, false);
		assert.strictEqual(smoke.status, 'active');
		assert.ok(Array.isArray(smoke.callSites));

		// Registry module itself is importable / has expected manifest slice.
		assert.strictEqual(DbgScaffoldSmoke.probeId, 'dbg-scaffold-smoke');
		assert.strictEqual(DbgScaffoldSmoke.ttlDays, 90);
		assert.strictEqual(DbgScaffoldSmoke.issueRef, 'anyarchive#u33');
	});
});

