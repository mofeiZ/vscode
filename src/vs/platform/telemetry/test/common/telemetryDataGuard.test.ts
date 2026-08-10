/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import {
	detectTelemetryUserData,
	flattenTelemetryStrings,
	formatTelemetryGuardViolation,
	isAllowedExtensionTelemetryString,
	redactTelemetryGuardEventName,
	scrubPersistedExtensionHostLogLine,
} from '../../common/telemetryDataGuard.js';

suite('TelemetryDataGuard', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	test('numeric-only payload is ok', () => {
		const result = detectTelemetryUserData({ count: 3, ok: true, nested: { n: 1 } });
		assert.strictEqual(result.hit, false);
	});

	test('trusted-looking object without paths is ok', () => {
		const result = detectTelemetryUserData({
			common: { extname: 'interview-toybox.desk-gnome', extversion: '0.1.0' },
			measurements: { duration: 12 },
		});
		assert.strictEqual(result.hit, false);
	});

	test('strict-shape allows opaque tokens and numbers', () => {
		const result = detectTelemetryUserData(
			{ extname: 'interview-toybox.desk-gnome', duration: 12, status: 'ok' },
			{ strictShape: true },
		);
		assert.strictEqual(result.hit, false);
	});

	test('absolute user path is blocked', () => {
		const result = detectTelemetryUserData({ filePath: '/Users/alice/secret.ts' });
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.strictEqual(result.layer, 'path');
			assert.ok(result.detail.includes('user-file-path'));
		}
	});

	test('tmp workspace path shape is blocked', () => {
		const result = detectTelemetryUserData({
			filePath: '/tmp/desk-gnome-oss-u11-demo/workspace/secret.ts',
		});
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.strictEqual(result.layer, 'path');
		}
	});

	test('GitHub token is blocked', () => {
		const result = detectTelemetryUserData({
			auth: 'ghp_012345678901234567890123456789012345',
		});
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.strictEqual(result.layer, 'secret');
			assert.ok(result.detail.includes('GitHub'));
		}
	});

	test('marker / canary token is blocked', () => {
		const canary = 'ANYARCHIVE_TEL_CANARY_abc123';
		const result = detectTelemetryUserData(
			{ note: `planted ${canary} in payload` },
			[canary],
		);
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.strictEqual(result.layer, 'canary');
		}
	});

	test('flattenTelemetryStrings walks nested objects', () => {
		const flat = flattenTelemetryStrings({ a: { b: 'x' }, c: ['y', 2] });
		assert.ok(flat.includes('x'));
		assert.ok(flat.includes('y'));
	});

	test('formatTelemetryGuardViolation is structured JSON without raw path', () => {
		const line = formatTelemetryGuardViolation({
			timestamp: '2026-08-10T00:00:00.000Z',
			eventName: 'interview-toybox.desk-gnome/anyarchive.probe',
			layer: 'path',
			detail: '<REDACTED: user-file-path>',
			pluginHostTelemetry: false,
			extensionId: 'interview-toybox.desk-gnome',
			pipe: 'extHost',
		});
		assert.ok(line.includes('anyarchive.probe'));
		assert.ok(line.includes('"layer":"path"'));
		assert.ok(!line.includes('/Users/'));
		JSON.parse(line);
	});

	// --- rt1 PoC families (strict-shape / extension-originated) ---

	test('rt1#1 measurements char-codes are BLOCKED (strict)', () => {
		const path = '/Users/alice/proj/secret.ts';
		const measurements: Record<string, number> = {};
		for (let i = 0; i < path.length; i++) {
			measurements[`c${i}`] = path.charCodeAt(i);
		}
		const result = detectTelemetryUserData({ measurements }, { strictShape: true });
		assert.strictEqual(result.hit, true);
	});

	test('rt1#2 base64 / hex / url-encoding are BLOCKED (strict)', () => {
		const path = '/Users/alice/proj/secret.ts';
		const b64 = globalThis.btoa(path);
		const hex = Array.from(path).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
		const url = encodeURIComponent(path);

		for (const payload of [{ p: b64 }, { p: hex }, { p: url }]) {
			const result = detectTelemetryUserData(payload, { strictShape: true });
			assert.strictEqual(result.hit, true, `expected block for ${JSON.stringify(payload)}`);
		}
	});

	test('rt1#3 non-enumerable own properties are BLOCKED (strict)', () => {
		const payload: Record<string, unknown> = {};
		Object.defineProperty(payload, 'hiddenPath', {
			value: '/Users/alice/proj/secret.ts',
			enumerable: false,
			configurable: true,
			writable: true,
		});
		assert.deepStrictEqual(Object.keys(payload), []);
		const result = detectTelemetryUserData(payload, { strictShape: true });
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.strictEqual(result.layer, 'path');
		}
	});

	test('rt1#4 split across fields / arrays is BLOCKED (strict)', () => {
		const result = detectTelemetryUserData(
			{ a: 'Users', b: 'alice', c: 'proj', d: 'secret.ts', parts: ['Users', 'alice', 'proj'] },
			{ strictShape: true },
		);
		assert.strictEqual(result.hit, true);
	});

	test('rt1#5 slash homoglyphs are BLOCKED (strict)', () => {
		const result = detectTelemetryUserData(
			{ filePath: '/Users\uFF0Falice\uFF0Fproj\uFF0Fsecret.ts' },
			{ strictShape: true },
		);
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.ok(result.layer === 'path' || result.layer === 'shape');
		}
	});

	test('rt1#6 Map / Set / byte arrays are BLOCKED (strict)', () => {
		const mapHit = detectTelemetryUserData(
			{ bag: new Map([['p', '/Users/alice/proj/secret.ts']]) },
			{ strictShape: true },
		);
		assert.strictEqual(mapHit.hit, true);

		const setHit = detectTelemetryUserData(
			{ bag: new Set(['/Users/alice/proj/secret.ts']) },
			{ strictShape: true },
		);
		assert.strictEqual(setHit.hit, true);

		const path = '/Users/alice/proj/secret.ts';
		const bytes = Uint8Array.from(Array.from(path).map(c => c.charCodeAt(0)));
		const byteHit = detectTelemetryUserData({ bytes }, { strictShape: true });
		assert.strictEqual(byteHit.hit, true);
	});

	test('rt1#7 depth > 8 fails closed for extension events (strict)', () => {
		let nested: Record<string, unknown> = { filePath: '/Users/alice/proj/secret.ts' };
		for (let i = 0; i < 10; i++) {
			nested = { child: nested };
		}
		const result = detectTelemetryUserData(nested, { strictShape: true });
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.ok(result.layer === 'shape' || result.layer === 'path');
		}
	});

	test('F2 event name with path is redacted in violation log', () => {
		const leaked = '/Users/alice/proj/secret.ts';
		const line = formatTelemetryGuardViolation({
			timestamp: '2026-08-10T00:00:00.000Z',
			eventName: leaked,
			layer: 'path',
			detail: '<REDACTED: user-file-path>',
			pluginHostTelemetry: false,
			extensionId: 'interview-toybox.desk-gnome',
			pipe: 'extHost',
		});
		assert.ok(!line.includes('/Users/alice'));
		assert.ok(line.includes('REDACTED'));
		assert.strictEqual(redactTelemetryGuardEventName(leaked).includes('REDACTED'), true);
		const detect = detectTelemetryUserData({ ok: true }, {
			strictShape: true,
			eventName: leaked,
		});
		assert.strictEqual(detect.hit, true);
	});

	test('F1 scrubPersistedExtensionHostLogLine redacts paths and secrets', () => {
		const line = 'Error: ENOENT open /Users/alice/proj/secret.ts token=ghp_012345678901234567890123456789012345';
		const scrubbed = scrubPersistedExtensionHostLogLine(line);
		assert.ok(!scrubbed.includes('/Users/alice'));
		assert.ok(!scrubbed.includes('ghp_'));
		assert.ok(scrubbed.includes('REDACTED'));
	});

	test('G1 logError(Error) payload shape is BLOCKED (strict)', () => {
		// Mirrors extHostTelemetry logError(Error) bag: name/message/stack/cause + data.
		const result = detectTelemetryUserData({
			name: 'Error',
			message: "ENOENT: no such file or directory, open '/Users/alice/project/.env'",
			stack: 'Error: ENOENT\n    at Object.open (/Users/alice/project/ext.js:1:1)',
			folder: '/Users/alice/project',
		}, { strictShape: true, eventName: 'exception' });
		assert.strictEqual(result.hit, true);
	});

	test('G2 additionalCommonProperties payload shape is BLOCKED (strict)', () => {
		// Mirrors scanning data merged with options.additionalCommonProperties.
		const data = { count: 1 };
		const additionalCommonProperties = { workspaceRoot: '/Users/alice/project' };
		const result = detectTelemetryUserData(
			{ ...data, ...additionalCommonProperties },
			{ strictShape: true, eventName: 'anyarchive.probe' },
		);
		assert.strictEqual(result.hit, true);
	});

	test('free-form extension string fails strict allowlist', () => {
		assert.strictEqual(isAllowedExtensionTelemetryString('ok'), true);
		assert.strictEqual(isAllowedExtensionTelemetryString('hello world'), false);
		const result = detectTelemetryUserData(
			{ note: 'user pasted some free form prose' },
			{ strictShape: true },
		);
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.strictEqual(result.layer, 'shape');
		}
	});

	// --- sr1 follow-ups (u23) ---

	test('sr1#1 path in property NAME is BLOCKED (Path B strict-shape)', () => {
		const workspaceFsPath = '/Users/alice/proj/secret.ts';
		const result = detectTelemetryUserData(
			{ [workspaceFsPath]: 1 },
			{ strictShape: true, eventName: 'anyarchive.probe' },
		);
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.ok(result.layer === 'path' || result.layer === 'shape');
		}
	});

	test('sr1#1 path in property NAME is BLOCKED (Path A pluginHost bounds)', () => {
		const workspaceFsPath = '/Users/alice/proj/secret.ts';
		const result = detectTelemetryUserData(
			{ [workspaceFsPath]: 1, pluginHostTelemetry: true },
			{
				markers: [workspaceFsPath],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'anyarchive.probe.core',
			},
		);
		assert.strictEqual(result.hit, true);
		if (result.hit) {
			assert.ok(result.layer === 'path' || result.layer === 'canary');
		}
	});

	test('sr1#2 <=24 numeric char-code OBJECT is BLOCKED', () => {
		// Under the 24-leaf cap; previously only arrays/typed arrays reassembled.
		const path = '/Users/a/b/c.ts'; // 14 code units
		assert.ok(path.length <= 24);
		const measurements: Record<string, number> = {};
		for (let i = 0; i < path.length; i++) {
			measurements[`c${i}`] = path.charCodeAt(i);
		}
		const strict = detectTelemetryUserData({ measurements }, { strictShape: true });
		assert.strictEqual(strict.hit, true, 'strict-shape must block indexed char-code object');

		// Nest under measurements so pluginHostTelemetry boolean does not break
		// the all-numeric indexed-object detector at the top level.
		const pathA = detectTelemetryUserData(
			{ measurements, pluginHostTelemetry: true },
			{ boundMeasurements: true, failClosedOnDepthAbort: true },
		);
		assert.strictEqual(pathA.hit, true, 'Path A bounds must block indexed char-code object');
	});

	test('sr1#4 scrub redacts content, non-home paths, JWT, and base64', () => {
		const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepad1234567890';
		const b64Path = globalThis.btoa('/Users/alice/proj/secret.ts');
		const lines = [
			'console.log dump: ' + 'x'.repeat(200),
			'failed to read /opt/company/data/secrets.env',
			'cache at /var/folders/xx/abcdefgh/T/tmp-file',
			`auth ${jwt}`,
			`encoded ${b64Path}`,
			'also D:\\Users\\bob\\secret.ts',
		];
		for (const line of lines) {
			const scrubbed = scrubPersistedExtensionHostLogLine(line);
			assert.ok(scrubbed.includes('REDACTED'), `expected redaction for: ${line.slice(0, 60)}`);
			assert.ok(!scrubbed.includes('/opt/company'), `opt path leaked: ${scrubbed}`);
			assert.ok(!scrubbed.includes('/var/folders'), `var/folders leaked: ${scrubbed}`);
			assert.ok(!scrubbed.includes('/Users/alice'), `home path leaked: ${scrubbed}`);
			assert.ok(!scrubbed.includes(jwt), `JWT leaked: ${scrubbed}`);
			assert.ok(!scrubbed.includes('x'.repeat(80)), `long content leaked: ${scrubbed}`);
		}
	});

	test('activatePlugin-style first-party payload is not false-positive blocked', () => {
		// Path A without pluginHostTelemetry / strictShape — core first-party shape.
		const result = detectTelemetryUserData({
			id: 'vscode.git',
			name: 'Git',
			pluginHostTelemetry: false,
			duration: 12,
			nested: { count: 1, size: 2, idle: 3, working: 4 },
		}, { markers: ['/Users/alice/proj'] });
		assert.strictEqual(result.hit, false);
	});
});
