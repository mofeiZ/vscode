/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import { detectTelemetryUserData, flattenTelemetryStrings, formatTelemetryGuardViolation } from '../../common/telemetryDataGuard.js';

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
		assert.deepStrictEqual(flat.sort(), ['x', 'y']);
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
});
