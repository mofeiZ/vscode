/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import {
	SessionEntityIdMap,
	SessionFileIdMap,
	SessionOpaqueIdMap,
	mintSessionId,
	mintWorkspaceId,
} from '../../common/opaqueIds.js';
import { isAllowedExtensionTelemetryString } from '../../common/telemetryDataGuard.js';

suite('SessionOpaqueIdMap (u45)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	test('stable per-session ids for the same key', () => {
		const map = new SessionFileIdMap();
		const a = map.opaqueId('/Users/alice/proj/a.ts');
		const a2 = map.opaqueId('/Users/alice/proj/a.ts');
		const b = map.opaqueId('/Users/alice/proj/b.ts');
		assert.strictEqual(a, 'file-1');
		assert.strictEqual(a2, 'file-1');
		assert.strictEqual(b, 'file-2');
		assert.strictEqual(map.size, 2);
		assert.ok(isAllowedExtensionTelemetryString(a));
		assert.ok(isAllowedExtensionTelemetryString(b));
	});

	test('different sessions get independent maps (not longitudinally joinable)', () => {
		const session1 = new SessionOpaqueIdMap('file');
		const session2 = new SessionOpaqueIdMap('file');
		const path = '/Users/alice/proj/shared.ts';
		assert.strictEqual(session1.opaqueId(path), 'file-1');
		assert.strictEqual(session2.opaqueId(path), 'file-1');
		// Same shape, but maps are independent: mutating one does not affect the other.
		session1.opaqueId('/Users/alice/proj/other.ts');
		assert.strictEqual(session1.size, 2);
		assert.strictEqual(session2.size, 1);
		// Session tokens differ across salts — fleet cannot join sessions by sess-*.
		const sessA = mintSessionId(new Uint8Array([1, 2, 3, 4]));
		const sessB = mintSessionId(new Uint8Array([9, 8, 7, 6]));
		assert.notStrictEqual(sessA, sessB);
		assert.ok(/^sess-[0-9a-f]{6}$/.test(sessA));
		assert.ok(isAllowedExtensionTelemetryString(sessA));
	});

	test('entity / ext prefixes mint guard-safe opaque ids', () => {
		const ext = new SessionEntityIdMap('ext');
		assert.strictEqual(ext.opaqueId('publisher.slow'), 'ext-1');
		assert.strictEqual(ext.opaqueId('publisher.fast'), 'ext-2');
		assert.strictEqual(ext.opaqueId('publisher.slow'), 'ext-1');
		assert.ok(isAllowedExtensionTelemetryString('ext-1'));
		const entity = new SessionOpaqueIdMap('entity');
		assert.strictEqual(entity.opaqueId('widget'), 'entity-1');
	});

	test('mintWorkspaceId is salted (same roots, different salt → different ws id)', () => {
		const roots = ['/Users/alice/proj'] as const;
		const ws1 = mintWorkspaceId('salt-a', roots);
		const ws2 = mintWorkspaceId('salt-b', roots);
		assert.notStrictEqual(ws1, ws2);
		assert.ok(/^ws-[0-9a-f]{6}$/.test(ws1));
		assert.ok(isAllowedExtensionTelemetryString(ws1));
	});
});
