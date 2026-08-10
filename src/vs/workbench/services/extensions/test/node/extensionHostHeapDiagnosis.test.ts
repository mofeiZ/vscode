/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { URI } from '../../../../../base/common/uri.js';
import { detectTelemetryUserData } from '../../../../../platform/telemetry/common/telemetryDataGuard.js';
import {
	analyzeSamplingAttribution,
	assertSafeSummaryShape,
	attributeSamplingProfile,
	buildSafeSummary,
	diffClassGroups,
	mergeAttribution,
	pickDominatorShape,
	primaryGrownRetainedBytes,
	type ExtHostHeapAttributionSafeSummary,
} from '../../common/extensionHostHeapDiagnosis.js';
import {
	decodeSnapshotFile,
	extractClassGroups,
	startAllocationSampling,
	stopAndGetProfile,
	writeSnapshot,
} from '../../node/extensionHostHeapCapture.js';

suite('extensionHostHeapDiagnosis', function () {
	this.timeout(240_000);

	test('diffClassGroups ranks grown retained size', () => {
		const before = [
			{ name: 'Array', category: 'array' as const, count: 10, selfSize: 100, retainedSize: 1_000 },
			{ name: 'Object', category: 'object' as const, count: 5, selfSize: 50, retainedSize: 500 },
		];
		const after = [
			{ name: 'Array', category: 'array' as const, count: 20, selfSize: 200, retainedSize: 10_000 },
			{ name: 'Object', category: 'object' as const, count: 6, selfSize: 60, retainedSize: 600 },
			{ name: '(closure)', category: 'closure' as const, count: 3, selfSize: 30, retainedSize: 2_000 },
		];
		const deltas = diffClassGroups(before, after);
		assert.strictEqual(deltas[0]!.name, 'Array');
		assert.ok(deltas[0]!.retainedDelta > deltas[1]!.retainedDelta);
	});

	test('analyzeSamplingAttribution (Tier-0) emits enriched enum/shape fields with no raw strings', () => {
		const leakyDir = '/tmp/exts/leaky.ext';
		const tidyDir = '/tmp/exts/tidy.ext';
		const profile = {
			head: {
				id: 1,
				selfSize: 0,
				callFrame: { functionName: '(root)', scriptId: '0', url: '', lineNumber: 0, columnNumber: 0 },
				children: [
					{
						id: 2,
						selfSize: 180 * 1024 * 1024,
						callFrame: {
							functionName: 'activateEvent',
							scriptId: '1',
							url: URI.file(`${leakyDir}/extension.js`).toString(true),
							lineNumber: 10,
							columnNumber: 0,
						},
						children: [],
					},
					{
						id: 3,
						selfSize: 20 * 1024 * 1024,
						callFrame: {
							functionName: 'activateEvent',
							scriptId: '2',
							url: URI.file(`${tidyDir}/extension.js`).toString(true),
							lineNumber: 10,
							columnNumber: 0,
						},
						children: [],
					},
				],
			},
		};
		const { summary, reportMeta } = analyzeSamplingAttribution({
			profile,
			extensionLocations: [
				{ id: 'leaky.ext', location: URI.file(leakyDir) },
				{ id: 'tidy.ext', location: URI.file(tidyDir) },
			],
			pid: 7,
			snapshotSeq: 3,
		});
		assertSafeSummaryShape(summary);
		assert.strictEqual(summary.extensions[0]!.extRef, 'ext-1');
		assert.ok(summary.extensions[0]!.sharePct >= 60);
		assert.ok(['high', 'medium', 'low'].includes(summary.extensions[0]!.confidence));
		assert.strictEqual(typeof summary.extensions[0]!.lanesAgree, 'boolean');
		assert.ok(summary.grownClassGroups.length >= 1);
		assert.ok(['array', 'string', 'object', 'closure', 'map-set', 'arraybuffer', 'regexp', 'promise', 'native', 'other']
			.includes(summary.grownClassGroups[0]!.category));
		assert.ok(typeof summary.dominatorDepth === 'number');
		assert.ok(typeof summary.dominatorFanout === 'number');
		assert.ok(typeof summary.retainedTopSharePct === 'number');
		assert.ok(reportMeta.text.includes('leaky.ext'));
		const json = JSON.stringify(summary);
		assert.ok(!json.includes('leaky.ext'));
		assert.ok(!json.includes('/tmp/'));
		assert.ok(!json.includes('activateEvent'));
		assert.ok(!json.includes('sampled-live'));
		const guard = detectTelemetryUserData(
			{ ...summary, pluginHostTelemetry: true },
			{
				markers: ['/tmp/exts/leaky.ext', 'leaky.ext'],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostHeapAttribution',
			},
		);
		assert.strictEqual(guard.hit, false, `Tier-0 sampling summary must pass guard, got ${JSON.stringify(guard)}`);
	});

	test('buildSafeSummary is opaque ids / enums / numbers only and passes the guard', () => {
		const attribution = [
			{ extensionId: 'leaky.ext', liveSampledBytes: 200 * 1024 * 1024, retainedBytes: 180 * 1024 * 1024, sharePct: 80, confidence: 'high' as const, lanesAgree: true },
			{ extensionId: 'tidy.ext', liveSampledBytes: 20 * 1024 * 1024, retainedBytes: 10 * 1024 * 1024, sharePct: 20, confidence: 'low' as const, lanesAgree: true },
		];
		const grown = [
			{ name: 'ArrayBuffer', category: 'arraybuffer' as const, countDelta: 100, selfDelta: 50, retainedDelta: 150 * 1024 * 1024 },
			{ name: '(closure)', category: 'closure' as const, countDelta: 40, selfDelta: 10, retainedDelta: 20 * 1024 * 1024 },
		];
		const dominator = {
			topDominatorRetainedBytes: 150 * 1024 * 1024,
			dominatorDepth: 2,
			dominatorFanout: 4,
			retainedTopSharePct: 70,
			topDominatorName: 'ArrayBuffer',
		};
		const { summary, reportMeta } = buildSafeSummary({
			attribution,
			grown,
			dominator,
			affinity: 0,
			pid: 4242,
			snapshotSeq: 1,
		});
		assertSafeSummaryShape(summary);
		assert.strictEqual(summary.extensions[0]!.extRef, 'ext-1');
		assert.strictEqual(reportMeta.opaqueToExtensionId['ext-1'], 'leaky.ext');
		assert.ok(reportMeta.text.includes('leaky.ext'));
		assert.ok(!JSON.stringify(summary).includes('leaky.ext'));
		assert.ok(!JSON.stringify(summary).includes('ArrayBuffer'));

		const guard = detectTelemetryUserData(
			{ ...summary, pluginHostTelemetry: true },
			{
				markers: ['/Users/alice/proj', 'leaky.ext'],
				boundMeasurements: true,
				failClosedOnDepthAbort: true,
				eventName: 'exthostHeapAttribution',
			},
		);
		assert.strictEqual(guard.hit, false, `safe summary must pass guard, got ${JSON.stringify(guard)}`);
	});

	test('headless fixture: leaky extension attributed first with larger retained share', async function () {
		if (typeof globalThis.gc !== 'function') {
			// Allocation-sampling drops collected samples; GC makes the tidy
			// extension's transient garbage disappear from the profile.
			this.skip();
		}

		const root = realpathSync(mkdtempSync(join(tmpdir(), 'eh-heap-diag-')));
		const leakyDir = join(root, 'exts', 'leaky.ext');
		const tidyDir = join(root, 'exts', 'tidy.ext');
		mkdirSync(leakyDir, { recursive: true });
		mkdirSync(tidyDir, { recursive: true });

		// Leaky retains large buffers with a shallow graph (keeps heapsnapshots
		// decodable). Dense small-object churn is used only during sampling so
		// allocation stacks attribute to the extension URL (r11 scoped fallback).
		writeFileSync(join(leakyDir, 'extension.js'), `
const retained = [];
function activateEvent() {
  const buf = Buffer.allocUnsafe(1024 * 1024);
  buf[0] = 1;
  retained.push(buf);
}
function activateDense() {
  const chunk = [];
  const buf = Buffer.allocUnsafe(256 * 1024);
  for (let i = 0; i < 4000; i++) {
    chunk.push({ i: i, t: 'x'.repeat(16), buf: buf });
  }
  retained.push(chunk);
}
module.exports = { activateEvent, activateDense, retained };
`);
		writeFileSync(join(tidyDir, 'extension.js'), `
function activateEvent() {
  const buf = Buffer.allocUnsafe(1024 * 1024);
  buf[0] = 1;
  return buf.length;
}
function activateDense() {
  const chunk = [];
  const buf = Buffer.allocUnsafe(256 * 1024);
  for (let i = 0; i < 4000; i++) {
    chunk.push({ i: i, t: 'x'.repeat(16), buf: buf });
  }
  return chunk.length;
}
module.exports = { activateEvent, activateDense };
`);

		const require = createRequire(import.meta.url);
		const leaky = require(join(leakyDir, 'extension.js')) as {
			activateEvent: () => void;
			activateDense: () => void;
			retained: unknown[];
		};
		const tidy = require(join(tidyDir, 'extension.js')) as {
			activateEvent: () => void;
			activateDense: () => void;
		};

		const snapA = join(root, 'heap-a.heapsnapshot');
		const snapB = join(root, 'heap-b.heapsnapshot');

		try {
			// --- Lane 1 (sampling): dense retained objects so stacks name leaky.ext.
			await startAllocationSampling(16_384);
			for (let i = 0; i < 4; i++) {
				leaky.activateDense();
				tidy.activateDense();
			}
			for (let i = 0; i < 80; i++) {
				leaky.activateDense();
				tidy.activateDense();
			}
			globalThis.gc!();
			const profile = await stopAndGetProfile();

			// Drop dense retainers so the snapshot pair stays WASM-decodable
			// (r11 scoped fallback: large object graphs crash @vscode/v8-heap-parser).
			leaky.retained.length = 0;
			globalThis.gc!();

			// --- Snapshot pair: shallow 1 MB buffers (≥128 MB retained, small file).
			writeSnapshot(snapA);
			for (let i = 0; i < 160; i++) {
				leaky.activateEvent();
				tidy.activateEvent();
			}
			globalThis.gc!();
			writeSnapshot(snapB);

			const graphA = await decodeSnapshotFile(snapA);
			const graphB = await decodeSnapshotFile(snapB);
			const groupsA = extractClassGroups(graphA, 50);
			const groupsB = extractClassGroups(graphB, 50);
			const grown = diffClassGroups(groupsA, groupsB);

			const extensionLocations = [
				{ id: 'leaky.ext', location: URI.file(leakyDir) },
				{ id: 'tidy.ext', location: URI.file(tidyDir) },
			];
			const lane1 = attributeSamplingProfile(profile, extensionLocations);
			const grownRetainedBytes = primaryGrownRetainedBytes(grown);
			const attribution = mergeAttribution(lane1, new Map(), grownRetainedBytes);
			const dominator = pickDominatorShape(grown, groupsB);
			const { summary, reportMeta } = buildSafeSummary({
				attribution,
				grown,
				dominator,
				affinity: 0,
				pid: process.pid,
				snapshotSeq: 1,
			});

			assert.ok(attribution.length >= 1, 'expected at least one attributed extension');
			assert.strictEqual(attribution[0]!.extensionId, 'leaky.ext', `expected leaky.ext first, got ${attribution.map(a => a.extensionId).join(',')}`);
			assert.ok(attribution[0]!.sharePct >= 60, `expected leaky share ≥ 60, got ${attribution[0]!.sharePct}`);

			const leakySafe = summary.extensions.find(e => reportMeta.opaqueToExtensionId[e.extRef] === 'leaky.ext');
			const tidySafe = summary.extensions.find(e => reportMeta.opaqueToExtensionId[e.extRef] === 'tidy.ext');
			assert.ok(leakySafe, 'safe summary must include opaque id for leaky.ext');
			assert.strictEqual(summary.extensions[0]!.extRef, leakySafe!.extRef, 'leaky opaque id must be rank 1');
			assert.ok(
				leakySafe!.retainedBucketMb >= 128,
				`leaky retained bucket should be ≥128, got ${leakySafe!.retainedBucketMb} (grownRetainedBytes=${grownRetainedBytes}, liveSampled=${attribution[0]!.liveSampledBytes})`,
			);
			if (tidySafe) {
				assert.ok(leakySafe!.liveSampledBucketMb >= tidySafe.liveSampledBucketMb, `live bucket leaky=${leakySafe!.liveSampledBucketMb} tidy=${tidySafe.liveSampledBucketMb}`);
				assert.ok(leakySafe!.retainedBucketMb > tidySafe.retainedBucketMb, `retained bucket leaky=${leakySafe!.retainedBucketMb} tidy=${tidySafe.retainedBucketMb}`);
			}
			assert.ok(attribution[0]!.liveSampledBytes > 0, 'leaky must have nonzero live sampled bytes');

			const grownCategories = new Set(summary.grownClassGroups.map(g => g.category));
			assert.ok(
				grownCategories.has('arraybuffer') || grownCategories.has('array') || grownCategories.has('closure') || grownCategories.has('object') || grownCategories.has('string'),
				`expected grown categories among arraybuffer/array/closure/object/string, got ${[...grownCategories].join(',')}`,
			);
			assert.ok(
				summary.topDominatorRetainedBucketMb >= 128,
				`topDominatorRetainedBucketMb should cover planted ≥128MB bucket, got ${summary.topDominatorRetainedBucketMb}`,
			);

			assertSafeSummaryShape(summary);
			assertNoSensitiveStrings(summary, [leakyDir, tidyDir, 'leaky.ext', 'tidy.ext', 'ArrayBuffer']);
			assert.ok(reportMeta.text.includes('leaky.ext'), 'local report should name the leaky fixture');

			const guard = detectTelemetryUserData(
				{ ...summary, pluginHostTelemetry: true },
				{
					markers: [leakyDir, tidyDir, '/Users/alice/proj'],
					boundMeasurements: true,
					failClosedOnDepthAbort: true,
					eventName: 'exthostHeapAttribution',
				},
			);
			assert.strictEqual(guard.hit, false, `fixture safe summary must pass guard, got ${JSON.stringify(guard)}`);
		} finally {
			try { await stopAndGetProfile(); } catch { /* sampling may already be stopped */ }
			rmSync(root, { recursive: true, force: true });
		}
	});
});

function assertNoSensitiveStrings(summary: ExtHostHeapAttributionSafeSummary, forbidden: readonly string[]): void {
	const blob = JSON.stringify(summary);
	for (const f of forbidden) {
		assert.ok(!blob.includes(f), `safe summary must not contain ${f}`);
	}
}
