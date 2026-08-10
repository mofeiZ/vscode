/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Extension-host heap diagnosis — pure analysis (u37 / r11).
 *
 * Attribution reuses the CPU profiler URL→extension mapping
 * (`TernarySearchTree.forUris` + `findSubstr` on script URLs). Safe summaries
 * carry numbers / closed enums / opaque per-session ids only — never paths,
 * constructor names, or marketplace ids.
 */

import { TernarySearchTree } from '../../../../base/common/ternarySearchTree.js';
import { URI } from '../../../../base/common/uri.js';
import { Schemas } from '../../../../base/common/network.js';
import { bucketRssMb } from './extensionHostMemoryMonitor.js';

export const HEAP_DIAGNOSIS_SCHEMA = 1;

/** Closed class categories for telemetered summaries (never raw constructor names). */
export type HeapClassCategory =
	| 'array'
	| 'string'
	| 'object'
	| 'closure'
	| 'map-set'
	| 'arraybuffer'
	| 'regexp'
	| 'promise'
	| 'native'
	| 'other';

/** Closed edge-type labels for retainer path shape (parser EdgeType). */
export type HeapEdgeTypeCategory =
	| 'context'
	| 'element'
	| 'property'
	| 'internal'
	| 'hidden'
	| 'shortcut'
	| 'weak'
	| 'invisible'
	| 'other';

export type HeapAttributionConfidence = 'high' | 'medium' | 'low';

/** Plain class-group row extracted from a decoded snapshot (no WASM types). */
export interface HeapClassGroupSummary {
	readonly name: string;
	readonly category: HeapClassCategory;
	readonly count: number;
	readonly selfSize: number;
	readonly retainedSize: number;
}

export interface HeapClassGroupDelta {
	readonly name: string;
	readonly category: HeapClassCategory;
	readonly countDelta: number;
	readonly selfDelta: number;
	readonly retainedDelta: number;
}

/** CDP `HeapProfiler` sampling profile node (subset). */
export interface AllocationSamplingProfileNode {
	readonly callFrame: {
		readonly functionName: string;
		readonly scriptId: string;
		readonly url: string;
		readonly lineNumber: number;
		readonly columnNumber: number;
	};
	readonly selfSize: number;
	readonly id: number;
	readonly children?: readonly AllocationSamplingProfileNode[];
}

export interface AllocationSamplingProfile {
	readonly head: AllocationSamplingProfileNode;
	readonly samples?: readonly unknown[];
}

export interface ExtensionLocationRef {
	readonly id: string;
	readonly location: URI;
}

export interface ExtensionAttributionRow {
	readonly extensionId: string;
	readonly liveSampledBytes: number;
	readonly retainedBytes: number;
	readonly sharePct: number;
	readonly confidence: HeapAttributionConfidence;
	readonly lanesAgree: boolean;
}

export interface DominatorShape {
	readonly topDominatorRetainedBytes: number;
	readonly dominatorDepth: number;
	readonly dominatorFanout: number;
	readonly retainedTopSharePct: number;
	/** Local-only label (constructor / class name). Never telemetered. */
	readonly topDominatorName: string;
}

export interface RetainerPathShape {
	readonly pathLen: number;
	readonly edgeTypes: readonly HeapEdgeTypeCategory[];
	readonly nodeCategories: readonly HeapClassCategory[];
}

export interface ExtHostHeapAttributionExtension {
	readonly extRef: string;
	readonly liveSampledBucketMb: number;
	readonly retainedBucketMb: number;
	readonly sharePct: number;
	readonly rank: number;
	readonly confidence: HeapAttributionConfidence;
	readonly lanesAgree: boolean;
}

export interface ExtHostHeapAttributionClassGroup {
	readonly classRef: string;
	readonly category: HeapClassCategory;
	readonly countDelta: number;
	readonly retainedDeltaBucketMb: number;
	readonly selfDeltaBucketMb: number;
}

/**
 * Telemetry-safe summary. Kept under the Path-A `boundMeasurements` numeric-leaf
 * cap (≤24 code-unit leaves): top-2 extensions + top-2 class groups + compact
 * dominator/retainer shape. Full local report carries richer detail.
 */
export interface ExtHostHeapAttributionSafeSummary {
	readonly schema: number;
	readonly affinity: number;
	readonly pid: number;
	readonly snapshotSeq: number;
	readonly extensions: readonly ExtHostHeapAttributionExtension[];
	readonly grownClassGroups: readonly ExtHostHeapAttributionClassGroup[];
	readonly topDominatorRetainedBucketMb: number;
	readonly dominatorDepth: number;
	readonly dominatorFanout: number;
	readonly retainedTopSharePct: number;
	readonly retainerPathLen: number;
}

export interface HeapDiagnosisLocalReport {
	readonly text: string;
	/** Opaque id → real extension id (local only). */
	readonly opaqueToExtensionId: Readonly<Record<string, string>>;
	/** Real extension id → opaque id. */
	readonly extensionIdToOpaque: Readonly<Record<string, string>>;
}

const ROOTISH_CLASS_NAMES = new Set([
	'global',
	'system / context',
	'(root)',
	'root',
]);

export function categorizeClassName(name: string): HeapClassCategory {
	const n = name.trim().toLowerCase();
	if (n.includes('arraybuffer') || n.includes('jsarraybufferdata') || n === 'buffer') {
		return 'arraybuffer';
	}
	if (n === 'array' || n === '(array)') {
		return 'array';
	}
	if (n.includes('string') || n === '(string)') {
		return 'string';
	}
	if (n.includes('closure') || n === '(closure)') {
		return 'closure';
	}
	if (n === 'map' || n === 'set' || n === 'weakmap' || n === 'weakset') {
		return 'map-set';
	}
	if (n === 'regexp' || n === '(regexp)') {
		return 'regexp';
	}
	if (n === 'promise') {
		return 'promise';
	}
	if (n.startsWith('system /') || n.includes('native') || n === '(compiled code)' || n === 'code') {
		return 'native';
	}
	if (n === 'object' || n === 'global') {
		return 'object';
	}
	return 'other';
}

/** Map parser NodeType ordinal (0–13) onto the closed category enum. */
export function categorizeNodeType(nodeType: number): HeapClassCategory {
	switch (nodeType) {
		case 1: return 'array';       // Array
		case 2: return 'string';      // String
		case 3: return 'object';      // Object
		case 5: return 'closure';     // Closure
		case 6: return 'regexp';      // RegExp
		case 8: return 'native';      // Native
		case 10:                      // ConcatString
		case 11: return 'string';     // SliceString
		default: return 'other';
	}
}

export function edgeTypeCategory(edgeType: number): HeapEdgeTypeCategory {
	switch (edgeType) {
		case 0: return 'context';
		case 1: return 'element';
		case 2: return 'property';
		case 3: return 'internal';
		case 4: return 'hidden';
		case 5: return 'shortcut';
		case 6: return 'weak';
		case 7: return 'invisible';
		default: return 'other';
	}
}

export function diffClassGroups(
	before: readonly HeapClassGroupSummary[],
	after: readonly HeapClassGroupSummary[],
): HeapClassGroupDelta[] {
	const prev = new Map<string, HeapClassGroupSummary>();
	for (const g of before) {
		prev.set(g.name, g);
	}
	const names = new Set<string>([...prev.keys(), ...after.map(g => g.name)]);
	const deltas: HeapClassGroupDelta[] = [];
	for (const name of names) {
		const a = prev.get(name);
		const b = after.find(g => g.name === name);
		const countDelta = (b?.count ?? 0) - (a?.count ?? 0);
		const selfDelta = (b?.selfSize ?? 0) - (a?.selfSize ?? 0);
		const retainedDelta = (b?.retainedSize ?? 0) - (a?.retainedSize ?? 0);
		if (countDelta === 0 && selfDelta === 0 && retainedDelta === 0) {
			continue;
		}
		deltas.push({
			name,
			category: b?.category ?? a?.category ?? categorizeClassName(name),
			countDelta,
			selfDelta,
			retainedDelta,
		});
	}
	return rankByRetainedGrowth(deltas);
}

export function rankByRetainedGrowth(deltas: readonly HeapClassGroupDelta[]): HeapClassGroupDelta[] {
	return [...deltas].sort((a, b) => b.retainedDelta - a.retainedDelta || b.selfDelta - a.selfDelta);
}

/**
 * Fold a sampling heap profile into live-sampled bytes per extension id.
 * Same URL-prefix mapping as `extensionHostProfiler._distill`.
 */
export function attributeSamplingProfile(
	profile: AllocationSamplingProfile,
	extensionLocations: readonly ExtensionLocationRef[],
): Map<string, number> {
	const searchTree = TernarySearchTree.forUris<string>();
	for (const ext of extensionLocations) {
		if (ext.location.scheme === Schemas.file) {
			searchTree.set(URI.file(ext.location.fsPath), ext.id);
		} else {
			searchTree.set(ext.location, ext.id);
		}
	}

	const bytesByExt = new Map<string, number>();
	const visit = (node: AllocationSamplingProfileNode): void => {
		if (node.selfSize > 0 && node.callFrame?.url) {
			let extId: string | undefined;
			try {
				extId = searchTree.findSubstr(URI.parse(node.callFrame.url));
			} catch {
				// ignore unparseable urls
			}
			if (extId) {
				bytesByExt.set(extId, (bytesByExt.get(extId) ?? 0) + node.selfSize);
			}
		}
		for (const child of node.children ?? []) {
			visit(child);
		}
	};
	visit(profile.head);
	return bytesByExt;
}

/**
 * Lane-2 corroboration: weight retained bytes toward extensions whose install
 * path appears in retainer / closure name hints (best-effort; names only).
 */
export function attributeRetainerHints(
	hints: readonly { readonly haystack: string; readonly retainedBytes: number }[],
	extensionLocations: readonly ExtensionLocationRef[],
): Map<string, number> {
	const bytesByExt = new Map<string, number>();
	for (const hint of hints) {
		for (const ext of extensionLocations) {
			const needle = ext.location.scheme === Schemas.file ? ext.location.fsPath : ext.location.toString();
			if (needle && hint.haystack.includes(needle)) {
				bytesByExt.set(ext.id, (bytesByExt.get(ext.id) ?? 0) + hint.retainedBytes);
			}
		}
	}
	return bytesByExt;
}

export function mergeAttribution(
	lane1: ReadonlyMap<string, number>,
	lane2: ReadonlyMap<string, number>,
	grownRetainedBytes: number,
): ExtensionAttributionRow[] {
	const ids = new Set<string>([...lane1.keys(), ...lane2.keys()]);
	const lane1Total = sumValues(lane1);
	const lane2Total = sumValues(lane2);
	const rows: ExtensionAttributionRow[] = [];

	for (const id of ids) {
		const live = lane1.get(id) ?? 0;
		const lane2Bytes = lane2.get(id) ?? 0;
		const sharePct = lane1Total > 0
			? Math.round((live / lane1Total) * 100)
			: (lane2Total > 0 ? Math.round((lane2Bytes / lane2Total) * 100) : 0);
		const retainedBytes = lane1Total > 0
			? Math.round(grownRetainedBytes * (live / lane1Total))
			: lane2Bytes;
		const lane1Share = lane1Total > 0 ? live / lane1Total : 0;
		const lane2Share = lane2Total > 0 ? lane2Bytes / lane2Total : 0;
		const lanesAgree = lane2Total === 0 || lane1Total === 0 || Math.abs(lane1Share - lane2Share) <= 0.25;
		let confidence: HeapAttributionConfidence = 'low';
		if (lane1Share >= 0.6 && lanesAgree) {
			confidence = 'high';
		} else if (lane1Share >= 0.4 || (lane2Share >= 0.6 && lanesAgree)) {
			confidence = 'medium';
		}
		rows.push({
			extensionId: id,
			liveSampledBytes: live,
			retainedBytes,
			sharePct,
			confidence,
			lanesAgree,
		});
	}

	rows.sort((a, b) => b.liveSampledBytes - a.liveSampledBytes || b.retainedBytes - a.retainedBytes);
	return rows;
}

export function pickDominatorShape(
	deltas: readonly HeapClassGroupDelta[],
	after: readonly HeapClassGroupSummary[],
): DominatorShape {
	const grown = deltas.find(d => d.retainedDelta > 0 && !ROOTISH_CLASS_NAMES.has(d.name.toLowerCase()));
	const topAfter = after.find(g => !ROOTISH_CLASS_NAMES.has(g.name.toLowerCase()));
	const topDominatorName = grown?.name ?? topAfter?.name ?? 'other';
	const topDominatorRetainedBytes = grown?.retainedDelta ?? topAfter?.retainedSize ?? 0;
	const totalGrowth = deltas.reduce((s, d) => s + Math.max(0, d.retainedDelta), 0);
	const retainedTopSharePct = totalGrowth > 0
		? Math.round((Math.max(0, topDominatorRetainedBytes) / totalGrowth) * 100)
		: 0;
	return {
		topDominatorRetainedBytes: Math.max(0, topDominatorRetainedBytes),
		dominatorDepth: grown ? 2 : 1,
		dominatorFanout: Math.max(1, after.length),
		retainedTopSharePct,
		topDominatorName,
	};
}

/**
 * Total grown-and-not-freed retained bytes for attribution weighting.
 * Uses the single largest non-rootish class-group retained Δ (dominator-tree
 * class groups overlap; summing them double-counts).
 */
export function primaryGrownRetainedBytes(deltas: readonly HeapClassGroupDelta[]): number {
	let best = 0;
	for (const d of deltas) {
		if (d.retainedDelta > best && !ROOTISH_CLASS_NAMES.has(d.name.toLowerCase())) {
			best = d.retainedDelta;
		}
	}
	return best;
}

export function buildSafeSummary(args: {
	readonly attribution: readonly ExtensionAttributionRow[];
	readonly grown: readonly HeapClassGroupDelta[];
	readonly dominator: DominatorShape;
	readonly retainer?: RetainerPathShape;
	readonly affinity?: number;
	readonly pid?: number;
	readonly snapshotSeq?: number;
	/** Defaults stay inside the ≤24 numeric-leaf guard budget. */
	readonly topExtensions?: number;
	readonly topClassGroups?: number;
}): { readonly summary: ExtHostHeapAttributionSafeSummary; readonly reportMeta: HeapDiagnosisLocalReport } {
	// Cap defaults: 2 ext × 4 nums + 2 class × 3 nums + 4 header + 4 dominator + 1 retainer = 23.
	const topKExt = Math.min(args.topExtensions ?? 2, 2);
	const topKClass = Math.min(args.topClassGroups ?? 2, 2);
	const opaqueToExtensionId: Record<string, string> = {};
	const extensionIdToOpaque: Record<string, string> = {};

	const extensions: ExtHostHeapAttributionExtension[] = args.attribution.slice(0, topKExt).map((row, idx) => {
		const extRef = `ext-${idx + 1}`;
		opaqueToExtensionId[extRef] = row.extensionId;
		extensionIdToOpaque[row.extensionId] = extRef;
		return {
			extRef,
			liveSampledBucketMb: bucketRssMb(row.liveSampledBytes / (1024 * 1024)),
			retainedBucketMb: bucketRssMb(row.retainedBytes / (1024 * 1024)),
			sharePct: row.sharePct,
			rank: idx + 1,
			confidence: row.confidence,
			lanesAgree: row.lanesAgree,
		};
	});

	const interestingGrown = args.grown
		.filter(d => d.retainedDelta > 0 && !ROOTISH_CLASS_NAMES.has(d.name.toLowerCase()))
		.slice(0, Math.max(topKClass, 10)); // local report keeps more; summary slices below

	const grownClassGroups: ExtHostHeapAttributionClassGroup[] = interestingGrown.slice(0, topKClass).map((d, idx) => ({
		classRef: `class-${idx + 1}`,
		category: d.category,
		countDelta: d.countDelta,
		retainedDeltaBucketMb: bucketRssMb(d.retainedDelta / (1024 * 1024)),
		selfDeltaBucketMb: bucketRssMb(Math.max(0, d.selfDelta) / (1024 * 1024)),
	}));

	const retainer = args.retainer ?? { pathLen: 0, edgeTypes: [], nodeCategories: [] };

	const summary: ExtHostHeapAttributionSafeSummary = {
		schema: HEAP_DIAGNOSIS_SCHEMA,
		affinity: args.affinity ?? 0,
		pid: args.pid ?? 0,
		snapshotSeq: args.snapshotSeq ?? 0,
		extensions,
		grownClassGroups,
		topDominatorRetainedBucketMb: bucketRssMb(args.dominator.topDominatorRetainedBytes / (1024 * 1024)),
		dominatorDepth: args.dominator.dominatorDepth,
		dominatorFanout: args.dominator.dominatorFanout,
		retainedTopSharePct: args.dominator.retainedTopSharePct,
		retainerPathLen: retainer.pathLen,
	};

	const text = renderLocalReport({
		summary,
		attribution: args.attribution,
		grown: interestingGrown,
		dominator: args.dominator,
		opaqueToExtensionId,
	});

	return {
		summary,
		reportMeta: { text, opaqueToExtensionId, extensionIdToOpaque },
	};
}

export function renderLocalReport(args: {
	readonly summary: ExtHostHeapAttributionSafeSummary;
	readonly attribution: readonly ExtensionAttributionRow[];
	readonly grown: readonly HeapClassGroupDelta[];
	readonly dominator: DominatorShape;
	readonly opaqueToExtensionId: Readonly<Record<string, string>>;
}): string {
	const lines: string[] = [];
	lines.push(`HEAP DIAGNOSIS affinity ${args.summary.affinity} pid ${args.summary.pid} — schema ${args.summary.schema}`);
	lines.push('ATTRIBUTION (live sampled bytes, lane-1)');
	for (const ext of args.summary.extensions) {
		const real = args.opaqueToExtensionId[ext.extRef] ?? ext.extRef;
		lines.push(`  ${ext.rank}. ${real}  liveBucket=${ext.liveSampledBucketMb}MB retainedBucket=${ext.retainedBucketMb}MB (${ext.sharePct}%) confidence=${ext.confidence}`);
	}
	lines.push('GROWN & NOT FREED (retained Δ)');
	for (let i = 0; i < args.grown.length; i++) {
		const g = args.grown[i]!;
		lines.push(`  ${i + 1}. ${g.name}  ${g.countDelta >= 0 ? '+' : ''}${g.countDelta} objs  retainedΔ=${g.retainedDelta} category=${g.category}`);
	}
	lines.push(`TOP DOMINATOR  ${args.dominator.topDominatorName} retains ${args.dominator.topDominatorRetainedBytes} bytes (${args.dominator.retainedTopSharePct}% of growth)`);
	lines.push('NEXT: confirm via diagnostic isolation (u35), or fix directly; raw snapshots LOCAL ONLY');
	return lines.join('\n');
}

/**
 * Assert the safe summary contains no free-form strings outside closed enums /
 * opaque-id patterns (defense in depth before the telemetry guard).
 */
export function assertSafeSummaryShape(summary: ExtHostHeapAttributionSafeSummary): void {
	const opaqueExt = /^ext-\d+$/;
	const opaqueClass = /^class-\d+$/;
	const categories = new Set<string>(['array', 'string', 'object', 'closure', 'map-set', 'arraybuffer', 'regexp', 'promise', 'native', 'other']);
	const conf = new Set<string>(['high', 'medium', 'low']);

	for (const ext of summary.extensions) {
		if (!opaqueExt.test(ext.extRef)) {
			throw new Error(`non-opaque extRef: ${ext.extRef}`);
		}
		if (!conf.has(ext.confidence)) {
			throw new Error(`bad confidence: ${ext.confidence}`);
		}
	}
	for (const g of summary.grownClassGroups) {
		if (!opaqueClass.test(g.classRef)) {
			throw new Error(`non-opaque classRef: ${g.classRef}`);
		}
		if (!categories.has(g.category)) {
			throw new Error(`bad category: ${g.category}`);
		}
	}
}

function sumValues(m: ReadonlyMap<string, number>): number {
	let s = 0;
	for (const v of m.values()) {
		s += v;
	}
	return s;
}
