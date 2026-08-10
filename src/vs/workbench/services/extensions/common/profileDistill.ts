/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Pure V8 CPU-profile distillation by URL→category prefix (r15 Category B / P-B).
 *
 * Extracted from `electron-browser/extensionHostProfiler.ts` `_distill` so the
 * EH-side CPU monitor and the renderer auto-profiler share one walk. No I/O.
 *
 * Input categories are `[urlPrefix, categoryId][]` (typically extension
 * install-root URIs → real extension ids). Special V8 frames map to
 * `program` / `gc` / `self` exactly as upstream.
 */

import { TernarySearchTree } from '../../../../base/common/ternarySearchTree.js';
import { URI } from '../../../../base/common/uri.js';
import type { IV8Profile, IV8ProfileNode } from '../../../../platform/profiling/common/profiling.js';

/** Extension id or one of the known program states (mirrors ProfileSegmentId). */
export type DistillSegmentId = string | 'idle' | 'program' | 'gc' | 'self';

export interface DistilledProfileSegments {
	readonly startTime: number;
	readonly endTime: number;
	readonly deltas: number[];
	readonly ids: DistillSegmentId[];
	getAggregatedTimes(): Map<DistillSegmentId, number>;
}

/**
 * Walk a V8 CPU profile and attribute sample time to URL-prefix categories.
 *
 * @param profile V8 `.cpuprofile` shape (`nodes` + `samples` + `timeDeltas`)
 * @param categories `[urlPrefix, categoryId]` — longest matching prefix wins via TernarySearchTree
 */
export function distillProfileByUrlCategory(
	profile: IV8Profile,
	categories: ReadonlyArray<readonly [url: string, category: string]>,
): DistilledProfileSegments {
	const searchTree = TernarySearchTree.forUris<string>();
	for (const [url, category] of categories) {
		try {
			searchTree.set(toUri(url), category);
		} catch {
			// ignore malformed category URLs
		}
	}

	const nodes = profile.nodes;
	const idsToNodes = new Map<number, IV8ProfileNode>();
	const idsToSegmentId = new Map<number, DistillSegmentId | null>();
	for (const node of nodes) {
		idsToNodes.set(node.id, node);
	}

	function visit(node: IV8ProfileNode, segmentId: DistillSegmentId | null): void {
		if (!segmentId) {
			switch (node.callFrame.functionName) {
				case '(root)':
					break;
				case '(program)':
					segmentId = 'program';
					break;
				case '(garbage collector)':
					segmentId = 'gc';
					break;
				default:
					segmentId = 'self';
					break;
			}
		} else if (segmentId === 'self' && node.callFrame.url) {
			let category: string | undefined;
			try {
				category = searchTree.findSubstr(URI.parse(node.callFrame.url));
			} catch {
				// ignore
			}
			if (category) {
				segmentId = category;
			}
		}
		idsToSegmentId.set(node.id, segmentId);

		if (node.children) {
			for (const child of node.children) {
				const childNode = idsToNodes.get(child);
				if (childNode) {
					visit(childNode, segmentId);
				}
			}
		}
	}
	if (nodes.length > 0) {
		visit(nodes[0]!, null);
	}

	const samples = profile.samples || [];
	const timeDeltas = profile.timeDeltas || [];
	const distilledDeltas: number[] = [];
	const distilledIds: DistillSegmentId[] = [];

	let currSegmentTime = 0;
	let currSegmentId: string | undefined;
	for (let i = 0; i < samples.length; i++) {
		const id = samples[i]!;
		const segmentId = idsToSegmentId.get(id);
		if (segmentId !== currSegmentId) {
			if (currSegmentId) {
				distilledIds.push(currSegmentId);
				distilledDeltas.push(currSegmentTime);
			}
			currSegmentId = segmentId ?? undefined;
			currSegmentTime = 0;
		}
		currSegmentTime += timeDeltas[i] ?? 0;
	}
	if (currSegmentId) {
		distilledIds.push(currSegmentId);
		distilledDeltas.push(currSegmentTime);
	}

	return {
		startTime: profile.startTime,
		endTime: profile.endTime,
		deltas: distilledDeltas,
		ids: distilledIds,
		getAggregatedTimes: () => {
			const segmentsToTime = new Map<DistillSegmentId, number>();
			for (let i = 0; i < distilledIds.length; i++) {
				const sid = distilledIds[i]!;
				segmentsToTime.set(sid, (segmentsToTime.get(sid) || 0) + distilledDeltas[i]!);
			}
			return segmentsToTime;
		},
	};
}

/** Aggregate times; returns entries sorted by time descending. */
export function rankedSegmentTimes(
	aggregated: ReadonlyMap<DistillSegmentId, number>,
): Array<{ readonly segmentId: DistillSegmentId; readonly time: number; readonly sharePct: number }> {
	let total = 0;
	for (const t of aggregated.values()) {
		total += t;
	}
	const rows: Array<{ segmentId: DistillSegmentId; time: number; sharePct: number }> = [];
	for (const [segmentId, time] of aggregated) {
		rows.push({
			segmentId,
			time,
			sharePct: total > 0 ? (time / total) * 100 : 0,
		});
	}
	rows.sort((a, b) => b.time - a.time || a.segmentId.localeCompare(b.segmentId));
	return rows;
}

export function isSpecialDistillSegment(id: DistillSegmentId): boolean {
	return id === 'idle' || id === 'program' || id === 'gc' || id === 'self';
}

function toUri(url: string): URI {
	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
		return URI.parse(url);
	}
	return URI.file(url);
}
