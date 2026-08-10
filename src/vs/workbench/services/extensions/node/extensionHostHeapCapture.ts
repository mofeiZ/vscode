/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * In-EH heap capture helpers (u37 / r11).
 *
 * Raw `.heapsnapshot` / `.heapprofile` artifacts are LOCAL / employee-internal
 * only — never telemetered. Analysis lives in `extensionHostHeapDiagnosis.ts`.
 */

import type { Session } from 'node:inspector';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import * as v8 from 'node:v8';
import {
	categorizeClassName,
	type AllocationSamplingProfile,
	type HeapClassGroupSummary,
} from '../common/extensionHostHeapDiagnosis.js';

const DEFAULT_SAMPLING_INTERVAL_BYTES = 131_072;

/** Lazy `@vscode/v8-heap-parser` surface (WASM; node build). */
export interface V8HeapParserGraph {
	get_class_groups(start: number, end: number, no_retained: boolean): Array<{
		name(): string;
		children_len: number;
		retained_size: bigint;
		self_size: bigint;
	}>;
	get_all_retainers(index: number, maxDistance: number): Array<{
		name(): string;
		edge_typ: number;
		typ: number;
		retained_size: bigint;
		index: number;
	}>;
	class_children(index: number, start: number, end: number, sort_by: number): Array<{
		name(): string;
		typ: number;
		retained_size: bigint;
		self_size: bigint;
		index: number;
	}>;
	root_index: number;
}

interface V8HeapParserModule {
	decode_bytes(input: Uint8Array): V8HeapParserGraph;
	WasmSortBy: { SelfSize: number; RetainedSize: number; Name: number };
	NodeType: Record<string, number>;
	EdgeType: Record<string, number>;
}

let parserModule: V8HeapParserModule | undefined;
let samplingSession: Session | undefined;
let samplingActive = false;

function loadParser(): V8HeapParserModule {
	if (!parserModule) {
		const require = createRequire(import.meta.url);
		parserModule = require('@vscode/v8-heap-parser') as V8HeapParserModule;
	}
	return parserModule;
}

/** Write a heap snapshot to `path` via `v8.writeHeapSnapshot`. Returns the path. */
export function writeSnapshot(path: string): string {
	return v8.writeHeapSnapshot(path);
}

/**
 * Start in-process allocation sampling (`HeapProfiler.startSampling`).
 * Default interval 128 KiB (r11).
 */
export async function startAllocationSampling(intervalBytes: number = DEFAULT_SAMPLING_INTERVAL_BYTES): Promise<void> {
	if (samplingActive) {
		return;
	}
	const { Session } = await import('node:inspector');
	samplingSession = new Session();
	samplingSession.connect();
	await post(samplingSession, 'HeapProfiler.enable');
	await post(samplingSession, 'HeapProfiler.startSampling', { samplingInterval: intervalBytes });
	samplingActive = true;
}

/** Stop sampling and return the CDP sampling profile. */
export async function stopAndGetProfile(): Promise<AllocationSamplingProfile> {
	if (!samplingSession || !samplingActive) {
		throw new Error('allocation sampling is not active');
	}
	const result = await post(samplingSession, 'HeapProfiler.stopSampling') as { profile: AllocationSamplingProfile };
	try {
		await post(samplingSession, 'HeapProfiler.disable');
	} catch {
		// best-effort
	}
	try {
		samplingSession.disconnect();
	} catch {
		// best-effort
	}
	samplingSession = undefined;
	samplingActive = false;
	return result.profile;
}

/** Decode a `.heapsnapshot` file into a parser Graph. */
export async function decodeSnapshotFile(path: string): Promise<V8HeapParserGraph> {
	const parser = loadParser();
	const buf = await readFile(path);
	return parser.decode_bytes(buf);
}

/** Extract plain class-group summaries (retained-size ordered). */
export function extractClassGroups(graph: V8HeapParserGraph, limit: number = 40): HeapClassGroupSummary[] {
	const groups = graph.get_class_groups(0, limit, false);
	return groups.map(g => ({
		name: g.name(),
		category: categorizeClassName(g.name()),
		count: g.children_len,
		selfSize: Number(g.self_size),
		retainedSize: Number(g.retained_size),
	}));
}

/**
 * Programmatic near-heap-limit snapshot hook (`v8.setHeapSnapshotNearHeapLimit`).
 * Wiring into EH `execArgv` is deferred to u38; this helper is for local/tests.
 */
export function installNearHeapLimitCapture(limit: number = 1): void {
	if (typeof v8.setHeapSnapshotNearHeapLimit === 'function') {
		v8.setHeapSnapshotNearHeapLimit(limit);
	}
}

function post(session: Session, method: string, params?: Record<string, unknown>): Promise<unknown> {
	return new Promise((resolve, reject) => {
		session.post(method, params ?? {}, (err, result) => {
			if (err) {
				reject(err);
				return;
			}
			resolve(result);
		});
	});
}
