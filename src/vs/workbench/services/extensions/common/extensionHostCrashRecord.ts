/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { VSBuffer } from '../../../../base/common/buffer.js';
import { joinPath } from '../../../../base/common/resources.js';
import { URI } from '../../../../base/common/uri.js';
import { ExtensionHostExitCode } from './extensionHostProtocol.js';

/**
 * Durable, numbers-only crash records for local extension hosts.
 * Written under `<userDataPath>/pending-errors/` (session-stable) so a
 * next-start flush can recover records the dying window never sent.
 */

export const PENDING_ERRORS_DIRNAME = 'pending-errors';
export const MAX_PENDING_ERROR_RECORDS = 20;
/** RSS bucket (MB) at/above which a signal-exit is treated as a weak OOM signal. */
export const HIGH_RSS_BUCKET_MB = 3072;
export const EXTENSION_HOST_CRASH_RECORD_SCHEMA = 1;

const STDERR_OOM_RE = /Reached heap limit|JavaScript heap out of memory|FATAL ERROR/i;

export type ExtensionHostExitClass =
	| 'clean'
	| 'versionMismatch'
	| 'unexpectedError'
	| 'oom'
	| 'crash'
	| 'killed'
	| 'unknown';

export interface ExtensionHostExitClassificationInput {
	readonly code: number;
	readonly reason: string | undefined;
	readonly stderrOomSeen: boolean;
	readonly lastRssBucketMb: number | null | undefined;
	readonly highRssBucketMb?: number;
}

export interface ExtensionHostExitClassification {
	readonly exitClass: ExtensionHostExitClass;
	readonly oomSuspected: boolean;
	/** True when only the weak exit-code+RSS heuristic contributed (not Electron/stderr). */
	readonly oomHeuristic: boolean;
	readonly electronOom: boolean;
	readonly stderrOom: boolean;
}

export interface ExtensionHostCrashRecord {
	readonly schema: typeof EXTENSION_HOST_CRASH_RECORD_SCHEMA;
	readonly ts: number;
	readonly code: number;
	readonly signal: string;
	readonly reason: string;
	readonly exitClass: ExtensionHostExitClass;
	readonly oomSuspected: boolean;
	readonly oomHeuristic: boolean;
	readonly affinity: number;
	readonly pid: number;
	readonly uptimeSec: number;
	readonly lastRssBucketMb: number | null;
	readonly lastHeapUsedMb: number | null;
	readonly secondsSinceLastSample: number | null;
	readonly secondsSinceLastAlert: number | null;
	readonly activatedExtensionCount: number;
	readonly extensionIds: string[];
	/** Set after a same-session `exthostCrashRecord` emission succeeds. */
	sentInSession?: boolean;
}

export interface ExtensionHostExitContext {
	readonly code: number;
	readonly signal: string;
	readonly reason: string;
	readonly stderrOomSeen: boolean;
	readonly affinity: number;
	readonly pid: number;
	readonly uptimeSec: number;
	readonly lastRssBucketMb: number | null;
	readonly lastHeapUsedMb: number | null;
	readonly secondsSinceLastSample: number | null;
	readonly secondsSinceLastAlert: number | null;
	readonly exitClass: ExtensionHostExitClass;
	readonly oomSuspected: boolean;
	readonly oomHeuristic: boolean;
}

/** Minimal file surface so flush/write can be unit-tested with InMemoryFileSystemProvider. */
export interface PendingErrorsFileService {
	exists(resource: URI): Promise<boolean>;
	createFolder(resource: URI): Promise<unknown>;
	resolve(resource: URI): Promise<{ children?: readonly { resource: URI; name: string; isDirectory?: boolean }[] }>;
	readFile(resource: URI): Promise<{ value: { toString(): string } }>;
	writeFile(resource: URI, buffer: VSBuffer): Promise<unknown>;
	del(resource: URI): Promise<void>;
}

const exitContextsByPid = new Map<number, ExtensionHostExitContext>();

export function stderrLooksLikeOom(line: string): boolean {
	return STDERR_OOM_RE.test(line);
}

export function classifyExtensionHostExit(input: ExtensionHostExitClassificationInput): ExtensionHostExitClassification {
	const highBucket = input.highRssBucketMb ?? HIGH_RSS_BUCKET_MB;
	const reason = input.reason ?? 'unknown';
	const electronOom = reason === 'oom' || reason === 'memory-eviction';
	const stderrOom = !!input.stderrOomSeen;
	const rss = input.lastRssBucketMb;
	const oomHeuristic = input.code > 128 && typeof rss === 'number' && rss >= highBucket;
	const oomSuspected = electronOom || stderrOom || oomHeuristic;

	let exitClass: ExtensionHostExitClass;
	if (input.code === ExtensionHostExitCode.VersionMismatch) {
		exitClass = 'versionMismatch';
	} else if (oomSuspected) {
		exitClass = 'oom';
	} else if (input.code === ExtensionHostExitCode.UnexpectedError) {
		exitClass = 'unexpectedError';
	} else if (reason === 'killed') {
		exitClass = 'killed';
	} else if (reason === 'crashed' || reason === 'abnormal-exit' || reason === 'launch-failed' || reason === 'integrity-failure') {
		exitClass = 'crash';
	} else if (reason === 'clean-exit' || input.code === 0) {
		exitClass = 'clean';
	} else {
		exitClass = 'unknown';
	}

	return { exitClass, oomSuspected, oomHeuristic, electronOom, stderrOom };
}

export function buildExtensionHostCrashRecord(args: {
	readonly ts: number;
	readonly code: number;
	readonly signal: string;
	readonly reason: string;
	readonly classification: ExtensionHostExitClassification;
	readonly affinity: number;
	readonly pid: number;
	readonly uptimeSec: number;
	readonly lastRssBucketMb: number | null;
	readonly lastHeapUsedMb: number | null;
	readonly secondsSinceLastSample: number | null;
	readonly secondsSinceLastAlert: number | null;
	readonly extensionIds: readonly string[];
}): ExtensionHostCrashRecord {
	return {
		schema: EXTENSION_HOST_CRASH_RECORD_SCHEMA,
		ts: args.ts,
		code: args.code,
		signal: args.signal,
		reason: args.reason,
		exitClass: args.classification.exitClass,
		oomSuspected: args.classification.oomSuspected,
		oomHeuristic: args.classification.oomHeuristic,
		affinity: args.affinity,
		pid: args.pid,
		uptimeSec: args.uptimeSec,
		lastRssBucketMb: args.lastRssBucketMb,
		lastHeapUsedMb: args.lastHeapUsedMb,
		secondsSinceLastSample: args.secondsSinceLastSample,
		secondsSinceLastAlert: args.secondsSinceLastAlert,
		activatedExtensionCount: args.extensionIds.length,
		extensionIds: args.extensionIds.slice(),
	};
}

/** Telemetry payload: numbers / enums / opaque marketplace ids only (no paths). */
export function crashRecordTelemetryData(record: ExtensionHostCrashRecord, extra?: { flushDelaySec?: number }): Record<string, unknown> {
	const data: Record<string, unknown> = {
		schema: record.schema,
		ts: record.ts,
		code: record.code,
		signal: record.signal,
		reason: record.reason,
		exitClass: record.exitClass,
		oomSuspected: record.oomSuspected,
		oomHeuristic: record.oomHeuristic,
		affinity: record.affinity,
		pid: record.pid,
		uptimeSec: record.uptimeSec,
		lastRssBucketMb: record.lastRssBucketMb,
		lastHeapUsedMb: record.lastHeapUsedMb,
		secondsSinceLastSample: record.secondsSinceLastSample,
		secondsSinceLastAlert: record.secondsSinceLastAlert,
		activatedExtensionCount: record.activatedExtensionCount,
		extensionIds: record.extensionIds.slice(),
	};
	if (typeof extra?.flushDelaySec === 'number') {
		data.flushDelaySec = extra.flushDelaySec;
	}
	return data;
}

export function crashRecordFileName(ts: number, affinity: number, pid: number): string {
	const iso = new Date(ts).toISOString().replace(/[:.]/g, '-');
	return `${iso}-eh${affinity}-${pid}.json`;
}

export function pendingErrorsDir(userDataHome: URI): URI {
	return joinPath(userDataHome, PENDING_ERRORS_DIRNAME);
}

export function publishExtensionHostExitContext(ctx: ExtensionHostExitContext): void {
	exitContextsByPid.set(ctx.pid, ctx);
}

export function consumeExtensionHostExitContext(pid: number | null): ExtensionHostExitContext | undefined {
	if (pid === null) {
		return undefined;
	}
	const ctx = exitContextsByPid.get(pid);
	if (ctx) {
		exitContextsByPid.delete(pid);
	}
	return ctx;
}

/** Test helper — clears the pid→context map. */
export function clearExtensionHostExitContextsForTests(): void {
	exitContextsByPid.clear();
}

export function formatUnexpectedExitBreadcrumb(args: {
	readonly code: number;
	readonly signal: string;
	readonly pid: number | null;
	readonly reason: string;
	readonly exitClass: ExtensionHostExitClass;
	readonly oomSuspected: boolean;
	readonly lastRssBucketMb: number | null;
}): string {
	const rss = args.lastRssBucketMb === null ? 'null' : String(args.lastRssBucketMb);
	return `Extension host exited unexpectedly: code=${args.code} signal=${args.signal} pid=${args.pid} reason=${args.reason} exitClass=${args.exitClass} oomSuspected=${args.oomSuspected} lastRssBucketMb=${rss}`;
}

async function ensurePendingDir(fileService: PendingErrorsFileService, dir: URI): Promise<void> {
	if (!(await fileService.exists(dir))) {
		await fileService.createFolder(dir);
	}
}

async function listPendingRecordFiles(fileService: PendingErrorsFileService, dir: URI): Promise<URI[]> {
	if (!(await fileService.exists(dir))) {
		return [];
	}
	const stat = await fileService.resolve(dir);
	const children = stat.children ?? [];
	return children
		.filter(c => !c.isDirectory && c.name.endsWith('.json'))
		.map(c => c.resource)
		.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

async function capPendingRecords(fileService: PendingErrorsFileService, dir: URI): Promise<void> {
	const files = await listPendingRecordFiles(fileService, dir);
	const overflow = files.length - MAX_PENDING_ERROR_RECORDS;
	if (overflow <= 0) {
		return;
	}
	for (let i = 0; i < overflow; i++) {
		await fileService.del(files[i]!);
	}
}

export async function writePendingExtensionHostCrashRecord(
	fileService: PendingErrorsFileService,
	userDataHome: URI,
	record: ExtensionHostCrashRecord,
): Promise<URI> {
	const dir = pendingErrorsDir(userDataHome);
	await ensurePendingDir(fileService, dir);
	const resource = joinPath(dir, crashRecordFileName(record.ts, record.affinity, record.pid));
	await fileService.writeFile(resource, VSBuffer.fromString(JSON.stringify(record)));
	await capPendingRecords(fileService, dir);
	return resource;
}

export async function markPendingCrashRecordSentInSession(
	fileService: PendingErrorsFileService,
	resource: URI,
	record: ExtensionHostCrashRecord,
): Promise<void> {
	const marked: ExtensionHostCrashRecord = { ...record, sentInSession: true };
	await fileService.writeFile(resource, VSBuffer.fromString(JSON.stringify(marked)));
}

export interface FlushPendingCrashRecordsResult {
	readonly flushed: number;
	readonly deletedAlreadySent: number;
	readonly records: ExtensionHostCrashRecord[];
}

/**
 * On next start: emit flush telemetry for unsent records, drop already-sent
 * same-session leftovers, delete every file processed.
 */
export async function flushPendingExtensionHostCrashRecords(
	fileService: PendingErrorsFileService,
	userDataHome: URI,
	nowMs: number,
	emitFlush: (record: ExtensionHostCrashRecord, flushDelaySec: number) => void,
): Promise<FlushPendingCrashRecordsResult> {
	const dir = pendingErrorsDir(userDataHome);
	const files = await listPendingRecordFiles(fileService, dir);
	let flushed = 0;
	let deletedAlreadySent = 0;
	const records: ExtensionHostCrashRecord[] = [];

	for (const resource of files) {
		let record: ExtensionHostCrashRecord | undefined;
		try {
			const raw = (await fileService.readFile(resource)).value.toString();
			record = JSON.parse(raw) as ExtensionHostCrashRecord;
		} catch {
			await fileService.del(resource);
			continue;
		}

		if (record.sentInSession) {
			deletedAlreadySent++;
			await fileService.del(resource);
			continue;
		}

		const flushDelaySec = Math.max(0, Math.round((nowMs - (record.ts || nowMs)) / 1000));
		emitFlush(record, flushDelaySec);
		records.push(record);
		flushed++;
		await fileService.del(resource);
	}

	return { flushed, deletedAlreadySent, records };
}
