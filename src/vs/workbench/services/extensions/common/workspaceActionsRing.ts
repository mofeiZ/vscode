/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * R4b / r17 Lane A — workspace-and-actions flight recorder (thin consumer).
 *
 * Keeps a bounded in-memory action ring via the u45 {@link FlightRecorderRing}
 * foundation. Records silently (no `publicLog`). Flushes the recent ring plus a
 * workspace-shape snapshot onto an existing diagnostic (crash / OOM / memory
 * alert) only. Per-session opaque file ids from {@link SessionFileIdMap}.
 *
 * Continuous per-action streaming is intentionally not wired (r17 §4.1 NO-GO).
 */

import {
	DEFAULT_FLIGHT_RECORDER_CAP,
	FlightRecorderRing,
} from '../../../../platform/telemetry/common/flightRecorder.js';
import {
	SessionFileIdMap,
	mintSessionId,
	mintWorkspaceId,
	type OpaqueId,
} from '../../../../platform/telemetry/common/opaqueIds.js';

/** Closed action kinds — never freeform command ids. */
export type WorkspaceActionKind = 'open' | 'close' | 'switch' | 'edit' | 'save';

/** Closed language histogram keys. Unknown → `other`. Never raw languageId strings. */
export type LanguageBucket =
	| 'typescript'
	| 'javascript'
	| 'python'
	| 'json'
	| 'markdown'
	| 'plaintext'
	| 'cpp'
	| 'go'
	| 'rust'
	| 'java'
	| 'csharp'
	| 'other';

/** Power-of-two-ish count buckets; telemetry stores the floor edge. */
export type CountBucket = 0 | 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024;

/** Workspace size buckets (MB). */
export type SizeBucketMb = 0 | 1 | 4 | 16 | 64 | 256 | 1024 | 4096 | 16384;

export const WORKSPACE_ACTIONS_RING_CAP = DEFAULT_FLIGHT_RECORDER_CAP;

/** Seconds-since-start floors admitted into `tSinceStartBucket` / `a*_t`. */
export const T_SINCE_START_BUCKETS = [0, 5, 15, 30, 60, 120, 300, 600, 1800, 3600] as const;

const COUNT_BUCKETS: readonly CountBucket[] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
const SIZE_BUCKETS_MB: readonly SizeBucketMb[] = [0, 1, 4, 16, 64, 256, 1024, 4096, 16384];

const LANGUAGE_BUCKETS: readonly LanguageBucket[] = [
	'typescript', 'javascript', 'python', 'json', 'markdown', 'plaintext',
	'cpp', 'go', 'rust', 'java', 'csharp', 'other',
];

const ACTION_KINDS = new Set<string>(['open', 'close', 'switch', 'edit', 'save']);

export interface WorkspaceShapeInput {
	readonly folderCount: number;
	readonly openEditorCount: number;
	/** Known/indexed file count if cheap; else 0. */
	readonly fileCount: number;
	/** Approx workspace size in MB if cheap; else 0. */
	readonly totalSizeMb: number;
	/** Counts keyed by closed {@link LanguageBucket}; missing → 0. */
	readonly languageCounts?: Partial<Record<LanguageBucket, number>>;
}

export interface WorkspaceActionsRecorderOptions {
	readonly salt: Uint8Array | string;
	readonly workspaceRoots: readonly string[];
	/** Cap for the underlying flight-recorder ring (default {@link WORKSPACE_ACTIONS_RING_CAP}). */
	readonly cap?: number;
	/** Session start wall clock (ms); defaults to construction time. */
	readonly sessionStartMs?: number;
	/** Optional injected file-id map (share with archive export within the session). */
	readonly fileIds?: SessionFileIdMap;
}

/**
 * Foundation `mintSessionId` / `mintWorkspaceId` emit `sess-` / `ws-` + hex.
 * Under `strictShape`, hyphenated tokens false-trigger base64 expansion and
 * fail the allowlist. Dot separators stay opaque and guard-safe.
 */
function toStrictShapeOpaqueId<P extends 'sess' | 'ws'>(minted: `${P}-${string}`, prefix: P): `${P}.${string}` {
	return minted.replace(`${prefix}-`, `${prefix}.`) as `${P}.${string}`;
}

/**
 * Floor `n` onto the greatest bucket edge ≤ n (clamped to the table).
 */
export function toCountBucket(n: number): CountBucket {
	const v = Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
	let best: CountBucket = 0;
	for (const edge of COUNT_BUCKETS) {
		if (v >= edge) {
			best = edge;
		} else {
			break;
		}
	}
	return best;
}

export function toSizeBucketMb(mb: number): SizeBucketMb {
	const v = Number.isFinite(mb) && mb > 0 ? Math.floor(mb) : 0;
	let best: SizeBucketMb = 0;
	for (const edge of SIZE_BUCKETS_MB) {
		if (v >= edge) {
			best = edge;
		} else {
			break;
		}
	}
	return best;
}

/** Floor seconds-since-start onto the r17 time bucket table. */
export function toTSinceStartBucket(secondsSinceStart: number): number {
	const v = Number.isFinite(secondsSinceStart) && secondsSinceStart > 0
		? Math.floor(secondsSinceStart)
		: 0;
	let best = 0;
	for (const edge of T_SINCE_START_BUCKETS) {
		if (v >= edge) {
			best = edge;
		} else {
			break;
		}
	}
	return best;
}

/** Map a raw languageId onto the closed histogram key. */
export function toLanguageBucket(languageId: string | undefined): LanguageBucket {
	if (!languageId) {
		return 'other';
	}
	const id = languageId.toLowerCase();
	switch (id) {
		case 'typescript':
		case 'typescriptreact':
			return 'typescript';
		case 'javascript':
		case 'javascriptreact':
			return 'javascript';
		case 'python':
			return 'python';
		case 'json':
		case 'jsonc':
			return 'json';
		case 'markdown':
			return 'markdown';
		case 'plaintext':
			return 'plaintext';
		case 'cpp':
		case 'c':
			return 'cpp';
		case 'go':
			return 'go';
		case 'rust':
			return 'rust';
		case 'java':
			return 'java';
		case 'csharp':
			return 'csharp';
		default:
			return 'other';
	}
}

function emptyLanguageCounts(): Record<LanguageBucket, number> {
	const out = Object.create(null) as Record<LanguageBucket, number>;
	for (const k of LANGUAGE_BUCKETS) {
		out[k] = 0;
	}
	return out;
}

/**
 * Session-scoped actions ring + workspace-shape snapshot.
 * Push is silent — never emits telemetry.
 */
export class WorkspaceActionsRecorder {
	private readonly _ring: FlightRecorderRing;
	private readonly _fileIds: SessionFileIdMap;
	private readonly _opaqueSessionId: `sess.${string}`;
	private _opaqueWorkspaceId: `ws.${string}`;
	private readonly _sessionStartMs: number;
	private _shape: WorkspaceShapeInput;

	constructor(options: WorkspaceActionsRecorderOptions) {
		this._ring = new FlightRecorderRing(options.cap ?? WORKSPACE_ACTIONS_RING_CAP);
		this._fileIds = options.fileIds ?? new SessionFileIdMap();
		this._opaqueSessionId = toStrictShapeOpaqueId(mintSessionId(options.salt), 'sess');
		this._opaqueWorkspaceId = toStrictShapeOpaqueId(mintWorkspaceId(options.salt, options.workspaceRoots), 'ws');
		this._sessionStartMs = options.sessionStartMs ?? Date.now();
		this._shape = {
			folderCount: 0,
			openEditorCount: 0,
			fileCount: 0,
			totalSizeMb: 0,
			languageCounts: emptyLanguageCounts(),
		};
	}

	get cap(): number {
		return this._ring.cap;
	}

	get length(): number {
		return this._ring.length;
	}

	get opaqueSessionId(): `sess.${string}` {
		return this._opaqueSessionId;
	}

	get opaqueWorkspaceId(): `ws.${string}` {
		return this._opaqueWorkspaceId;
	}

	get fileIds(): SessionFileIdMap {
		return this._fileIds;
	}

	/** Underlying foundation ring (tests / advanced attach). */
	get ring(): FlightRecorderRing {
		return this._ring;
	}

	/**
	 * Record an editor action. Mints a per-session opaque file id; paths never
	 * leave this method. Does **not** call telemetry.
	 */
	recordAction(actionKind: WorkspaceActionKind, filePath: string, nowMs: number = Date.now()): OpaqueId {
		if (!ACTION_KINDS.has(actionKind)) {
			throw new Error(`WorkspaceActionsRecorder: unknown actionKind ${actionKind}`);
		}
		const opaqueFileId = this._fileIds.opaqueId(filePath);
		const tBucket = toTSinceStartBucket((nowMs - this._sessionStartMs) / 1000);
		this._ring.record({
			kind: actionKind,
			opaqueId: opaqueFileId,
			tBucket,
		});
		return opaqueFileId;
	}

	/** Replace the workspace-shape snapshot (buckets computed at flush time). */
	updateWorkspaceShape(shape: WorkspaceShapeInput): void {
		const languageCounts = emptyLanguageCounts();
		if (shape.languageCounts) {
			for (const k of LANGUAGE_BUCKETS) {
				const n = shape.languageCounts[k];
				if (typeof n === 'number' && Number.isFinite(n) && n > 0) {
					languageCounts[k] = Math.floor(n);
				}
			}
		}
		this._shape = {
			folderCount: shape.folderCount,
			openEditorCount: shape.openEditorCount,
			fileCount: shape.fileCount,
			totalSizeMb: shape.totalSizeMb,
			languageCounts,
		};
	}

	/** Recompute workspace id when roots change (same session salt). */
	setWorkspaceRoots(salt: Uint8Array | string, roots: readonly string[]): void {
		this._opaqueWorkspaceId = toStrictShapeOpaqueId(mintWorkspaceId(salt, roots), 'ws');
	}

	clear(): void {
		this._ring.clear();
	}

	/**
	 * Attach recent ring + workspace shape onto a diagnostic payload as flat
	 * guard-safe leaves (r17 `WorkspaceActionsContext`). Uses
	 * {@link FlightRecorderRing.flushInto} then renames `a*_id` → `a*_file`
	 * and writes `actionRingLen` / `actionRingCap` meta.
	 *
	 * Mutates and returns `diagnostic`. Never emits telemetry itself.
	 */
	flushInto(diagnostic: Record<string, unknown>): Record<string, unknown> {
		diagnostic.opaqueSessionId = this._opaqueSessionId;
		diagnostic.opaqueWorkspaceId = this._opaqueWorkspaceId;
		diagnostic.folderCountBucket = toCountBucket(this._shape.folderCount);
		diagnostic.openEditorCountBucket = toCountBucket(this._shape.openEditorCount);
		diagnostic.fileCountBucket = toCountBucket(this._shape.fileCount);
		diagnostic.totalSizeBucketMb = toSizeBucketMb(this._shape.totalSizeMb);

		// Omit zero counts so leaf budget stays under strictShape code-unit caps
		// (r17: missing keys = 0). Non-zero closed-enum keys only.
		const langs = this._shape.languageCounts ?? emptyLanguageCounts();
		for (const k of LANGUAGE_BUCKETS) {
			const n = langs[k] ?? 0;
			if (n > 0) {
				diagnostic[`lang_${k}`] = n;
			}
		}

		// Foundation flatten (`a0_kind` / `a0_id` / `a0_t`); r17 schema uses `a*_file`.
		this._ring.flushInto(diagnostic, { prefix: 'a', includeMeta: false });
		const len = this._ring.length;
		diagnostic.actionRingLen = len;
		diagnostic.actionRingCap = this._ring.cap;
		for (let i = 0; i < len; i++) {
			const idKey = `a${i}_id`;
			if (Object.prototype.hasOwnProperty.call(diagnostic, idKey)) {
				diagnostic[`a${i}_file`] = diagnostic[idKey];
				delete diagnostic[idKey];
			}
		}
		return diagnostic;
	}

	/**
	 * Flat `workspaceActionsContext` leaves only (no crash/alert carrier fields).
	 * Intended for strictShape checks and optional sibling emit; correlated via
	 * `opaqueSessionId` / `opaqueWorkspaceId`.
	 */
	buildContextPayload(): Record<string, unknown> {
		return this.flushInto({});
	}
}

/** Optional process-wide recorder so crash / memory-alert carriers can attach. */
let activeWorkspaceActionsRecorder: WorkspaceActionsRecorder | undefined;

export function setActiveWorkspaceActionsRecorder(recorder: WorkspaceActionsRecorder | undefined): void {
	activeWorkspaceActionsRecorder = recorder;
}

export function getActiveWorkspaceActionsRecorder(): WorkspaceActionsRecorder | undefined {
	return activeWorkspaceActionsRecorder;
}

/**
 * If an active workspace-actions recorder is registered, flatten ring + shape
 * into `diagnostic`. No-op when none is set.
 */
export function flushActiveWorkspaceActionsInto(
	diagnostic: Record<string, unknown>,
): Record<string, unknown> {
	const recorder = activeWorkspaceActionsRecorder;
	if (!recorder) {
		return diagnostic;
	}
	return recorder.flushInto(diagnostic);
}
