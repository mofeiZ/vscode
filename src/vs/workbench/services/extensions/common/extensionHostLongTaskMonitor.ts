/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Extension-host long-task monitor (r15 Category A / P-A) — pure, headless-testable.
 *
 * Thin consumer of the u45 perf foundation: {@link SessionEntityIdMap} for opaque
 * extension ids, {@link FlightRecorderRing} for alert breadcrumbs, and
 * {@link tryGuardSafeEmit} / {@link checkGuardSafePayload} for Path-A emit.
 *
 * Measures the *sync slice* that blocks the single EH event loop (not await-inclusive
 * wall time). Dispatch sites push a `{kind, opaqueExtId}` scope; the RPC catch-all
 * consults the current scope for attribution.
 */

import { getActiveFlightRecorder } from '../../../../platform/telemetry/common/flightRecorder.js';
import {
	tryGuardSafeEmit,
	type GuardSafeEmitResult,
	type GuardSafeTelemetrySink,
} from '../../../../platform/telemetry/common/guardSafeEmit.js';
import {
	SessionEntityIdMap,
	type OpaqueId,
} from '../../../../platform/telemetry/common/opaqueIds.js';

/** Record sync slices at/above this floor (renderer longtask convention). */
export const LONG_TASK_SYNC_FLOOR_MS = 50;

/** Alert when one extension accrues this many ≥500 ms sync tasks in a window. */
export const LONG_TASK_ALERT_COUNT_AT_500 = 5;
export const LONG_TASK_ALERT_SYNC_MS = 500;

/** Alert on any single sync slice at/above the RPC watchdog bar. */
export const LONG_TASK_ALERT_ANY_MS = 3000;

/** Aggregation / emit window (matches u30 sample cadence × MEMORY_SAMPLE_TELEMETRY_EVERY_N). */
export const LONG_TASK_WINDOW_SEC = 300;

/** Max `exthostLongTask` events emitted per window. */
export const LONG_TASK_TOP_K = 5;

/** Closed ms bucket edges (telemetry reports the highest edge ≤ duration; 3000 for 3000+). */
export const LONG_TASK_MS_BUCKET_EDGES: readonly number[] = [50, 100, 250, 500, 1000, 3000];

/** ELD p99 alert threshold (ms) sustained across consecutive windows. */
export const ELD_ALERT_P99_MS = 100;
export const ELD_ALERT_CONSECUTIVE_WINDOWS = 2;

/** Sentinel opaque id for unattributed RPC / unknown scope (guard-safe closed token). */
export const LONG_TASK_UNATTRIBUTED_OPAQUE: OpaqueId = 'ext-0';

export type LongTaskKind = 'command' | 'provider' | 'event' | 'rpc' | 'activation';

export interface LongTaskScope {
	readonly kind: LongTaskKind;
	/** Opaque `ext-N` or {@link LONG_TASK_UNATTRIBUTED_OPAQUE}; never a real extension id. */
	readonly opaqueExtId: OpaqueId;
}

export interface LongTaskSlice {
	readonly kind: LongTaskKind;
	readonly opaqueExtId: OpaqueId;
	readonly syncMs: number;
	readonly wallMs: number;
}

export interface ExtHostLongTaskTelemetryPayload {
	readonly kind: LongTaskKind;
	readonly opaqueExtId: string;
	readonly syncMsBucket: number;
	readonly wallMsBucket: number;
	readonly count: number;
	readonly windowSec: number;
}

export interface ExtHostEventLoopLagTelemetryPayload {
	readonly p50Bucket: number;
	readonly p99Bucket: number;
	readonly maxBucket: number;
	readonly windowSec: number;
}

export interface EventLoopLagSnapshot {
	readonly p50Ms: number;
	readonly p99Ms: number;
	readonly maxMs: number;
}

export interface LongTaskAlertDecision {
	readonly fire: boolean;
	readonly reason?: 'count500' | 'any3000';
	readonly opaqueExtId?: OpaqueId;
	readonly kind?: LongTaskKind;
	readonly countAt500?: number;
}

interface ExtWindowAgg {
	opaqueExtId: OpaqueId;
	kindCounts: Map<LongTaskKind, number>;
	maxSyncMs: number;
	maxWallMs: number;
	count: number;
	countAt500: number;
	has3000: boolean;
	/** Dominant (kind, syncBucket, wallBucket) by count for the single-event emit. */
	bucketKeyCounts: Map<string, { kind: LongTaskKind; syncMsBucket: number; wallMsBucket: number; count: number }>;
}

export interface LongTaskWindowFlush {
	readonly longTasks: readonly ExtHostLongTaskTelemetryPayload[];
	readonly eventLoopLag?: ExtHostEventLoopLagTelemetryPayload;
	readonly alerts: readonly LongTaskAlertDecision[];
	readonly eldAlert: boolean;
}

function nowMs(): number {
	return typeof performance !== 'undefined' && typeof performance.now === 'function'
		? performance.now()
		: Date.now();
}

/**
 * Map raw duration (ms) to the highest configured edge ≤ duration.
 * Values ≥3000 map to 3000 (the `3000+` bucket). Below the floor → 0.
 */
export function bucketLongTaskMs(ms: number): number {
	if (!Number.isFinite(ms) || ms < LONG_TASK_SYNC_FLOOR_MS) {
		return 0;
	}
	let bucket = LONG_TASK_MS_BUCKET_EDGES[0]!;
	for (const edge of LONG_TASK_MS_BUCKET_EDGES) {
		if (ms >= edge) {
			bucket = edge;
		} else {
			break;
		}
	}
	return bucket;
}

export function decideLongTaskAlert(stats: {
	readonly countAt500: number;
	readonly has3000: boolean;
	readonly opaqueExtId: OpaqueId;
	readonly kind: LongTaskKind;
}): LongTaskAlertDecision {
	if (stats.has3000) {
		return { fire: true, reason: 'any3000', opaqueExtId: stats.opaqueExtId, kind: stats.kind };
	}
	if (stats.countAt500 >= LONG_TASK_ALERT_COUNT_AT_500) {
		return {
			fire: true,
			reason: 'count500',
			opaqueExtId: stats.opaqueExtId,
			kind: stats.kind,
			countAt500: stats.countAt500,
		};
	}
	return { fire: false };
}

export function buildLongTaskTelemetryPayload(
	kind: LongTaskKind,
	opaqueExtId: string,
	syncMsBucket: number,
	wallMsBucket: number,
	count: number,
	windowSec: number = LONG_TASK_WINDOW_SEC,
): ExtHostLongTaskTelemetryPayload {
	return { kind, opaqueExtId, syncMsBucket, wallMsBucket, count, windowSec };
}

export function buildEventLoopLagTelemetryPayload(
	snap: EventLoopLagSnapshot,
	windowSec: number = LONG_TASK_WINDOW_SEC,
): ExtHostEventLoopLagTelemetryPayload {
	return {
		p50Bucket: bucketLongTaskMs(snap.p50Ms),
		p99Bucket: bucketLongTaskMs(snap.p99Ms),
		maxBucket: bucketLongTaskMs(snap.maxMs),
		windowSec,
	};
}

/**
 * Pure windowed aggregator + scope stack. One instance per EH lifetime.
 */
export class ExtensionHostLongTaskMonitor {
	private readonly _opaqueIds: SessionEntityIdMap;
	private readonly _scopeStack: LongTaskScope[] = [];
	/** Monotonic count of attributed scope pushes — RPC catch-all uses this to avoid double-count. */
	private _attributedScopePushes = 0;
	private readonly _byExt = new Map<string, ExtWindowAgg>();
	private _windowStartMs: number;
	private _eldWindow: EventLoopLagSnapshot | undefined;
	private _eldHighStreak = 0;
	private readonly _windowSec: number;

	constructor(options?: {
		readonly opaqueIds?: SessionEntityIdMap;
		readonly windowSec?: number;
		readonly nowMs?: number;
	}) {
		this._opaqueIds = options?.opaqueIds ?? new SessionEntityIdMap('ext');
		this._windowSec = options?.windowSec ?? LONG_TASK_WINDOW_SEC;
		this._windowStartMs = options?.nowMs ?? Date.now();
	}

	/** Mint / reuse opaque id for a real extension identifier (never telemetered). */
	opaqueExtIdFor(extensionId: string | undefined): OpaqueId {
		if (!extensionId) {
			return LONG_TASK_UNATTRIBUTED_OPAQUE;
		}
		return this._opaqueIds.opaqueId(extensionId);
	}

	pushScope(kind: LongTaskKind, extensionId: string | undefined): LongTaskScope {
		const scope: LongTaskScope = {
			kind,
			opaqueExtId: this.opaqueExtIdFor(extensionId),
		};
		this._scopeStack.push(scope);
		if (kind !== 'rpc') {
			this._attributedScopePushes += 1;
		}
		return scope;
	}

	popScope(): void {
		this._scopeStack.pop();
	}

	currentScope(): LongTaskScope | undefined {
		return this._scopeStack.length > 0
			? this._scopeStack[this._scopeStack.length - 1]
			: undefined;
	}

	/**
	 * Time the sync slice of `fn`. Scope is pushed for the sync duration only
	 * (EH is single-threaded; nesting is a plain stack). Wall time for thenables
	 * is recorded when the promise settles; only slices with sync ≥ floor are kept.
	 */
	measureSync<T>(kind: LongTaskKind, extensionId: string | undefined, fn: () => T): T {
		const scope = this.pushScope(kind, extensionId);
		const t0 = nowMs();
		try {
			const result = fn();
			const syncMs = nowMs() - t0;
			if (isThenable(result)) {
				const opaqueExtId = scope.opaqueExtId;
				const recordedKind = kind;
				Promise.resolve(result).then(
					() => this._recordMeasured(recordedKind, opaqueExtId, syncMs, nowMs() - t0),
					() => this._recordMeasured(recordedKind, opaqueExtId, syncMs, nowMs() - t0),
				);
			} else {
				this._recordMeasured(kind, scope.opaqueExtId, syncMs, syncMs);
			}
			return result;
		} catch (err) {
			const syncMs = nowMs() - t0;
			this._recordMeasured(kind, scope.opaqueExtId, syncMs, syncMs);
			throw err;
		} finally {
			this.popScope();
		}
	}

	/**
	 * RPC catch-all: time every main→EH invoke. If an attributed wrap (command /
	 * provider / event / activation) ran inside, skip — those sites already recorded.
	 * Otherwise emit `kind='rpc'` with the unattributed sentinel opaque id.
	 */
	measureRpc<T>(fn: () => T): T {
		const attributedBefore = this._attributedScopePushes;
		const t0 = nowMs();
		try {
			const result = fn();
			const syncMs = nowMs() - t0;
			const finish = (wallMs: number) => {
				if (this._attributedScopePushes !== attributedBefore) {
					return;
				}
				this._recordMeasured('rpc', LONG_TASK_UNATTRIBUTED_OPAQUE, syncMs, wallMs);
			};
			if (isThenable(result)) {
				Promise.resolve(result).then(
					() => finish(nowMs() - t0),
					() => finish(nowMs() - t0),
				);
			} else {
				finish(syncMs);
			}
			return result;
		} catch (err) {
			const syncMs = nowMs() - t0;
			if (this._attributedScopePushes === attributedBefore) {
				this._recordMeasured('rpc', LONG_TASK_UNATTRIBUTED_OPAQUE, syncMs, syncMs);
			}
			throw err;
		}
	}

	/** Scripted / test entry: record a completed slice (sync/wall in ms). */
	recordSlice(kind: LongTaskKind, extensionId: string | undefined, syncMs: number, wallMs?: number): void {
		this._recordMeasured(kind, this.opaqueExtIdFor(extensionId), syncMs, wallMs ?? syncMs);
	}

	/** Record using an already-minted opaque id (tests asserting attribution). */
	recordSliceOpaque(kind: LongTaskKind, opaqueExtId: OpaqueId, syncMs: number, wallMs?: number): void {
		this._recordMeasured(kind, opaqueExtId, syncMs, wallMs ?? syncMs);
	}

	/** Fold an ELD histogram sample into the current window (called on u30 tick). */
	noteEventLoopLag(snap: EventLoopLagSnapshot): void {
		if (!this._eldWindow) {
			this._eldWindow = snap;
			return;
		}
		// Keep worst p99 / max within the window; p50 as running max-of-p50 (conservative).
		this._eldWindow = {
			p50Ms: Math.max(this._eldWindow.p50Ms, snap.p50Ms),
			p99Ms: Math.max(this._eldWindow.p99Ms, snap.p99Ms),
			maxMs: Math.max(this._eldWindow.maxMs, snap.maxMs),
		};
	}

	/**
	 * Flush when the wall window elapses. Safe to call on every sampler tick.
	 * Returns undefined when the window is still open.
	 */
	flushIfDue(nowWallMs: number, sink?: GuardSafeTelemetrySink): LongTaskWindowFlush | undefined {
		if (nowWallMs - this._windowStartMs < this._windowSec * 1000) {
			return undefined;
		}
		return this.forceFlush(nowWallMs, sink);
	}

	/** Force end-of-window aggregation (tests / shutdown). */
	forceFlush(nowWallMs: number = Date.now(), sink?: GuardSafeTelemetrySink): LongTaskWindowFlush {
		const longTasks = this._buildTopKPayloads();
		const alerts = this._collectAlerts();
		const eld = this._eldWindow;
		const eventLoopLag = eld ? buildEventLoopLagTelemetryPayload(eld, this._windowSec) : undefined;
		let eldAlert = false;
		if (eld && eld.p99Ms >= ELD_ALERT_P99_MS) {
			this._eldHighStreak += 1;
			eldAlert = this._eldHighStreak >= ELD_ALERT_CONSECUTIVE_WINDOWS;
		} else {
			this._eldHighStreak = 0;
		}

		if (sink) {
			for (const payload of longTasks) {
				this._emit(sink, 'exthostLongTask', payload as unknown as Record<string, unknown>);
			}
			if (eventLoopLag) {
				this._emit(sink, 'exthostEventLoopLag', eventLoopLag as unknown as Record<string, unknown>);
			}
		}

		for (const alert of alerts) {
			if (alert.fire && alert.opaqueExtId) {
				getActiveFlightRecorder()?.record({
					kind: 'longTask',
					opaqueId: alert.opaqueExtId,
					tBucket: alert.reason === 'any3000' ? 3000 : 500,
				});
			}
		}

		this._byExt.clear();
		this._eldWindow = undefined;
		this._windowStartMs = nowWallMs;

		return { longTasks, eventLoopLag, alerts, eldAlert };
	}

	/** Test helper: current opaque map size. */
	get opaqueMapSize(): number {
		return this._opaqueIds.size;
	}

	resetForTests(): void {
		this._scopeStack.length = 0;
		this._attributedScopePushes = 0;
		this._byExt.clear();
		this._eldWindow = undefined;
		this._eldHighStreak = 0;
		this._opaqueIds.clear();
		this._windowStartMs = Date.now();
	}

	private _emit(sink: GuardSafeTelemetrySink, eventName: string, data: Record<string, unknown>): GuardSafeEmitResult {
		return tryGuardSafeEmit(sink, eventName, data, {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			usePublicLog2: true,
		});
	}

	private _recordMeasured(kind: LongTaskKind, opaqueExtId: OpaqueId, syncMs: number, wallMs: number): void {
		if (!Number.isFinite(syncMs) || syncMs < LONG_TASK_SYNC_FLOOR_MS) {
			return;
		}
		const syncMsBucket = bucketLongTaskMs(syncMs);
		const wallMsBucket = bucketLongTaskMs(wallMs) || syncMsBucket;
		let agg = this._byExt.get(opaqueExtId);
		if (!agg) {
			agg = {
				opaqueExtId,
				kindCounts: new Map(),
				maxSyncMs: 0,
				maxWallMs: 0,
				count: 0,
				countAt500: 0,
				has3000: false,
				bucketKeyCounts: new Map(),
			};
			this._byExt.set(opaqueExtId, agg);
		}
		agg.count += 1;
		agg.maxSyncMs = Math.max(agg.maxSyncMs, syncMs);
		agg.maxWallMs = Math.max(agg.maxWallMs, wallMs);
		agg.kindCounts.set(kind, (agg.kindCounts.get(kind) ?? 0) + 1);
		if (syncMs >= LONG_TASK_ALERT_SYNC_MS) {
			agg.countAt500 += 1;
		}
		if (syncMs >= LONG_TASK_ALERT_ANY_MS) {
			agg.has3000 = true;
		}
		const bKey = `${kind}|${syncMsBucket}|${wallMsBucket}`;
		const prev = agg.bucketKeyCounts.get(bKey);
		if (prev) {
			prev.count += 1;
		} else {
			agg.bucketKeyCounts.set(bKey, { kind, syncMsBucket, wallMsBucket, count: 1 });
		}
	}

	private _dominantKind(agg: ExtWindowAgg): LongTaskKind {
		let best: LongTaskKind = 'rpc';
		let bestCount = -1;
		for (const [kind, count] of agg.kindCounts) {
			if (count > bestCount) {
				best = kind;
				bestCount = count;
			}
		}
		return best;
	}

	private _buildTopKPayloads(): ExtHostLongTaskTelemetryPayload[] {
		const ranked = [...this._byExt.values()].sort((a, b) => b.count - a.count || b.maxSyncMs - a.maxSyncMs);
		const out: ExtHostLongTaskTelemetryPayload[] = [];
		for (const agg of ranked.slice(0, LONG_TASK_TOP_K)) {
			// Prefer the bucket-key with the highest count among the dominant kind.
			const dominant = this._dominantKind(agg);
			let best = [...agg.bucketKeyCounts.values()]
				.filter(b => b.kind === dominant)
				.sort((a, b) => b.count - a.count || b.syncMsBucket - a.syncMsBucket)[0];
			if (!best) {
				best = {
					kind: dominant,
					syncMsBucket: bucketLongTaskMs(agg.maxSyncMs),
					wallMsBucket: bucketLongTaskMs(agg.maxWallMs) || bucketLongTaskMs(agg.maxSyncMs),
					count: agg.count,
				};
			}
			out.push(buildLongTaskTelemetryPayload(
				best.kind,
				agg.opaqueExtId,
				best.syncMsBucket,
				best.wallMsBucket,
				agg.count,
				this._windowSec,
			));
		}
		return out;
	}

	private _collectAlerts(): LongTaskAlertDecision[] {
		const out: LongTaskAlertDecision[] = [];
		for (const agg of this._byExt.values()) {
			const decision = decideLongTaskAlert({
				countAt500: agg.countAt500,
				has3000: agg.has3000,
				opaqueExtId: agg.opaqueExtId,
				kind: this._dominantKind(agg),
			});
			if (decision.fire) {
				out.push(decision);
			}
		}
		return out;
	}
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
	return !!value && typeof (value as PromiseLike<unknown>).then === 'function';
}

/** Process-wide monitor so dispatch choke points can attribute without DI. */
let activeLongTaskMonitor: ExtensionHostLongTaskMonitor | undefined;

export function getActiveLongTaskMonitor(): ExtensionHostLongTaskMonitor | undefined {
	return activeLongTaskMonitor;
}

export function setActiveLongTaskMonitor(monitor: ExtensionHostLongTaskMonitor | undefined): void {
	activeLongTaskMonitor = monitor;
}

/** Lazily create the process-wide monitor (EH startup / first dispatch). */
export function ensureActiveLongTaskMonitor(): ExtensionHostLongTaskMonitor {
	if (!activeLongTaskMonitor) {
		activeLongTaskMonitor = new ExtensionHostLongTaskMonitor();
	}
	return activeLongTaskMonitor;
}
