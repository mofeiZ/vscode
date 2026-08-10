/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Extension-host CPU monitor (r15 Category B / P-B) — pure, headless-testable.
 *
 * Thin consumer of the u45 perf foundation: {@link SessionEntityIdMap} for opaque
 * extension ids and {@link tryGuardSafeEmit} / {@link checkGuardSafePayload} for
 * Path-A emit. Attribution reuses {@link distillProfileByUrlCategory}.
 *
 * Layer 1: `process.cpuUsage()` delta on the existing u30 30s tick (effectively free).
 * Layer 2: gated short sampling profile only after sustained ≥50% for 3 samples.
 */

import {
	tryGuardSafeEmit,
	type GuardSafeEmitResult,
	type GuardSafeTelemetrySink,
} from '../../../../platform/telemetry/common/guardSafeEmit.js';
import {
	SessionEntityIdMap,
	type OpaqueId,
} from '../../../../platform/telemetry/common/opaqueIds.js';
import type { IV8Profile } from '../../../../platform/profiling/common/profiling.js';
import {
	distillProfileByUrlCategory,
	isSpecialDistillSegment,
	rankedSegmentTimes,
	type DistillSegmentId,
} from './profileDistill.js';
import { MEMORY_SAMPLE_TELEMETRY_EVERY_N } from './extensionHostMemoryMonitor.js';

/** % of one core — telemetry reports the highest edge ≤ pct (200 for 200+). */
export const CPU_PCT_BUCKET_EDGES: readonly number[] = [5, 10, 25, 50, 75, 100, 200];

/** Trigger attribution when cpuPct sustains at/above this for N consecutive samples. */
export const CPU_SUSTAIN_THRESHOLD_PCT = 50;
export const CPU_SUSTAIN_SAMPLES = 3;

/** Badge / high-confidence attribution bar (share of profiled window). */
export const CPU_TOP_SHARE_ALERT_PCT = 60;

/** Rate-limit: profiles ≥10 min apart, ≤3 per EH session. */
export const CPU_PROFILE_MIN_INTERVAL_MS = 10 * 60_000;
export const CPU_PROFILE_MAX_PER_SESSION = 3;

/** Default short profile duration (ms) — matches auto-profiler ballpark. */
export const CPU_PROFILE_DURATION_MS = 5_000;

/** Emit `exthostCpuSample` on the same cadence as `exthostMemorySample`. */
export const CPU_SAMPLE_TELEMETRY_EVERY_N = MEMORY_SAMPLE_TELEMETRY_EVERY_N;

/** Sustained-seconds bucket edges (3 × 30s ≈ 90s trigger). */
export const CPU_SUSTAINED_SEC_BUCKET_EDGES: readonly number[] = [30, 60, 90, 180, 300];

export type CpuAlertResultKind = 'extension' | 'self' | 'gc' | 'program' | 'inconclusive';

export interface CpuUsageLike {
	readonly user: number;
	readonly system: number;
}

export interface ExtHostCpuSample {
	readonly cpuPct: number;
	readonly cpuPctBucket: number;
	readonly sampleSeq: number;
	readonly uptimeSec: number;
	readonly tsMs: number;
}

export interface ExtHostCpuSampleTelemetryPayload {
	readonly cpuPctBucket: number;
	readonly sampleSeq: number;
	readonly uptimeSec: number;
}

export interface ExtHostCpuAlertTelemetryPayload {
	readonly cpuPctBucket: number;
	readonly sustainedSecBucket: number;
	readonly topSharePctBucket: number;
	readonly profileMs: number;
	readonly resultKind: CpuAlertResultKind;
	/** Present only when {@link resultKind} is `extension`. Opaque `ext-N`. */
	readonly topOpaqueExtId?: string;
}

export interface CpuAlertState {
	/** Consecutive samples at/above {@link CPU_SUSTAIN_THRESHOLD_PCT}. */
	highStreak: number;
	/** Profiles started this EH session. */
	profilesThisSession: number;
	/** Earliest wall time another profile may start (0 = ready). */
	nextProfileAllowedMs: number;
	/** True while an in-flight profile is running (suppress re-triggers). */
	profileInFlight: boolean;
}

export interface CpuProfileTriggerDecision {
	readonly trigger: boolean;
	readonly nextState: CpuAlertState;
	readonly sustainedSec: number;
}

export interface CpuAttributionResult {
	readonly resultKind: CpuAlertResultKind;
	readonly topSharePct: number;
	readonly topSharePctBucket: number;
	readonly topOpaqueExtId?: OpaqueId;
	/** Real extension id for local logs only — never telemetered. */
	readonly topRealExtId?: string;
	readonly topSegmentId: DistillSegmentId | undefined;
}

export function createCpuAlertState(): CpuAlertState {
	return {
		highStreak: 0,
		profilesThisSession: 0,
		nextProfileAllowedMs: 0,
		profileInFlight: false,
	};
}

/**
 * Map raw CPU % (one core = 100; can exceed 100 with worker_threads) to a closed edge.
 */
export function bucketCpuPct(cpuPct: number): number {
	if (!Number.isFinite(cpuPct) || cpuPct < 0) {
		return 0;
	}
	let bucket = 0;
	for (const edge of CPU_PCT_BUCKET_EDGES) {
		if (cpuPct >= edge) {
			bucket = edge;
		} else {
			break;
		}
	}
	return bucket;
}

/** Share % → 10-step bucket (0, 10, …, 100). */
export function bucketSharePct(sharePct: number): number {
	if (!Number.isFinite(sharePct) || sharePct < 0) {
		return 0;
	}
	const clamped = Math.min(100, sharePct);
	return Math.floor(clamped / 10) * 10;
}

export function bucketSustainedSec(sustainedSec: number): number {
	if (!Number.isFinite(sustainedSec) || sustainedSec < 0) {
		return 0;
	}
	let bucket = 0;
	for (const edge of CPU_SUSTAINED_SEC_BUCKET_EDGES) {
		if (sustainedSec >= edge) {
			bucket = edge;
		} else {
			break;
		}
	}
	return bucket;
}

/**
 * CPU % of one core from a `process.cpuUsage` delta over a wall interval.
 * `delta` user+system are microseconds; `wallMs` is milliseconds.
 */
export function computeCpuPct(delta: CpuUsageLike, wallMs: number): number {
	if (!Number.isFinite(wallMs) || wallMs <= 0) {
		return 0;
	}
	const deltaUs = delta.user + delta.system;
	if (!Number.isFinite(deltaUs) || deltaUs < 0) {
		return 0;
	}
	const wallUs = wallMs * 1000;
	return (deltaUs / wallUs) * 100;
}

/**
 * Absolute cumulative usages → delta. Returns undefined when `prev` is missing
 * (baseline tick — store absolute, no pct yet).
 */
export function cpuUsageDelta(prev: CpuUsageLike | undefined, curr: CpuUsageLike): CpuUsageLike | undefined {
	if (!prev) {
		return undefined;
	}
	return {
		user: Math.max(0, curr.user - prev.user),
		system: Math.max(0, curr.system - prev.system),
	};
}

/**
 * Pure sustain / rate-limit state machine (u30 `decideMemoryAlert` shape).
 * `trigger` means: start a short in-process sampling profile.
 */
export function decideCpuProfileTrigger(
	cpuPct: number,
	state: CpuAlertState,
	nowMs: number,
	options?: {
		readonly thresholdPct?: number;
		readonly sustainSamples?: number;
		readonly minIntervalMs?: number;
		readonly maxPerSession?: number;
		readonly sampleIntervalSec?: number;
	},
): CpuProfileTriggerDecision {
	const threshold = options?.thresholdPct ?? CPU_SUSTAIN_THRESHOLD_PCT;
	const needSamples = options?.sustainSamples ?? CPU_SUSTAIN_SAMPLES;
	const minInterval = options?.minIntervalMs ?? CPU_PROFILE_MIN_INTERVAL_MS;
	const maxPerSession = options?.maxPerSession ?? CPU_PROFILE_MAX_PER_SESSION;
	const sampleIntervalSec = options?.sampleIntervalSec ?? 30;

	let highStreak = cpuPct >= threshold ? state.highStreak + 1 : 0;
	const sustainedSec = highStreak * sampleIntervalSec;

	if (
		!state.profileInFlight
		&& highStreak >= needSamples
		&& state.profilesThisSession < maxPerSession
		&& nowMs >= state.nextProfileAllowedMs
	) {
		return {
			trigger: true,
			sustainedSec,
			nextState: {
				highStreak: 0, // consume the streak; next trigger needs a fresh sustain
				profilesThisSession: state.profilesThisSession + 1,
				nextProfileAllowedMs: nowMs + minInterval,
				profileInFlight: true,
			},
		};
	}

	return {
		trigger: false,
		sustainedSec,
		nextState: {
			highStreak,
			profilesThisSession: state.profilesThisSession,
			nextProfileAllowedMs: state.nextProfileAllowedMs,
			profileInFlight: state.profileInFlight,
		},
	};
}

export function markCpuProfileFinished(state: CpuAlertState): CpuAlertState {
	return { ...state, profileInFlight: false };
}

export function buildCpuSampleTelemetryPayload(sample: ExtHostCpuSample): ExtHostCpuSampleTelemetryPayload {
	return {
		cpuPctBucket: sample.cpuPctBucket,
		sampleSeq: sample.sampleSeq,
		uptimeSec: sample.uptimeSec,
	};
}

export function buildCpuAlertTelemetryPayload(args: {
	readonly cpuPctBucket: number;
	readonly sustainedSec: number;
	readonly attribution: CpuAttributionResult;
	readonly profileMs?: number;
}): ExtHostCpuAlertTelemetryPayload {
	const payload: ExtHostCpuAlertTelemetryPayload = {
		cpuPctBucket: args.cpuPctBucket,
		sustainedSecBucket: bucketSustainedSec(args.sustainedSec),
		topSharePctBucket: args.attribution.topSharePctBucket,
		profileMs: args.profileMs ?? CPU_PROFILE_DURATION_MS,
		resultKind: args.attribution.resultKind,
	};
	if (args.attribution.resultKind === 'extension' && args.attribution.topOpaqueExtId) {
		return { ...payload, topOpaqueExtId: args.attribution.topOpaqueExtId };
	}
	return payload;
}

export function shouldEmitCpuSampleTelemetry(sampleSeq: number, everyN: number = CPU_SAMPLE_TELEMETRY_EVERY_N): boolean {
	return sampleSeq === 1 || sampleSeq % everyN === 0;
}

/**
 * Attribute a distilled profile: top extension → opaque id; special segments
 * keep their taxonomy (`gc` / `program` / `self`); empty → inconclusive.
 */
export function attributeCpuProfile(
	profile: IV8Profile,
	categories: ReadonlyArray<readonly [url: string, extensionId: string]>,
	opaqueIds: SessionEntityIdMap,
): CpuAttributionResult {
	const distilled = distillProfileByUrlCategory(profile, categories);
	const ranked = rankedSegmentTimes(distilled.getAggregatedTimes());
	if (ranked.length === 0) {
		return {
			resultKind: 'inconclusive',
			topSharePct: 0,
			topSharePctBucket: 0,
			topSegmentId: undefined,
		};
	}
	const top = ranked[0]!;
	const topSharePctBucket = bucketSharePct(top.sharePct);

	if (isSpecialDistillSegment(top.segmentId)) {
		const kind: CpuAlertResultKind =
			top.segmentId === 'gc' ? 'gc'
				: top.segmentId === 'program' ? 'program'
					: top.segmentId === 'self' ? 'self'
						: 'inconclusive';
		return {
			resultKind: kind,
			topSharePct: top.sharePct,
			topSharePctBucket,
			topSegmentId: top.segmentId,
		};
	}

	const topOpaqueExtId = opaqueIds.opaqueId(top.segmentId);
	return {
		resultKind: 'extension',
		topSharePct: top.sharePct,
		topSharePctBucket,
		topOpaqueExtId,
		topRealExtId: top.segmentId,
		topSegmentId: top.segmentId,
	};
}

export interface CpuTickResult {
	readonly sample: ExtHostCpuSample | undefined;
	readonly shouldProfile: boolean;
	readonly sustainedSec: number;
	readonly emitSample: boolean;
	readonly samplePayload?: ExtHostCpuSampleTelemetryPayload;
}

/**
 * One instance per EH lifetime. Pure except optional guard-safe emit via sink.
 */
export class ExtensionHostCpuMonitor {
	private readonly _opaqueIds: SessionEntityIdMap;
	private _prevCpu: CpuUsageLike | undefined;
	private _prevWallMs: number | undefined;
	private _sampleSeq = 0;
	private _state: CpuAlertState;
	/** Sustained seconds at the moment of the last trigger (for alert payload). */
	private _lastTriggerSustainedSec = 0;
	private _lastCpuPctBucket = 0;

	constructor(options?: {
		readonly opaqueIds?: SessionEntityIdMap;
		readonly initialState?: CpuAlertState;
	}) {
		this._opaqueIds = options?.opaqueIds ?? new SessionEntityIdMap('ext');
		this._state = options?.initialState ?? createCpuAlertState();
	}

	get state(): CpuAlertState {
		return this._state;
	}

	opaqueExtIdFor(extensionId: string): OpaqueId {
		return this._opaqueIds.opaqueId(extensionId);
	}

	/**
	 * Feed one absolute `process.cpuUsage()` reading + wall timestamp.
	 * First call establishes baseline (no sample). Subsequent calls compute pct.
	 */
	onCpuSample(args: {
		readonly cpuUsage: CpuUsageLike;
		readonly wallMs: number;
		readonly uptimeSec: number;
		readonly sink?: GuardSafeTelemetrySink;
		readonly sampleIntervalSec?: number;
	}): CpuTickResult {
		const delta = cpuUsageDelta(this._prevCpu, args.cpuUsage);
		const wallDeltaMs = this._prevWallMs !== undefined ? args.wallMs - this._prevWallMs : 0;
		this._prevCpu = args.cpuUsage;
		this._prevWallMs = args.wallMs;

		if (!delta || wallDeltaMs <= 0) {
			return { sample: undefined, shouldProfile: false, sustainedSec: 0, emitSample: false };
		}

		this._sampleSeq += 1;
		const cpuPct = computeCpuPct(delta, wallDeltaMs);
		const sample: ExtHostCpuSample = {
			cpuPct,
			cpuPctBucket: bucketCpuPct(cpuPct),
			sampleSeq: this._sampleSeq,
			uptimeSec: Math.round(args.uptimeSec),
			tsMs: args.wallMs,
		};
		this._lastCpuPctBucket = sample.cpuPctBucket;

		const decision = decideCpuProfileTrigger(cpuPct, this._state, args.wallMs, {
			sampleIntervalSec: args.sampleIntervalSec,
		});
		this._state = decision.nextState;
		if (decision.trigger) {
			this._lastTriggerSustainedSec = decision.sustainedSec;
		}

		const emitSample = shouldEmitCpuSampleTelemetry(sample.sampleSeq);
		const samplePayload = emitSample ? buildCpuSampleTelemetryPayload(sample) : undefined;
		if (emitSample && samplePayload && args.sink) {
			this._emit(args.sink, 'exthostCpuSample', samplePayload as unknown as Record<string, unknown>);
		}

		return {
			sample,
			shouldProfile: decision.trigger,
			sustainedSec: decision.sustainedSec,
			emitSample,
			samplePayload,
		};
	}

	/**
	 * After a gated profile completes: attribute, emit `exthostCpuAlert`, clear in-flight.
	 */
	completeProfile(args: {
		readonly profile: IV8Profile;
		readonly categories: ReadonlyArray<readonly [url: string, extensionId: string]>;
		readonly sink?: GuardSafeTelemetrySink;
		readonly profileMs?: number;
		readonly cpuPctBucket?: number;
		readonly sustainedSec?: number;
	}): { readonly attribution: CpuAttributionResult; readonly alertPayload: ExtHostCpuAlertTelemetryPayload; readonly emitted: boolean } {
		const attribution = attributeCpuProfile(args.profile, args.categories, this._opaqueIds);
		const alertPayload = buildCpuAlertTelemetryPayload({
			cpuPctBucket: args.cpuPctBucket ?? this._lastCpuPctBucket,
			sustainedSec: args.sustainedSec ?? this._lastTriggerSustainedSec,
			attribution,
			profileMs: args.profileMs,
		});
		this._state = markCpuProfileFinished(this._state);

		let emitted = false;
		if (args.sink) {
			const result = this._emit(args.sink, 'exthostCpuAlert', alertPayload as unknown as Record<string, unknown>);
			emitted = result.emitted;
		}
		return { attribution, alertPayload, emitted };
	}

	/** Test / abort path: clear in-flight without emitting. */
	cancelProfile(): void {
		this._state = markCpuProfileFinished(this._state);
	}

	resetForTests(): void {
		this._prevCpu = undefined;
		this._prevWallMs = undefined;
		this._sampleSeq = 0;
		this._state = createCpuAlertState();
		this._lastTriggerSustainedSec = 0;
		this._lastCpuPctBucket = 0;
		this._opaqueIds.clear();
	}

	private _emit(sink: GuardSafeTelemetrySink, eventName: string, data: Record<string, unknown>): GuardSafeEmitResult {
		return tryGuardSafeEmit(sink, eventName, data, {
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			usePublicLog2: true,
		});
	}
}
