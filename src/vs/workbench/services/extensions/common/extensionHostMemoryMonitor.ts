/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Per-extension-host memory sampling helpers (pure / unit-testable).
 *
 * Privacy: telemetry payloads built here are numbers, buckets, and short enums
 * only — never paths or contents. Affinity is stamped main-thread-side.
 */

/** Fixed RSS bucket edges in MB (telemetry reports the highest edge ≤ RSS). */
export const RSS_BUCKET_EDGES_MB: readonly number[] = [128, 256, 512, 1024, 1536, 2048, 3072, 4096, 6144, 8192];

/** Default level-alert threshold: fire when RSS bucket reaches/crosses this edge. */
export const DEFAULT_LEVEL_THRESHOLD_BUCKET_MB = 3072;

/** Default growth-alert threshold in MB/min (u7 leak was ~8290 MB/min). */
export const DEFAULT_GROWTH_THRESHOLD_MB_PER_MIN = 256;

/** Sample cadence used by the EH IntervalTimer. */
export const MEMORY_SAMPLE_INTERVAL_MS = 30_000;

/** Emit `exthostMemorySample` every Nth sample (~5 min at 30s cadence) plus baseline. */
export const MEMORY_SAMPLE_TELEMETRY_EVERY_N = 10;

export type MemoryAlertTrigger = 'level' | 'growth';

export interface ExtHostMemorySample {
	readonly rssMb: number;
	readonly rssBucketMb: number;
	readonly heapUsedMb: number;
	readonly heapTotalMb: number;
	readonly externalMb: number;
	readonly growthMbPerMin: number;
	readonly uptimeSec: number;
	readonly sampleSeq: number;
	readonly pid: number;
	readonly tsMs: number;
}

export interface ExtHostMemoryTelemetryPayload {
	readonly rssBucketMb: number;
	readonly heapUsedMb: number;
	readonly heapTotalMb: number;
	readonly externalMb: number;
	readonly growthMbPerMin: number;
	readonly uptimeSec: number;
	readonly sampleSeq: number;
	readonly pid: number;
}

export interface ExtHostMemoryAlertTelemetryPayload extends ExtHostMemoryTelemetryPayload {
	readonly trigger: MemoryAlertTrigger;
	readonly thresholdBucketMb: number;
}

export interface MemoryAlertState {
	/** Level arm: true until a level alert fires; re-armed below hysteresis floor. */
	levelArmed: boolean;
	/** Earliest wall time a growth alert may fire again (0 = ready). */
	growthNextAllowedMs: number;
	/** Current growth backoff window in ms (doubles after each growth fire). */
	growthBackoffMs: number;
}

export interface MemoryAlertDecision {
	readonly fire: boolean;
	readonly trigger?: MemoryAlertTrigger;
	readonly thresholdBucketMb?: number;
	readonly nextState: MemoryAlertState;
}

export interface DecideMemoryAlertOptions {
	readonly levelThresholdBucketMb?: number;
	readonly growthThresholdMbPerMin?: number;
	readonly nowMs?: number;
	readonly initialGrowthBackoffMs?: number;
}

const DEFAULT_INITIAL_GROWTH_BACKOFF_MS = 60_000;

export function createMemoryAlertState(): MemoryAlertState {
	return {
		levelArmed: true,
		growthNextAllowedMs: 0,
		growthBackoffMs: DEFAULT_INITIAL_GROWTH_BACKOFF_MS,
	};
}

/**
 * Map raw RSS (MB) to the highest configured edge ≤ RSS (0 if below the first edge).
 */
export function bucketRssMb(rssMb: number): number {
	if (!Number.isFinite(rssMb) || rssMb < 0) {
		return 0;
	}
	let bucket = 0;
	for (const edge of RSS_BUCKET_EDGES_MB) {
		if (rssMb >= edge) {
			bucket = edge;
		} else {
			break;
		}
	}
	return bucket;
}

/** Edge immediately below `edge`, or 0 if `edge` is the first / unknown. */
export function previousRssBucketEdge(edge: number): number {
	const idx = RSS_BUCKET_EDGES_MB.indexOf(edge);
	if (idx <= 0) {
		return 0;
	}
	return RSS_BUCKET_EDGES_MB[idx - 1]!;
}

export function bytesToRoundedMb(bytes: number): number {
	if (!Number.isFinite(bytes) || bytes < 0) {
		return 0;
	}
	return Math.round(bytes / (1024 * 1024));
}

/**
 * Growth rate (MB/min) from a ring of samples. Needs ≥2 points; uses oldest→newest slope.
 */
export function computeGrowthMbPerMin(samples: ReadonlyArray<{ readonly rssMb: number; readonly tsMs: number }>): number {
	if (samples.length < 2) {
		return 0;
	}
	const first = samples[0]!;
	const last = samples[samples.length - 1]!;
	const dtMs = last.tsMs - first.tsMs;
	if (dtMs <= 0) {
		return 0;
	}
	return ((last.rssMb - first.rssMb) / dtMs) * 60_000;
}

/**
 * Pure alert decision: level bucket-crossing with hysteresis + growth-rate with exponential backoff.
 */
export function decideMemoryAlert(
	sample: Pick<ExtHostMemorySample, 'rssBucketMb' | 'growthMbPerMin'>,
	state: MemoryAlertState,
	options: DecideMemoryAlertOptions = {},
): MemoryAlertDecision {
	const levelThreshold = options.levelThresholdBucketMb ?? DEFAULT_LEVEL_THRESHOLD_BUCKET_MB;
	const growthThreshold = options.growthThresholdMbPerMin ?? DEFAULT_GROWTH_THRESHOLD_MB_PER_MIN;
	const nowMs = options.nowMs ?? 0;
	const initialBackoff = options.initialGrowthBackoffMs ?? DEFAULT_INITIAL_GROWTH_BACKOFF_MS;

	const hysteresisFloor = previousRssBucketEdge(levelThreshold);
	let levelArmed = state.levelArmed;
	let growthNextAllowedMs = state.growthNextAllowedMs;
	let growthBackoffMs = state.growthBackoffMs > 0 ? state.growthBackoffMs : initialBackoff;

	// Re-arm level trigger once RSS drops below the previous bucket edge.
	if (!levelArmed && sample.rssBucketMb < hysteresisFloor) {
		levelArmed = true;
	}

	// Prefer level over growth when both would fire on the same sample.
	if (levelArmed && sample.rssBucketMb >= levelThreshold) {
		return {
			fire: true,
			trigger: 'level',
			thresholdBucketMb: levelThreshold,
			nextState: {
				levelArmed: false,
				growthNextAllowedMs,
				growthBackoffMs,
			},
		};
	}

	const growthSustained = sample.growthMbPerMin > growthThreshold;
	if (!growthSustained) {
		// Cool down: reset backoff schedule when growth falls below threshold.
		return {
			fire: false,
			nextState: {
				levelArmed,
				growthNextAllowedMs: 0,
				growthBackoffMs: initialBackoff,
			},
		};
	}

	if (nowMs >= growthNextAllowedMs) {
		const nextBackoff = Math.min(growthBackoffMs * 2, 60 * 60_000);
		return {
			fire: true,
			trigger: 'growth',
			thresholdBucketMb: levelThreshold,
			nextState: {
				levelArmed,
				growthNextAllowedMs: nowMs + growthBackoffMs,
				growthBackoffMs: nextBackoff,
			},
		};
	}

	return {
		fire: false,
		nextState: {
			levelArmed,
			growthNextAllowedMs,
			growthBackoffMs,
		},
	};
}

export function buildMemoryTelemetryPayload(sample: ExtHostMemorySample): ExtHostMemoryTelemetryPayload {
	return {
		rssBucketMb: sample.rssBucketMb,
		heapUsedMb: sample.heapUsedMb,
		heapTotalMb: sample.heapTotalMb,
		externalMb: sample.externalMb,
		growthMbPerMin: Math.round(sample.growthMbPerMin),
		uptimeSec: sample.uptimeSec,
		sampleSeq: sample.sampleSeq,
		pid: sample.pid,
	};
}

export function buildMemoryAlertTelemetryPayload(
	sample: ExtHostMemorySample,
	trigger: MemoryAlertTrigger,
	thresholdBucketMb: number,
): ExtHostMemoryAlertTelemetryPayload {
	return {
		...buildMemoryTelemetryPayload(sample),
		trigger,
		thresholdBucketMb,
	};
}

/** Local metrics line (numbers only). Raw RSS MB is OK here — file is not exfiltrated. */
export function formatMemoryLogLine(sample: ExtHostMemorySample, kind: 'SAMPLE' | 'ALERT' = 'SAMPLE', trigger?: MemoryAlertTrigger): string {
	const base = `${kind} seq=${sample.sampleSeq} ts=${sample.tsMs} pid=${sample.pid} uptimeSec=${sample.uptimeSec} rssMb=${sample.rssMb} rssBucketMb=${sample.rssBucketMb} heapUsedMb=${sample.heapUsedMb} heapTotalMb=${sample.heapTotalMb} externalMb=${sample.externalMb} growthMbPerMin=${Math.round(sample.growthMbPerMin)}`;
	if (kind === 'ALERT' && trigger) {
		return `${base} trigger=${trigger}`;
	}
	return base;
}

export function shouldEmitMemorySampleTelemetry(sampleSeq: number, everyN: number = MEMORY_SAMPLE_TELEMETRY_EVERY_N): boolean {
	// sampleSeq is 1-based: baseline (1) plus every Nth thereafter.
	return sampleSeq === 1 || sampleSeq % everyN === 0;
}

/**
 * Ring buffer of recent samples for growth-rate computation.
 */
export class MemorySampleRing {
	private readonly _samples: Array<{ rssMb: number; tsMs: number }> = [];

	constructor(private readonly _capacity: number = 8) { }

	push(rssMb: number, tsMs: number): void {
		this._samples.push({ rssMb, tsMs });
		while (this._samples.length > this._capacity) {
			this._samples.shift();
		}
	}

	get samples(): ReadonlyArray<{ readonly rssMb: number; readonly tsMs: number }> {
		return this._samples;
	}

	growthMbPerMin(): number {
		return computeGrowthMbPerMin(this._samples);
	}
}

export interface ProcessMemoryUsageLike {
	readonly rss: number;
	readonly heapUsed: number;
	readonly heapTotal: number;
	readonly external: number;
}

export function buildMemorySample(args: {
	readonly usage: ProcessMemoryUsageLike;
	readonly uptimeSec: number;
	readonly sampleSeq: number;
	readonly pid: number;
	readonly tsMs: number;
	readonly ring: MemorySampleRing;
}): ExtHostMemorySample {
	const rssMb = bytesToRoundedMb(args.usage.rss);
	args.ring.push(rssMb, args.tsMs);
	const rssBucketMb = bucketRssMb(rssMb);
	return {
		rssMb,
		rssBucketMb,
		heapUsedMb: bytesToRoundedMb(args.usage.heapUsed),
		heapTotalMb: bytesToRoundedMb(args.usage.heapTotal),
		externalMb: bytesToRoundedMb(args.usage.external),
		growthMbPerMin: args.ring.growthMbPerMin(),
		uptimeSec: Math.round(args.uptimeSec),
		sampleSeq: args.sampleSeq,
		pid: args.pid,
		tsMs: args.tsMs,
	};
}
