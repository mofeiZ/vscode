/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Generic bounded flight-recorder ring (u45 perf foundation).
 *
 * Pattern from Desk Gnome's rolling sample shelf
 * (`extensions/desk-gnome/src/extension.ts` ROLLING_MAX_SAMPLES / rollingSamples)
 * and r17 workspace-actions Lane A: keep recent `{kind, opaqueId, tBucket}`
 * entries in memory; never stream; flush only onto an existing diagnostic.
 *
 * Callers (crash record, memory alert, long-task/CPU alert, R4b action ring)
 * attach via {@link FlightRecorderRing.flushInto} or the process-wide active ring.
 */

export const DEFAULT_FLIGHT_RECORDER_CAP = 32;

/** One ring slot — numbers / closed enums / opaque ids only. */
export interface FlightRecorderEntry {
	readonly kind: string;
	readonly opaqueId: string;
	readonly tBucket: number;
}

export interface FlightRecorderFlushOptions {
	/**
	 * Leaf prefix for flattened fields (`${prefix}0_kind`, …).
	 * Default `fr` keeps the generic carrier distinct from R4b's `a0_*` schema.
	 */
	readonly prefix?: string;
	/** When true (default), also write `${prefix}RingLen` / `${prefix}RingCap`. */
	readonly includeMeta?: boolean;
}

/**
 * In-memory capped ring. Push is silent — no telemetry.
 */
export class FlightRecorderRing {
	private readonly entries: FlightRecorderEntry[] = [];

	constructor(
		private readonly _cap: number = DEFAULT_FLIGHT_RECORDER_CAP,
	) {
		if (!Number.isFinite(_cap) || _cap < 1) {
			throw new Error('FlightRecorderRing cap must be a positive finite number');
		}
	}

	get cap(): number {
		return this._cap;
	}

	get length(): number {
		return this.entries.length;
	}

	record(entry: FlightRecorderEntry): void {
		this.entries.push(entry);
		if (this.entries.length > this._cap) {
			this.entries.splice(0, this.entries.length - this._cap);
		}
	}

	/** Newest-last copy of the current window. */
	snapshot(): readonly FlightRecorderEntry[] {
		return this.entries.slice();
	}

	clear(): void {
		this.entries.length = 0;
	}

	/**
	 * Attach the recent ring onto a diagnostic payload as flat leaves
	 * (guard-friendly; no nested arrays of objects).
	 *
	 * Mutates and returns `diagnostic`.
	 */
	flushInto(diagnostic: Record<string, unknown>, options?: FlightRecorderFlushOptions): Record<string, unknown> {
		const prefix = options?.prefix ?? 'fr';
		const includeMeta = options?.includeMeta !== false;
		const snap = this.snapshot();
		if (includeMeta) {
			diagnostic[`${prefix}RingLen`] = snap.length;
			diagnostic[`${prefix}RingCap`] = this._cap;
		}
		for (let i = 0; i < snap.length; i++) {
			const e = snap[i]!;
			diagnostic[`${prefix}${i}_kind`] = e.kind;
			diagnostic[`${prefix}${i}_id`] = e.opaqueId;
			diagnostic[`${prefix}${i}_t`] = e.tBucket;
		}
		return diagnostic;
	}
}

/** Optional process-wide ring so crash / memory-alert carriers can attach without DI. */
let activeFlightRecorder: FlightRecorderRing | undefined;

export function setActiveFlightRecorder(ring: FlightRecorderRing | undefined): void {
	activeFlightRecorder = ring;
}

export function getActiveFlightRecorder(): FlightRecorderRing | undefined {
	return activeFlightRecorder;
}

/**
 * If an active ring is registered, flatten it into `diagnostic`.
 * No-op when none is set (existing crash/alert payloads stay unchanged).
 */
export function flushActiveFlightRecorderInto(
	diagnostic: Record<string, unknown>,
	options?: FlightRecorderFlushOptions,
): Record<string, unknown> {
	const ring = activeFlightRecorder;
	if (!ring) {
		return diagnostic;
	}
	return ring.flushInto(diagnostic, options);
}
