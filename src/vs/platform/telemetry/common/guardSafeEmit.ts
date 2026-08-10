/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Guard-safe telemetry emit helper (u45 perf foundation).
 *
 * Extracts the pre-check pattern used by:
 * - `_emitGuardedCrashTelemetry` (`nativeExtensionService.ts`)
 * - `logDebugProbe` (`debugProbes/logDebugProbe.ts`)
 * - Path A `detectTelemetryUserData` in `mainThreadTelemetry.ts`
 *
 * Feature consumers (latency / CPU / R4b / heap attribution) call this instead
 * of open-coding detect→drop→publicLog.
 */

import type { ITelemetryService } from './telemetry.js';
import {
	detectTelemetryUserData,
	type TelemetryGuardDetectOptions,
	type TelemetryGuardHit,
	type TelemetryGuardResult,
} from './telemetryDataGuard.js';

export type GuardSafeEmitResult =
	| { readonly emitted: true }
	| { readonly emitted: false; readonly guard: TelemetryGuardHit };

export interface GuardSafeEmitOptions {
	readonly boundMeasurements?: boolean;
	readonly strictShape?: boolean;
	readonly failClosedOnDepthAbort?: boolean;
	/** Called when the guard blocks; never throws into the emit path. */
	readonly onBlocked?: (eventName: string, guard: TelemetryGuardHit) => void;
	/**
	 * Prefer `publicLog2` when true (default). Crash-record path historically
	 * uses `publicLog`; pass false to match that carrier.
	 */
	readonly usePublicLog2?: boolean;
}

/** Minimal surface so unit tests need not construct a full telemetry service. */
export interface GuardSafeTelemetrySink {
	publicLog(eventName: string, data?: Record<string, unknown>): void;
	publicLog2?(eventName: string, data?: Record<string, unknown>): void;
}

/**
 * Run `detectTelemetryUserData` on `data`; on miss, emit. On hit, invoke
 * `onBlocked` (if any) and skip emit.
 */
export function tryGuardSafeEmit(
	telemetryService: GuardSafeTelemetrySink | ITelemetryService,
	eventName: string,
	data: Record<string, unknown>,
	options?: GuardSafeEmitOptions,
): GuardSafeEmitResult {
	const detectOpts: TelemetryGuardDetectOptions = {
		boundMeasurements: options?.boundMeasurements ?? true,
		strictShape: options?.strictShape,
		failClosedOnDepthAbort: options?.failClosedOnDepthAbort ?? true,
		eventName,
	};
	const guard: TelemetryGuardResult = detectTelemetryUserData(data, detectOpts);
	if (guard.hit) {
		try {
			options?.onBlocked?.(eventName, guard);
		} catch {
			// Logging must never throw into the emit path.
		}
		return { emitted: false, guard };
	}

	const usePublicLog2 = options?.usePublicLog2 !== false;
	if (usePublicLog2 && typeof telemetryService.publicLog2 === 'function') {
		telemetryService.publicLog2(eventName, data as never);
	} else {
		telemetryService.publicLog(eventName, data);
	}
	return { emitted: true };
}

/**
 * Pure guard check for builders/tests that assemble a payload before emit.
 * Defaults match Path-A diagnostic events (bound measurements, fail-closed depth).
 */
export function checkGuardSafePayload(
	data: unknown,
	eventName: string,
	options?: Pick<GuardSafeEmitOptions, 'boundMeasurements' | 'strictShape' | 'failClosedOnDepthAbort'>,
): TelemetryGuardResult {
	return detectTelemetryUserData(data, {
		boundMeasurements: options?.boundMeasurements ?? true,
		strictShape: options?.strictShape,
		failClosedOnDepthAbort: options?.failClosedOnDepthAbort ?? true,
		eventName,
	});
}
