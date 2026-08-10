/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { StringSHA1 } from '../../../../base/common/hash.js';
import { IGDPRProperty } from '../gdprTypings.js';
import { ITelemetryService } from '../telemetry.js';
import {
	detectTelemetryUserData,
	formatTelemetryGuardViolation,
	isAllowedExtensionTelemetryString,
	TelemetryGuardViolation,
} from '../telemetryDataGuard.js';

/** Max TTL at registration (design §3.1 / skill hard rule 3). */
export const DEBUG_PROBE_MAX_TTL_DAYS = 90;

/**
 * Branded opaque id. Free-form `string` is not assignable; produce only via
 * {@link opaque} / {@link hashOpaque}.
 */
export type OpaqueId = string & { readonly __opaqueId: unique symbol };

/**
 * Enum / short-token literal. Bare `string` collapses to `never` so free-form
 * strings do not type-check as probe payload values.
 */
export type ProbeEnumLiteral<T extends string> = string extends T ? never : T;

/**
 * One leaf admitted by {@link SafeProbePayload}: number | boolean | enum-literal | OpaqueId.
 */
export type SafeProbeLeaf<T> =
	T extends number | boolean | OpaqueId ? T :
	T extends string ? ProbeEnumLiteral<T> :
	never;

/**
 * Compile-time-safe probe payload. Free-form `string` properties become `never`
 * and fail assignment; only number / boolean / string literals / OpaqueId pass.
 */
export type SafeProbePayload<T> = { [K in keyof T]: SafeProbeLeaf<T[K]> };

/**
 * Minimal lifecycle slice (u32): ownership + issue join + TTL.
 * `expiresAt` is derived as createdAt + ttlDays (ISO date) when not supplied.
 */
export interface IDebugProbeManifest {
	readonly owner: string;
	readonly issueRef: string;
	readonly createdAt: string;
	readonly ttlDays: number;
}

export interface IDebugProbeMetadata extends IDebugProbeManifest {
	/** Stable id: dbg-<ticket>-<slug>. Never reused. */
	readonly probeId: string;
	/** Alias of issueRef — skill/enumerate parse this key. */
	readonly issue: string;
	/** ISO date. REQUIRED. Runtime-enforced. */
	readonly expiresAt: string;
	/** One line: what question this probe answers. */
	readonly comment: string;
	readonly gdpr: IGDPRProperty;
}

export interface IDebugProbeDefinition extends IDebugProbeMetadata { }

export type DebugProbeEventName = `debugProbe/${string}`;

/** Optional sink for violation lines (tests / host wiring to telemetry-guard.log). */
let _violationSink: ((line: string) => void) | undefined;

export function setDebugProbeViolationSink(sink: ((line: string) => void) | undefined): void {
	_violationSink = sink;
}

/** Test seam: override "now" for expiry checks. */
let _nowMs: (() => number) | undefined;

export function setDebugProbeNowMs(nowMs: (() => number) | undefined): void {
	_nowMs = nowMs;
}

function currentNowMs(): number {
	return _nowMs ? _nowMs() : Date.now();
}

/**
 * Brand a pre-validated opaque token as {@link OpaqueId}.
 * Rejects values the strict-shape allowlist would refuse.
 *
 * Prefer dotted / underscored tokens (`fid.a1b2`, `id_7f3a`). Pure hex or
 * base64-alphabet blobs are expanded by the data guard's decode-before-scan
 * and often fail strict shape even when `isAllowedExtensionTelemetryString` passes.
 */
export function opaque(id: string): OpaqueId {
	if (!isAllowedExtensionTelemetryString(id)) {
		throw new Error(`opaque(): value is not an allowed telemetry token (len/charset/path-like): ${id.length} chars`);
	}
	return id as OpaqueId;
}

/**
 * Hash an arbitrary string to a short prefixed {@link OpaqueId} (no raw value retained).
 * Prefix `h.` keeps the token out of the guard's pure-hex / base64 expanders.
 */
export function hashOpaque(value: string, hexChars: number = 16): OpaqueId {
	const n = Math.max(8, Math.min(28, Math.floor(hexChars)));
	const sha = new StringSHA1();
	sha.update(value);
	return opaque(`h.${sha.digest().slice(0, n)}`);
}

function addDaysIso(createdAt: string, ttlDays: number): string {
	const base = Date.parse(createdAt);
	if (!Number.isFinite(base)) {
		throw new Error(`defineDebugProbe: createdAt is not a parseable ISO date: ${createdAt}`);
	}
	const ms = base + ttlDays * 86_400_000;
	return new Date(ms).toISOString().slice(0, 10);
}

function daysBetween(createdAt: string, expiresAt: string): number {
	const a = Date.parse(createdAt);
	const b = Date.parse(expiresAt);
	if (!Number.isFinite(a) || !Number.isFinite(b)) {
		throw new Error('defineDebugProbe: createdAt/expiresAt must be parseable ISO dates');
	}
	return Math.round((b - a) / 86_400_000);
}

type DefineDebugProbeInput = {
	readonly probeId: string;
	readonly owner: string;
	readonly createdAt: string;
	readonly comment: string;
	readonly gdpr: IGDPRProperty;
	readonly issueRef?: string;
	readonly issue?: string;
	readonly ttlDays?: number;
	readonly expiresAt?: string;
};

/**
 * Register a probe metadata literal. Validates TTL ≤ 90d.
 * Prefer a statically-parseable object literal at the call site (enumerate script).
 */
export function defineDebugProbe<T extends DefineDebugProbeInput>(meta: T & (string extends T['probeId'] ? never : unknown)): IDebugProbeDefinition {
	const issueRef = meta.issueRef ?? meta.issue;
	if (!issueRef) {
		throw new Error(`defineDebugProbe(${meta.probeId}): issueRef (or issue) is required`);
	}
	if (!meta.probeId.startsWith('dbg-')) {
		throw new Error(`defineDebugProbe: probeId must start with 'dbg-': ${meta.probeId}`);
	}

	let ttlDays = meta.ttlDays;
	let expiresAt = meta.expiresAt;
	if (ttlDays === undefined && expiresAt === undefined) {
		throw new Error(`defineDebugProbe(${meta.probeId}): ttlDays or expiresAt is required`);
	}
	if (ttlDays === undefined && expiresAt !== undefined) {
		ttlDays = daysBetween(meta.createdAt, expiresAt);
	}
	if (expiresAt === undefined && ttlDays !== undefined) {
		expiresAt = addDaysIso(meta.createdAt, ttlDays);
	}
	if (ttlDays === undefined || expiresAt === undefined) {
		throw new Error(`defineDebugProbe(${meta.probeId}): failed to resolve ttlDays/expiresAt`);
	}
	if (!Number.isFinite(ttlDays) || ttlDays <= 0) {
		throw new Error(`defineDebugProbe(${meta.probeId}): ttlDays must be a positive number`);
	}
	if (ttlDays > DEBUG_PROBE_MAX_TTL_DAYS) {
		throw new Error(`defineDebugProbe(${meta.probeId}): ttlDays ${ttlDays} exceeds max ${DEBUG_PROBE_MAX_TTL_DAYS}`);
	}
	const span = daysBetween(meta.createdAt, expiresAt);
	if (span > DEBUG_PROBE_MAX_TTL_DAYS) {
		throw new Error(`defineDebugProbe(${meta.probeId}): expiresAt is >${DEBUG_PROBE_MAX_TTL_DAYS}d from createdAt (${span}d)`);
	}

	return {
		probeId: meta.probeId,
		owner: meta.owner,
		createdAt: meta.createdAt,
		issueRef,
		issue: meta.issue ?? issueRef,
		ttlDays,
		expiresAt,
		comment: meta.comment,
		gdpr: meta.gdpr,
	};
}

export function isDebugProbeExpired(probe: Pick<IDebugProbeMetadata, 'expiresAt'>, nowMs: number = currentNowMs()): boolean {
	const exp = Date.parse(probe.expiresAt);
	if (!Number.isFinite(exp)) {
		return true; // fail closed
	}
	return nowMs > exp;
}

function emitViolation(violation: TelemetryGuardViolation): void {
	const line = formatTelemetryGuardViolation(violation);
	try {
		_violationSink?.(line);
	} catch {
		// Logging must never throw into the probe path.
	}
}

/**
 * Emit a debug probe event through the guarded first-party pipe.
 *
 * (a) no-op if past expiresAt (TTL);
 * (b) run detectTelemetryUserData(strictShape) — on hit, log violation + drop;
 * (c) stamp probeId, publicLog2(`debugProbe/<probeId>`, …).
 *
 * Payload type admits only number | boolean | enum-literal | OpaqueId.
 */
export function logDebugProbe<T extends Record<string, unknown>>(
	telemetryService: ITelemetryService,
	probe: IDebugProbeDefinition,
	data: SafeProbePayload<T> & T,
): void {
	if (isDebugProbeExpired(probe)) {
		return;
	}

	const eventName: DebugProbeEventName = `debugProbe/${probe.probeId}`;
	// Runtime backstop against `as any` / trusted-value smuggling.
	const guard = detectTelemetryUserData(data, {
		strictShape: true,
		eventName,
	});
	if (guard.hit) {
		emitViolation({
			timestamp: new Date().toISOString(),
			eventName,
			layer: guard.layer,
			detail: guard.detail,
			pluginHostTelemetry: false,
			pipe: 'core',
		});
		return;
	}

	const payload = {
		...data,
		probeId: probe.probeId,
	};
	telemetryService.publicLog2(eventName, payload as never);
}
