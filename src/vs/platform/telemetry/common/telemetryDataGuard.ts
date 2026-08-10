/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Fail-closed telemetry data guard (AnyArchive / H4).
 *
 * Pure detection helpers used at the two outbound choke points:
 * - TelemetryService._doLog (core / Path A)
 * - ExtHostTelemetryLogger.logEvent (createTelemetryLogger / Path B)
 *
 * On hit the caller must block the event (no appender / no sender) and append a
 * durable line to telemetry-guard.log under extHostLogsPath.
 */

export type TelemetryGuardLayer = 'canary' | 'path' | 'secret';

export type TelemetryGuardHit = {
	readonly hit: true;
	readonly layer: TelemetryGuardLayer;
	/** Redacted evidence only — never the raw secret / full path. */
	readonly detail: string;
};

export type TelemetryGuardMiss = {
	readonly hit: false;
};

export type TelemetryGuardResult = TelemetryGuardHit | TelemetryGuardMiss;

export type TelemetryGuardViolation = {
	readonly timestamp: string;
	readonly eventName: string;
	readonly layer: TelemetryGuardLayer;
	readonly detail: string;
	readonly pluginHostTelemetry: boolean;
	readonly extensionId?: string;
	readonly pipe: 'core' | 'extHost';
};

/** Absolute user-home style paths (desk-gnome ABS_UNIX / ABS_WIN ideas). */
const ABS_UNIX_HOME_RE = /(?:^|[\s"'=`])(\/(?:Users|home)\/[^\s"'`]+)/;
const ABS_WIN_HOME_RE = /(?:^|[\s"'=`])([A-Za-z]:\\Users\\[^\s"'`]+)/;
/**
 * Broader absolute path shape (aligned with anonymizeFilePaths fileRegex):
 * catches /tmp/... workspace roots used in disposable OSS proof runs.
 */
const ABS_PATH_RE = /(?:file:\/\/)?(?:[a-zA-Z]:(?:\\\\|\\|\/)|(?:\\\\|\\|\/))(?:[\w\-\._@]+(?:\\\\|\\|\/))+[\w\-\._@]+/;

const SECRET_REGEXES: ReadonlyArray<{ label: string; regex: RegExp }> = [
	{ label: 'GitHub Token', regex: /(gh[psuro]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/ },
	{ label: 'Slack Token', regex: /xox[pbar]\-[A-Za-z0-9]/ },
	{ label: 'Generic Secret', regex: /(key|token|sig|secret|signature|password|passwd|pwd)[^a-zA-Z0-9]/i },
];

/**
 * Flatten nested telemetry payloads into string leaf values for scanning.
 */
export function flattenTelemetryStrings(data: unknown): string[] {
	const out: string[] = [];
	const visit = (value: unknown, depth: number): void => {
		if (depth > 8 || value === null || value === undefined) {
			return;
		}
		if (typeof value === 'string') {
			if (value.length > 0) {
				out.push(value);
			}
			return;
		}
		if (typeof value === 'number' || typeof value === 'boolean') {
			return;
		}
		if (Array.isArray(value)) {
			for (const item of value) {
				visit(item, depth + 1);
			}
			return;
		}
		if (typeof value === 'object') {
			// TelemetryTrustedValue / similar: scan .value if present
			const record = value as Record<string, unknown>;
			if (Object.prototype.hasOwnProperty.call(record, 'isTrustedTelemetryValue') && 'value' in record) {
				visit(record.value, depth + 1);
				return;
			}
			for (const key of Object.keys(record)) {
				visit(record[key], depth + 1);
			}
		}
	};
	visit(data, 0);
	return out;
}

function looksLikePath(value: string): boolean {
	if (!value.includes('/') && !value.includes('\\')) {
		return false;
	}
	return ABS_UNIX_HOME_RE.test(value) || ABS_WIN_HOME_RE.test(value) || ABS_PATH_RE.test(value);
}

function detectSecret(value: string): string | undefined {
	for (const entry of SECRET_REGEXES) {
		if (entry.regex.test(value)) {
			return entry.label;
		}
	}
	return undefined;
}

/**
 * Detect user data that must not leave via telemetry.
 * Layer order: canary/marker includes → path shape → secret shape.
 */
export function detectTelemetryUserData(data: unknown, markers: readonly string[] = []): TelemetryGuardResult {
	const strings = flattenTelemetryStrings(data);
	const usableMarkers = markers.filter(m => typeof m === 'string' && m.length >= 3);

	for (const s of strings) {
		for (const marker of usableMarkers) {
			if (s.includes(marker)) {
				return { hit: true, layer: 'canary', detail: '<REDACTED: canary-marker>' };
			}
		}
	}

	for (const s of strings) {
		if (looksLikePath(s)) {
			return { hit: true, layer: 'path', detail: '<REDACTED: user-file-path>' };
		}
	}

	for (const s of strings) {
		const label = detectSecret(s);
		if (label) {
			return { hit: true, layer: 'secret', detail: `<REDACTED: ${label}>` };
		}
	}

	return { hit: false };
}

/** One structured line for telemetry-guard.log (no raw secrets). */
export function formatTelemetryGuardViolation(v: TelemetryGuardViolation): string {
	return JSON.stringify({
		ts: v.timestamp,
		event: v.eventName,
		layer: v.layer,
		detail: v.detail,
		pluginHostTelemetry: v.pluginHostTelemetry,
		extensionId: v.extensionId ?? null,
		pipe: v.pipe,
		action: 'blocked',
	});
}
