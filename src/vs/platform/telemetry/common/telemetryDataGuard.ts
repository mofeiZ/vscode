/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Fail-closed telemetry data guard (AnyArchive / H4).
 *
 * Pure detection helpers used at the two outbound choke points:
 * - TelemetryService._doLog (core / Path A)
 * - ExtHostTelemetryLogger (createTelemetryLogger / Path B)
 *
 * Extension-originated events use a strict-shape allowlist (opaque id / enum /
 * short token). Core first-party events keep the residual canary/path/secret
 * scan. On hit the caller must block the event and append a durable line to
 * telemetry-guard.log under extHostLogsPath.
 */

export type TelemetryGuardLayer = 'canary' | 'path' | 'secret' | 'shape';

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

export type TelemetryGuardDetectOptions = {
	readonly markers?: readonly string[];
	/**
	 * Full strict-shape allowlist (Path B / createTelemetryLogger): admit only
	 * opaque-id / enum / short-token strings; free-form rejected. Also enables
	 * measurement bounds + fail-closed depth.
	 */
	readonly strictShape?: boolean;
	/**
	 * Bound the numeric/measurements lane (char-code smuggling). Used for
	 * pluginHostTelemetry on Path A without applying the string allowlist that
	 * would break first-party EH events (activatePlugin, etc.).
	 */
	readonly boundMeasurements?: boolean;
	/** Fail closed when flatten aborts at max depth. */
	readonly failClosedOnDepthAbort?: boolean;
	/** Scanned + redacted separately from the payload. */
	readonly eventName?: string;
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

/** Slash / path-separator homoglyphs → ASCII `/` after NFKC. */
const SLASH_HOMOGLYPH_RE = /[\uFF0F\u2044\u2215\u2571\u27CB\u29F8\uFE68]/g;

const MAX_VISIT_DEPTH = 8;
/** Bound measurements lane so char-code arrays cannot smuggle paths (rt1#1). */
const MAX_STRICT_NUMERIC_LEAVES = 24;
const MAX_STRICT_NUMBER_ARRAY_LEN = 12;

/** Opaque id / enum / short token — no whitespace, no path separators. */
const SAFE_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/;
const SAFE_VERSION_RE = /^\d+\.\d+(\.\d+)?(-[A-Za-z0-9.+_-]+)?$/;
const SAFE_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function canonicalizeTelemetryString(value: string): string {
	return value.normalize('NFKC').replace(SLASH_HOMOGLYPH_RE, '/').replace(/\\/g, '/');
}

function tryDecodeBase64(value: string): string | undefined {
	if (value.length < 8 || value.length > 4096 || value.length % 4 !== 0) {
		return undefined;
	}
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
		return undefined;
	}
	try {
		if (typeof globalThis.atob === 'function') {
			const decoded = globalThis.atob(value);
			return decoded.length > 0 ? decoded : undefined;
		}
	} catch {
		// fall through
	}
	try {
		// Node / Electron unit-test host
		const buf = (globalThis as unknown as { Buffer?: { from(s: string, e: string): { toString(e: string): string } } }).Buffer;
		if (buf) {
			const decoded = buf.from(value, 'base64').toString('utf8');
			return decoded.length > 0 ? decoded : undefined;
		}
	} catch {
		// ignore
	}
	return undefined;
}

function tryDecodeHex(value: string): string | undefined {
	const hex = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
	if (hex.length < 8 || hex.length > 4096 || hex.length % 2 !== 0) {
		return undefined;
	}
	if (!/^[0-9a-fA-F]+$/.test(hex)) {
		return undefined;
	}
	try {
		let out = '';
		for (let i = 0; i < hex.length; i += 2) {
			out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
		}
		return out.length > 0 ? out : undefined;
	} catch {
		return undefined;
	}
}

function tryDecodeUrl(value: string): string | undefined {
	if (!/%[0-9a-fA-F]{2}/.test(value)) {
		return undefined;
	}
	try {
		return decodeURIComponent(value);
	} catch {
		return undefined;
	}
}

function expandEncodedCandidates(value: string): string[] {
	const out: string[] = [];
	const b64 = tryDecodeBase64(value);
	if (b64 !== undefined) {
		out.push(b64);
	}
	const hex = tryDecodeHex(value);
	if (hex !== undefined) {
		out.push(hex);
	}
	const url = tryDecodeUrl(value);
	if (url !== undefined && url !== value) {
		out.push(url);
	}
	return out;
}

function isTypedNumberArray(value: object): value is ArrayLike<number> {
	return ArrayBuffer.isView(value) && !(value instanceof DataView);
}

export type FlattenTelemetryStringsResult = {
	readonly strings: string[];
	readonly numericLeafCount: number;
	readonly depthAborted: boolean;
	readonly oversizedNumberArray: boolean;
};

/**
 * Flatten nested telemetry payloads into string leaf values for scanning.
 * Visits non-enumerable own props, Map/Set, typed arrays; canonicalizes and
 * candidate-decodes string leaves; synthesizes strings from dense char-code
 * number arrays for residual path/secret scanning.
 */
export function flattenTelemetryStringsDetailed(data: unknown): FlattenTelemetryStringsResult {
	const out: string[] = [];
	let numericLeafCount = 0;
	let depthAborted = false;
	let oversizedNumberArray = false;

	const pushString = (raw: string): void => {
		if (raw.length === 0) {
			return;
		}
		const canonical = canonicalizeTelemetryString(raw);
		out.push(canonical);
		for (const decoded of expandEncodedCandidates(canonical)) {
			out.push(canonicalizeTelemetryString(decoded));
		}
	};

	const visitNumberArray = (nums: ArrayLike<number>): void => {
		if (nums.length > MAX_STRICT_NUMBER_ARRAY_LEN) {
			oversizedNumberArray = true;
		}
		// Dense code-unit arrays (rt1#1 / #6): rebuild candidate string.
		if (nums.length >= 4) {
			let allCodeUnits = true;
			let built = '';
			const limit = Math.min(nums.length, 4096);
			for (let i = 0; i < limit; i++) {
				const n = nums[i];
				if (typeof n !== 'number' || !Number.isInteger(n) || n < 0 || n > 0x10ffff) {
					allCodeUnits = false;
					break;
				}
				built += String.fromCodePoint(n);
			}
			if (allCodeUnits && built.length > 0) {
				pushString(built);
			}
		}
	};

	const visit = (value: unknown, depth: number): void => {
		if (value === null || value === undefined) {
			return;
		}
		if (depth > MAX_VISIT_DEPTH) {
			depthAborted = true;
			return;
		}
		if (typeof value === 'string') {
			pushString(value);
			return;
		}
		if (typeof value === 'number' || typeof value === 'boolean') {
			if (typeof value === 'number') {
				numericLeafCount++;
			}
			return;
		}
		if (typeof value === 'bigint') {
			numericLeafCount++;
			return;
		}
		if (Array.isArray(value)) {
			if (value.length > 0 && value.every(v => typeof v === 'number')) {
				numericLeafCount += value.length;
				visitNumberArray(value);
				return;
			}
			for (const item of value) {
				visit(item, depth + 1);
			}
			return;
		}
		if (typeof value === 'object') {
			if (value instanceof Map) {
				for (const [k, v] of value.entries()) {
					visit(k, depth + 1);
					visit(v, depth + 1);
				}
				return;
			}
			if (value instanceof Set) {
				for (const v of value.values()) {
					visit(v, depth + 1);
				}
				return;
			}
			if (isTypedNumberArray(value)) {
				numericLeafCount += value.length;
				visitNumberArray(value);
				return;
			}
			const record = value as Record<string, unknown>;
			if (Object.prototype.hasOwnProperty.call(record, 'isTrustedTelemetryValue') && 'value' in record) {
				visit(record.value, depth + 1);
				return;
			}
			// Align with validateTelemetryData flatten (getOwnPropertyNames).
			for (const key of Object.getOwnPropertyNames(record)) {
				visit(record[key], depth + 1);
			}
			return;
		}
	};

	visit(data, 0);

	// Rejoin fragments so split-field / array smuggling still hits path/canary (rt1#4).
	// Only synthesize an absolute-looking join when fragments look like path segments
	// (e.g. Users/alice/…); blindly prefixing '/' caused false positives on ordinary
	// opaque tokens like extname + version.
	const leaves = out.slice();
	if (leaves.length > 1) {
		out.push(leaves.join('\0'));
		out.push(leaves.join(''));
		// Slash-join only when fragments look like path segments. A naive
		// join('/') on ordinary tokens (Error + test-error) false-positives the
		// broad ABS_PATH_RE via a `/a/b` substring.
		const pathSegment = (s: string): boolean =>
			/^(Users|home|tmp|var|private)$/i.test(s)
			|| s.startsWith('/')
			|| s.startsWith('Users/')
			|| s.startsWith('home/')
			|| s.startsWith('tmp/')
			|| /^[A-Za-z]:$/.test(s)
			|| /^[A-Za-z]:\\/.test(s);
		if (leaves.some(pathSegment)) {
			const joined = leaves.join('/');
			out.push(joined.startsWith('/') ? joined : '/' + joined);
		}
	}

	return { strings: out, numericLeafCount, depthAborted, oversizedNumberArray };
}

/**
 * Flatten nested telemetry payloads into string leaf values for scanning.
 */
export function flattenTelemetryStrings(data: unknown): string[] {
	return flattenTelemetryStringsDetailed(data).strings;
}

function looksLikePath(value: string): boolean {
	if (!value.includes('/')) {
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

export function isAllowedExtensionTelemetryString(value: string): boolean {
	if (value.length === 0 || value.length > 128) {
		return false;
	}
	if (value.includes('/') || /\s/.test(value)) {
		return false;
	}
	return SAFE_TOKEN_RE.test(value) || SAFE_VERSION_RE.test(value) || SAFE_UUID_RE.test(value);
}

function scanStrings(strings: readonly string[], markers: readonly string[]): TelemetryGuardResult {
	const usableMarkers = markers.filter(m => typeof m === 'string' && m.length >= 3)
		.map(m => canonicalizeTelemetryString(m));

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

/**
 * Detect user data that must not leave via telemetry.
 * Layer order: canary/marker → path → secret → (strict) shape / measurement bounds.
 */
export function detectTelemetryUserData(
	data: unknown,
	markersOrOptions: readonly string[] | TelemetryGuardDetectOptions = [],
	maybeOptions?: TelemetryGuardDetectOptions,
): TelemetryGuardResult {
	const options: TelemetryGuardDetectOptions = Array.isArray(markersOrOptions)
		? { ...(maybeOptions ?? {}), markers: markersOrOptions }
		: markersOrOptions;
	const markers = options.markers ?? [];
	const strictShape = !!options.strictShape;
	const boundMeasurements = strictShape || !!options.boundMeasurements;
	const failClosedOnDepthAbort = strictShape || !!options.failClosedOnDepthAbort;

	const flat = flattenTelemetryStringsDetailed(data);
	const strings = [...flat.strings];
	if (typeof options.eventName === 'string' && options.eventName.length > 0) {
		strings.push(...flattenTelemetryStringsDetailed(options.eventName).strings);
	}

	if (failClosedOnDepthAbort && flat.depthAborted) {
		return { hit: true, layer: 'shape', detail: '<REDACTED: depth-limit>' };
	}
	if (boundMeasurements && (flat.oversizedNumberArray || flat.numericLeafCount > MAX_STRICT_NUMERIC_LEAVES)) {
		return { hit: true, layer: 'shape', detail: '<REDACTED: measurements-bound>' };
	}

	const residual = scanStrings(strings, markers);
	if (residual.hit) {
		return residual;
	}

	if (strictShape) {
		// Allowlist: every leaf string (and decoded candidates) must be an opaque token.
		for (const s of collectRawCanonicalLeaves(data)) {
			if (!isAllowedExtensionTelemetryString(s)) {
				return { hit: true, layer: 'shape', detail: '<REDACTED: disallowed-string-shape>' };
			}
		}
		if (typeof options.eventName === 'string' && options.eventName.length > 0) {
			for (const part of options.eventName.split('/')) {
				const canonical = canonicalizeTelemetryString(part);
				if (canonical.length > 0 && !isAllowedExtensionTelemetryString(canonical)) {
					return { hit: true, layer: 'shape', detail: '<REDACTED: disallowed-event-name>' };
				}
			}
		}
	}

	return { hit: false };
}

function collectRawCanonicalLeaves(data: unknown): string[] {
	const out: string[] = [];
	const visit = (value: unknown, depth: number): void => {
		if (value === null || value === undefined || depth > MAX_VISIT_DEPTH) {
			return;
		}
		if (typeof value === 'string') {
			if (value.length > 0) {
				out.push(canonicalizeTelemetryString(value));
				for (const decoded of expandEncodedCandidates(canonicalizeTelemetryString(value))) {
					out.push(canonicalizeTelemetryString(decoded));
				}
			}
			return;
		}
		if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
			return;
		}
		if (Array.isArray(value)) {
			if (value.length > 0 && value.every(v => typeof v === 'number')) {
				return;
			}
			for (const item of value) {
				visit(item, depth + 1);
			}
			return;
		}
		if (typeof value === 'object') {
			if (value instanceof Map) {
				for (const [k, v] of value.entries()) {
					visit(k, depth + 1);
					visit(v, depth + 1);
				}
				return;
			}
			if (value instanceof Set) {
				for (const v of value.values()) {
					visit(v, depth + 1);
				}
				return;
			}
			if (isTypedNumberArray(value)) {
				return;
			}
			const record = value as Record<string, unknown>;
			if (Object.prototype.hasOwnProperty.call(record, 'isTrustedTelemetryValue') && 'value' in record) {
				visit(record.value, depth + 1);
				return;
			}
			for (const key of Object.getOwnPropertyNames(record)) {
				visit(record[key], depth + 1);
			}
		}
	};
	visit(data, 0);
	return out;
}

/**
 * Redact a telemetry event name before persisting it to telemetry-guard.log (F2).
 */
export function redactTelemetryGuardEventName(eventName: string): string {
	const guard = detectTelemetryUserData({ eventName }, [], { strictShape: false });
	if (guard.hit) {
		return `<REDACTED: event-name:${guard.layer}>`;
	}
	// Also catch free-form path/secret-only names that scan as the sole string.
	const flat = flattenTelemetryStringsDetailed(eventName);
	const residual = scanStrings(flat.strings, []);
	if (residual.hit) {
		return `<REDACTED: event-name:${residual.layer}>`;
	}
	return eventName;
}

/**
 * Scrub a single EH stdout/stderr line before durable persistence (F1).
 * Preserves crash-diagnostic structure while removing home/tmp paths and secrets.
 * Avoids the broad ABS_PATH_RE (it false-positives on https://… URLs).
 */
export function scrubPersistedExtensionHostLogLine(line: string): string {
	if (!line) {
		return line;
	}
	let out = line;
	out = out.replace(ABS_UNIX_HOME_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_WIN_HOME_RE, ' <REDACTED: user-file-path>');
	out = out.replace(/(?:^|[\s"'=`])(\/(?:tmp|private\/tmp)\/[^\s"'`]+)/g, ' <REDACTED: user-file-path>');
	// Homoglyph / NFKC: redact individual tokens whose canonical form is a home/tmp path.
	out = out.replace(/\S+/g, token => {
		const canonical = canonicalizeTelemetryString(token);
		if (ABS_UNIX_HOME_RE.test(canonical) || ABS_WIN_HOME_RE.test(canonical)) {
			return '<REDACTED: user-file-path>';
		}
		if (/^\/(?:Users|home|tmp|private\/tmp)\//.test(canonical)) {
			return '<REDACTED: user-file-path>';
		}
		return token;
	});
	// Secret pass with placeholder protection so a label like "GitHub Token"
	// is not re-matched by the Generic Secret `(token)[^A-Za-z0-9]` heuristic.
	const held: string[] = [];
	const hold = (marker: string): string => {
		held.push(marker);
		return `\0H${held.length - 1}\0`;
	};
	out = out.replace(/<REDACTED:[^>]*>/g, m => hold(m));
	for (const entry of SECRET_REGEXES) {
		out = out.replace(entry.regex, () => hold(`<REDACTED: ${entry.label}>`));
	}
	out = out.replace(/\0H(\d+)\0/g, (_, i) => held[Number(i)] ?? '');
	return out;
}

/** One structured line for telemetry-guard.log (no raw secrets / paths in event). */
export function formatTelemetryGuardViolation(v: TelemetryGuardViolation): string {
	return JSON.stringify({
		ts: v.timestamp,
		event: redactTelemetryGuardEventName(v.eventName),
		layer: v.layer,
		detail: v.detail,
		pluginHostTelemetry: v.pluginHostTelemetry,
		extensionId: v.extensionId ?? null,
		pipe: v.pipe,
		action: 'blocked',
	});
}
