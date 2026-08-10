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
/**
 * Extra absolute roots that must not persist in EH stderr (beyond home/tmp).
 * Kept separate from ABS_PATH_RE so URL-like strings are not over-redacted in
 * residual telemetry scanning.
 */
const ABS_UNIX_SENSITIVE_ROOT_RE = /(?:^|[\s"'=`])(\/(?:Users|home|tmp|private\/tmp|opt|var\/folders|var\/tmp|etc|root)\/[^\s"'`]+)/;
const ABS_WIN_ANY_DRIVE_RE = /(?:^|[\s"'=`])([A-Za-z]:\\(?:Users\\|[^\\\s"'`]+\\)[^\s"'`]+)/;

const SECRET_REGEXES: ReadonlyArray<{ label: string; regex: RegExp }> = [
	{ label: 'GitHub Token', regex: /(gh[psuro]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/ },
	{ label: 'Slack Token', regex: /xox[pbar]\-[A-Za-z0-9]/ },
	{ label: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
	{ label: 'Generic Secret', regex: /(key|token|sig|secret|signature|password|passwd|pwd)[^a-zA-Z0-9]/i },
];

/** Indexed char-code object keys: c0..cN or bare 0..N. */
const CHAR_CODE_KEY_RE = /^c?(\d+)$/;

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

function isCodeUnitNumber(n: unknown): n is number {
	return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 0x10ffff;
}

type NumericObjectReassembly = {
	readonly built?: string;
	readonly codeUnitCount: number;
	/** Contiguous c0..cN / 0..N keys — char-code smuggling shape (sr1#2). */
	readonly indexedCharCodeShape: boolean;
};

/**
 * Rebuild a candidate string from dense/indexed numeric object shapes
 * (sr1#2: `{ c0:47, c1:85, ... }` under the 24-leaf cap).
 */
function tryReassembleNumericObject(record: Record<string, unknown>): NumericObjectReassembly {
	const names = Object.getOwnPropertyNames(record);
	if (names.length === 0) {
		return { codeUnitCount: 0, indexedCharCodeShape: false };
	}

	const indexed: { idx: number; n: number }[] = [];
	const plainCodeUnits: number[] = [];
	let allValuesAreCodeUnits = true;

	for (const key of names) {
		const v = record[key];
		if (!isCodeUnitNumber(v)) {
			allValuesAreCodeUnits = false;
			break;
		}
		plainCodeUnits.push(v);
		const m = CHAR_CODE_KEY_RE.exec(key);
		if (m) {
			indexed.push({ idx: Number(m[1]), n: v });
		}
	}

	if (!allValuesAreCodeUnits) {
		return { codeUnitCount: 0, indexedCharCodeShape: false };
	}

	const codeUnitCount = plainCodeUnits.length;

	if (indexed.length >= 4 && indexed.length === names.length) {
		indexed.sort((a, b) => a.idx - b.idx);
		let contiguous = true;
		for (let i = 1; i < indexed.length; i++) {
			if (indexed[i].idx !== indexed[i - 1].idx + 1) {
				contiguous = false;
				break;
			}
		}
		if (contiguous) {
			const built = indexed.map(e => String.fromCodePoint(e.n)).join('');
			return { built, codeUnitCount, indexedCharCodeShape: true };
		}
	}

	// Dense all-numeric-value object (no/partial index keys): stable key order.
	// Scanned as a candidate string but not fail-closed (ordinary measurements).
	if (plainCodeUnits.length >= 4) {
		const sortedKeys = names.slice().sort();
		const built = sortedKeys.map(k => String.fromCodePoint(record[k] as number)).join('');
		return { built, codeUnitCount, indexedCharCodeShape: false };
	}

	return { codeUnitCount, indexedCharCodeShape: false };
}

export type FlattenTelemetryStringsResult = {
	readonly strings: string[];
	readonly numericLeafCount: number;
	readonly depthAborted: boolean;
	readonly oversizedNumberArray: boolean;
	/** Contiguous indexed char-code object (`c0`..`cN`) seen (sr1#2). */
	readonly indexedCharCodeObject: boolean;
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
	let indexedCharCodeObject = false;

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
				if (!isCodeUnitNumber(n)) {
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

			// sr1#2: reassemble contiguous/dense numeric object shapes before
			// walking leaves so `{ c0:47, c1:85, ... }` is scanned as a string.
			const reassembled = tryReassembleNumericObject(record);
			if (reassembled.indexedCharCodeShape) {
				indexedCharCodeObject = true;
				// Property-name-derived index slots count toward the numeric budget
				// (keys like c0..cN are part of the smuggling channel).
				numericLeafCount += reassembled.codeUnitCount;
				if (reassembled.codeUnitCount > MAX_STRICT_NUMBER_ARRAY_LEN) {
					oversizedNumberArray = true;
				}
				if (reassembled.built) {
					pushString(reassembled.built);
				}
				for (const key of Object.getOwnPropertyNames(record)) {
					pushString(key);
				}
				return;
			}
			if (reassembled.built) {
				// Non-indexed all-numeric object: scan reconstructed candidate,
				// then fall through so ordinary measurement leaves still count.
				pushString(reassembled.built);
			}

			// Align with validateTelemetryData flatten (getOwnPropertyNames).
			// sr1#1: scan canonicalized own-property names, not only values.
			for (const key of Object.getOwnPropertyNames(record)) {
				pushString(key);
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
			/^(Users|home|tmp|var|private|opt)$/i.test(s)
			|| s.startsWith('/')
			|| s.startsWith('Users/')
			|| s.startsWith('home/')
			|| s.startsWith('tmp/')
			|| s.startsWith('opt/')
			|| s.startsWith('var/')
			|| /^[A-Za-z]:$/.test(s)
			|| /^[A-Za-z]:\\/.test(s);
		if (leaves.some(pathSegment)) {
			const joined = leaves.join('/');
			out.push(joined.startsWith('/') ? joined : '/' + joined);
		}
	}

	return { strings: out, numericLeafCount, depthAborted, oversizedNumberArray, indexedCharCodeObject };
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
	if (boundMeasurements && (
		flat.oversizedNumberArray
		|| flat.numericLeafCount > MAX_STRICT_NUMERIC_LEAVES
		// sr1#2: indexed char-code objects are a measurements-lane smuggling
		// channel even when leaf count is under the cap.
		|| flat.indexedCharCodeObject
	)) {
		return { hit: true, layer: 'shape', detail: '<REDACTED: measurements-bound>' };
	}

	const residual = scanStrings(strings, markers);
	if (residual.hit) {
		return residual;
	}

	if (strictShape) {
		// Allowlist: every leaf string, own-property name, and decoded candidate
		// must be an opaque token (sr1#1: keys are in scope).
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
	const push = (value: string): void => {
		if (value.length === 0) {
			return;
		}
		const canonical = canonicalizeTelemetryString(value);
		out.push(canonical);
		for (const decoded of expandEncodedCandidates(canonical)) {
			out.push(canonicalizeTelemetryString(decoded));
		}
	};
	const visit = (value: unknown, depth: number): void => {
		if (value === null || value === undefined || depth > MAX_VISIT_DEPTH) {
			return;
		}
		if (typeof value === 'string') {
			push(value);
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
				// sr1#1: every own key must pass the allowlist. Check the key itself
				// only — do not expand accidental base64/hex decodes of ordinary
				// tokens like "duration" (those still go through residual scan via
				// flattenTelemetryStringsDetailed).
				if (key.length > 0) {
					out.push(canonicalizeTelemetryString(key));
				}
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

function simpleHashPrefix(value: string): string {
	// Non-crypto stable fingerprint for persisted EH lines (sr1#4 fail-closed).
	let h = 2166136261;
	for (let i = 0; i < value.length; i++) {
		h ^= value.charCodeAt(i);
		h = Math.imul(h, 16777619);
	}
	return (h >>> 0).toString(16).padStart(8, '0');
}

function tokenLooksLikeAbsolutePath(canonical: string): boolean {
	if (!canonical.includes('/') && !canonical.includes('\\')) {
		return false;
	}
	if (
		ABS_UNIX_HOME_RE.test(canonical)
		|| ABS_WIN_HOME_RE.test(canonical)
		|| ABS_UNIX_SENSITIVE_ROOT_RE.test(canonical)
		|| ABS_WIN_ANY_DRIVE_RE.test(canonical)
	) {
		return true;
	}
	return /^\/(?:Users|home|tmp|private\/tmp|opt|var\/folders|var\/tmp|etc|root)\//.test(canonical)
		|| /^[A-Za-z]:[\\/]/.test(canonical);
}

function tokenLooksLikeUserContent(canonical: string): boolean {
	if (canonical.length >= 160) {
		return true;
	}
	// High-entropy / encoded blobs (base64-like) that survived decode-before-scan.
	if (canonical.length >= 48 && /^[A-Za-z0-9+/=_-]+$/.test(canonical) && /[A-Za-z]/.test(canonical) && /\d/.test(canonical)) {
		return true;
	}
	return false;
}

/**
 * Scrub a single EH stdout/stderr line before durable persistence (F1 / sr1#4).
 * Decode-before-scan (base64/hex/url), expand path roots beyond home/tmp, and
 * fail closed on residual user-content / secret-shaped tokens. Crash markers and
 * short diagnostic structure survive; raw paths/contents/secrets do not.
 */
export function scrubPersistedExtensionHostLogLine(line: string): string {
	if (!line) {
		return line;
	}
	let out = line;
	out = out.replace(ABS_UNIX_SENSITIVE_ROOT_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_UNIX_HOME_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_WIN_ANY_DRIVE_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_WIN_HOME_RE, ' <REDACTED: user-file-path>');
	out = out.replace(/(?:^|[\s"'=`])(\/(?:tmp|private\/tmp)\/[^\s"'`]+)/g, ' <REDACTED: user-file-path>');

	// Per-token: canonicalize, decode-before-scan, redact paths/secrets/content.
	out = out.replace(/\S+/g, token => {
		const canonical = canonicalizeTelemetryString(token);
		const candidates = [canonical, ...expandEncodedCandidates(canonical).map(canonicalizeTelemetryString)];
		for (const candidate of candidates) {
			if (tokenLooksLikeAbsolutePath(candidate)) {
				return '<REDACTED: user-file-path>';
			}
			const secret = detectSecret(candidate);
			if (secret) {
				return `<REDACTED: ${secret}>`;
			}
		}
		if (candidates.some(tokenLooksLikeUserContent)) {
			return `<REDACTED: content:${simpleHashPrefix(canonical)}>`;
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

	// Fail closed: if the line still carries an absolute path shape, hash it.
	const residualCanonical = canonicalizeTelemetryString(out);
	if (ABS_PATH_RE.test(residualCanonical) || ABS_UNIX_SENSITIVE_ROOT_RE.test(residualCanonical) || ABS_WIN_ANY_DRIVE_RE.test(residualCanonical)) {
		const prefix = out.slice(0, 80).replace(/\s+/g, ' ');
		return `${prefix.slice(0, 40)}… <REDACTED: line:${simpleHashPrefix(line)}>`;
	}
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
