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
	/** Fail closed when flatten aborts at max depth or visit budget. */
	readonly failClosedOnDepthAbort?: boolean;
	/** Scanned + redacted separately from the payload. */
	readonly eventName?: string;
};

/** Absolute user-home style paths (desk-gnome ABS_UNIX / ABS_WIN ideas). */
const ABS_UNIX_HOME_RE = /(?:^|[\s"'=`\[(])(\/(?:Users|home)\/[^\s"'`\]]+(?:\s+[^\s"'`\]]+(?:\/[^\s"'`\]]*)*)*)/g;
const ABS_WIN_HOME_RE = /(?:^|[\s"'=`\[(])([A-Za-z]:\\Users\\[^\s"'`\]]+(?:\s+[^\s"'`\]]+(?:\\[^\s"'`\]]*)*)*)/g;
/**
 * Extra absolute roots that must not persist in EH stderr (beyond home/tmp).
 * Rooted so URL-like strings and relative stack frames are not over-redacted
 * (sr2 FP2/FP5). `[`/`(` delimiters cover stack frames like `[/opt/homebrew/...]`.
 */
const ABS_UNIX_SENSITIVE_ROOT_RE = /(?:^|[\s"'=`\[(])(\/(?:Users|home|tmp|private\/tmp|opt|var\/folders|var\/tmp|etc|root)\/[^\s"'`\]]+(?:\s+[^\s"'`\]]+(?:\/[^\s"'`\]]*)*)*)/g;
const ABS_WIN_ANY_DRIVE_RE = /(?:^|[\s"'=`\[(])([A-Za-z]:\\(?:Users\\|[^\\\s"'`\]]+\\)[^\s"'`\]]+(?:\s+[^\s"'`\]]+(?:\\[^\s"'`\]]*)*)*)/g;
const ABS_UNIX_TMP_RE = /(?:^|[\s"'=`\[(])(\/(?:tmp|private\/tmp)\/[^\s"'`\]]+(?:\s+[^\s"'`\]]+(?:\/[^\s"'`\]]*)*)*)/g;
/** Mid-string rooted segment after canonicalize (scrub tokens, stack frames). */
const ABS_ROOTED_SEGMENT_RE = /\/(?:Users|home|tmp|private\/tmp|opt|var\/folders|var\/tmp|etc|root)\//;

/**
 * Generic Secret requires an assignment/value context so bare property names
 * like `key` / `sourceKey` / `reconnectionToken` are not convicted (sr2 FP1).
 */
const SECRET_REGEXES: ReadonlyArray<{ label: string; regex: RegExp }> = [
	{ label: 'GitHub Token', regex: /(gh[psuro]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/g },
	{ label: 'Slack Token', regex: /xox[pbar]\-[A-Za-z0-9-]+/g },
	{ label: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
	// Assignment context; allow `_`/`-` prefix so `api_key=` hits, but not `monkey=`.
	{ label: 'Generic Secret', regex: /(?:^|[^A-Za-z0-9])(key|token|sig|secret|signature|password|passwd|pwd)\s*[:=]\s*\S/gi },
];

/** Indexed char-code object keys: c0..cN or bare 0..N. */
const CHAR_CODE_KEY_RE = /^c?(\d+)$/;

/** Slash / path-separator homoglyphs → ASCII `/` after NFKC. */
const SLASH_HOMOGLYPH_RE = /[\uFF0F\u2044\u2215\u2571\u27CB\u29F8\uFE68]/g;

const MAX_VISIT_DEPTH = 8;
/** Bound measurements lane so char-code arrays cannot smuggle paths (rt1#1). */
const MAX_STRICT_CODE_UNIT_LEAVES = 24;
const MAX_STRICT_BOOLEAN_LEAVES = 48;
const MAX_STRICT_NUMBER_ARRAY_LEN = 12;
/** DoS caps (sr2 D1): DAG fanout amplification and huge leaf joins. */
const MAX_VISIT_NODES = 2048;
const MAX_VISIT_LEAVES = 512;
const MAX_REJOIN_CHARS = 8192;
/** Path B: opaque tokens longer than this are not legitimate enums (sr2 B1). */
const MAX_STRICT_TOKEN_LEN = 32;

/** Opaque id / enum / short token — no whitespace, no path separators. */
const SAFE_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/;
const SAFE_VERSION_RE = /^\d+\.\d+(\.\d+)?(-[A-Za-z0-9.+_-]+)?$/;
const SAFE_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** First-party event-name segments (`api/scm/createSourceControl`, dotted ids). */
const SAFE_EVENT_NAME_SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;

export function canonicalizeTelemetryString(value: string): string {
	return value.normalize('NFKC').replace(SLASH_HOMOGLYPH_RE, '/').replace(/\\/g, '/');
}

function tryDecodeBase64(value: string): string | undefined {
	// Normalize base64url / unpadded before length%4 and alphabet gates (sr2 B1).
	const norm = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
	if (norm.length < 8 || norm.length > 4096) {
		return undefined;
	}
	if (!/^[A-Za-z0-9+/]+$/.test(norm)) {
		return undefined;
	}
	const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4);
	try {
		if (typeof globalThis.atob === 'function') {
			const decoded = globalThis.atob(padded);
			return decoded.length > 0 ? decoded : undefined;
		}
	} catch {
		// fall through
	}
	try {
		// Node / Electron unit-test host
		const buf = (globalThis as unknown as { Buffer?: { from(s: string, e: string): { toString(e: string): string } } }).Buffer;
		if (buf) {
			const decoded = buf.from(padded, 'base64').toString('utf8');
			return decoded.length > 0 ? decoded : undefined;
		}
	} catch {
		// ignore
	}
	return undefined;
}

function tryDecodeHex(value: string): string | undefined {
	let raw = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
	// sr2 B1: stray "h" prefix used as an evasion.
	if (raw.length >= 9 && (raw[0] === 'h' || raw[0] === 'H') && /^[hH][0-9a-fA-F]+$/.test(raw)) {
		raw = raw.slice(1);
	}
	if (raw.length < 8 || raw.length > 4096) {
		return undefined;
	}
	if (!/^[0-9a-fA-F]+$/.test(raw)) {
		return undefined;
	}
	// Odd length: also try left-pad and drop-first (sr2 B1).
	const candidates = raw.length % 2 === 0 ? [raw] : ['0' + raw, raw.slice(1)];
	for (const hex of candidates) {
		if (hex.length < 8 || hex.length % 2 !== 0) {
			continue;
		}
		try {
			let out = '';
			for (let i = 0; i < hex.length; i += 2) {
				out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
			}
			if (out.length > 0) {
				return out;
			}
		} catch {
			// try next candidate
		}
	}
	return undefined;
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
 * (sr1#2 / sr2 B2). Budget counting is separate — this never aborts the
 * whole object because of one non-code-unit sibling.
 */
function tryReassembleNumericObject(record: Record<string, unknown>): NumericObjectReassembly {
	const names = Object.getOwnPropertyNames(record);
	if (names.length === 0) {
		return { codeUnitCount: 0, indexedCharCodeShape: false };
	}

	const indexed: { idx: number; n: number }[] = [];
	const plainInNameOrder: number[] = [];
	let codeUnitCount = 0;

	for (const key of names) {
		const v = record[key];
		if (!isCodeUnitNumber(v)) {
			continue;
		}
		codeUnitCount++;
		plainInNameOrder.push(v);
		const m = CHAR_CODE_KEY_RE.exec(key);
		if (m) {
			indexed.push({ idx: Number(m[1]), n: v });
		}
	}

	if (indexed.length >= 4) {
		indexed.sort((a, b) => a.idx - b.idx);
		const built = indexed.map(e => String.fromCodePoint(e.n)).join('');
		return { built, codeUnitCount, indexedCharCodeShape: true };
	}

	if (plainInNameOrder.length >= 4) {
		const built = plainInNameOrder.map(n => String.fromCodePoint(n)).join('');
		return { built, codeUnitCount, indexedCharCodeShape: false };
	}

	return { codeUnitCount, indexedCharCodeShape: false };
}

export type FlattenTelemetryStringsResult = {
	readonly strings: string[];
	/** Real leaves only — synthetic rejoins are excluded (sr2 FP1). */
	readonly leafStrings: string[];
	readonly codeUnitLeafCount: number;
	readonly booleanLeafCount: number;
	/** @deprecated use codeUnitLeafCount — kept for older call sites/tests */
	readonly numericLeafCount: number;
	readonly depthAborted: boolean;
	readonly budgetExceeded: boolean;
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
	let codeUnitLeafCount = 0;
	let booleanLeafCount = 0;
	let depthAborted = false;
	let budgetExceeded = false;
	let oversizedNumberArray = false;
	let indexedCharCodeObject = false;
	let nodeCount = 0;
	let leafCount = 0;
	const visited = new WeakSet<object>();
	/** Visit-order channel so wrapped/Map/split code units still reassemble. */
	const codeUnitChannel: number[] = [];

	const noteLeaf = (): boolean => {
		leafCount++;
		if (leafCount > MAX_VISIT_LEAVES) {
			budgetExceeded = true;
			return false;
		}
		return true;
	};

	const pushString = (raw: string): void => {
		if (raw.length === 0 || budgetExceeded || depthAborted) {
			return;
		}
		if (!noteLeaf()) {
			return;
		}
		const canonical = canonicalizeTelemetryString(raw);
		out.push(canonical);
		for (const decoded of expandEncodedCandidates(canonical)) {
			if (!noteLeaf()) {
				return;
			}
			out.push(canonicalizeTelemetryString(decoded));
		}
	};

	const noteCodeUnit = (n: number): void => {
		codeUnitLeafCount++;
		codeUnitChannel.push(n);
	};

	const rebuildCodeUnits = (nums: readonly number[]): void => {
		if (nums.length > MAX_STRICT_NUMBER_ARRAY_LEN) {
			oversizedNumberArray = true;
		}
		if (nums.length >= 4) {
			const limit = Math.min(nums.length, 4096);
			let built = '';
			for (let i = 0; i < limit; i++) {
				built += String.fromCodePoint(nums[i]);
			}
			if (built.length > 0) {
				pushString(built);
			}
		}
	};

	const visit = (value: unknown, depth: number): void => {
		if (value === null || value === undefined || budgetExceeded || depthAborted) {
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
		if (typeof value === 'boolean') {
			if (!noteLeaf()) {
				return;
			}
			booleanLeafCount++;
			return;
		}
		if (typeof value === 'number') {
			if (!noteLeaf()) {
				return;
			}
			// Only code-unit-range integers feed the smuggling budget (sr2 B2/FP3).
			if (isCodeUnitNumber(value)) {
				noteCodeUnit(value);
			}
			return;
		}
		if (typeof value === 'bigint') {
			if (!noteLeaf()) {
				return;
			}
			const asNumber = Number(value);
			if (Number.isSafeInteger(asNumber) && isCodeUnitNumber(asNumber)) {
				noteCodeUnit(asNumber);
			}
			return;
		}
		if (typeof value !== 'object') {
			return;
		}

		if (visited.has(value)) {
			return;
		}
		visited.add(value);
		nodeCount++;
		if (nodeCount > MAX_VISIT_NODES) {
			budgetExceeded = true;
			return;
		}

		if (Array.isArray(value)) {
			const codeUnits: number[] = [];
			for (const item of value) {
				if (budgetExceeded || depthAborted) {
					return;
				}
				if (isCodeUnitNumber(item)) {
					if (!noteLeaf()) {
						return;
					}
					noteCodeUnit(item);
					codeUnits.push(item);
				} else if (typeof item === 'boolean') {
					if (!noteLeaf()) {
						return;
					}
					booleanLeafCount++;
				} else {
					visit(item, depth + 1);
				}
			}
			if (codeUnits.length >= 4) {
				rebuildCodeUnits(codeUnits);
			}
			return;
		}

		if (value instanceof Map) {
			const codeUnits: number[] = [];
			for (const [k, v] of value.entries()) {
				if (budgetExceeded || depthAborted) {
					return;
				}
				visit(k, depth + 1);
				if (isCodeUnitNumber(v)) {
					if (!noteLeaf()) {
						return;
					}
					noteCodeUnit(v);
					codeUnits.push(v);
				} else {
					visit(v, depth + 1);
				}
			}
			if (codeUnits.length >= 4) {
				rebuildCodeUnits(codeUnits);
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
			const codeUnits: number[] = [];
			const limit = Math.min(value.length, 4096);
			for (let i = 0; i < limit; i++) {
				const n = value[i];
				if (isCodeUnitNumber(n)) {
					if (!noteLeaf()) {
						return;
					}
					noteCodeUnit(n);
					codeUnits.push(n);
				}
			}
			if (codeUnits.length >= 4) {
				rebuildCodeUnits(codeUnits);
			}
			return;
		}

		const record = value as Record<string, unknown>;
		// Trusted-value unwrap matches cleanData (telemetryUtils), which collapses
		// the same shape to `value` and drops sibling own props. If cleanData ever
		// starts forwarding siblings, this early return becomes a leak surface.
		if (Object.prototype.hasOwnProperty.call(record, 'isTrustedTelemetryValue') && 'value' in record) {
			visit(record.value, depth + 1);
			return;
		}

		// sr1#2 / sr2 B2: reassemble best-effort; skip non-code-unit siblings.
		const reassembled = tryReassembleNumericObject(record);
		if (reassembled.indexedCharCodeShape) {
			indexedCharCodeObject = true;
		}
		if (reassembled.built) {
			pushString(reassembled.built);
		}

		// Align with validateTelemetryData flatten (getOwnPropertyNames).
		// sr1#1: scan canonicalized own-property names, not only values.
		for (const key of Object.getOwnPropertyNames(record)) {
			if (budgetExceeded || depthAborted) {
				return;
			}
			pushString(key);
			visit(record[key], depth + 1);
		}
	};

	visit(data, 0);

	// Global visit-order channel catches wrapped / split / Map shapes that
	// never form a single dense object for tryReassembleNumericObject.
	if (!budgetExceeded && !depthAborted && codeUnitChannel.length >= 4) {
		const built = codeUnitChannel.slice(0, 4096).map(n => String.fromCodePoint(n)).join('');
		if (built.length > 0 && !out.includes(canonicalizeTelemetryString(built))) {
			pushString(built);
		}
	}

	const leafStrings = out.slice();

	// Fail closed on depth/budget BEFORE building multi-MB rejoins (sr2 D1).
	if (depthAborted || budgetExceeded) {
		return {
			strings: leafStrings,
			leafStrings,
			codeUnitLeafCount,
			booleanLeafCount,
			numericLeafCount: codeUnitLeafCount,
			depthAborted,
			budgetExceeded,
			oversizedNumberArray,
			indexedCharCodeObject,
		};
	}

	// Rejoin fragments so split-field / array smuggling still hits path/canary (rt1#4).
	// Synthetic joins are appended to `strings` only — secret scan uses leafStrings.
	if (leafStrings.length > 1) {
		let totalChars = 0;
		for (const s of leafStrings) {
			totalChars += s.length;
			if (totalChars > MAX_REJOIN_CHARS) {
				break;
			}
		}
		if (totalChars <= MAX_REJOIN_CHARS) {
			out.push(leafStrings.join('\0'));
			out.push(leafStrings.join(''));
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
			if (leafStrings.some(pathSegment)) {
				const joined = leafStrings.join('/');
				out.push(joined.startsWith('/') ? joined : '/' + joined);
			}
		}
	}

	return {
		strings: out,
		leafStrings,
		codeUnitLeafCount,
		booleanLeafCount,
		numericLeafCount: codeUnitLeafCount,
		depthAborted,
		budgetExceeded,
		oversizedNumberArray,
		indexedCharCodeObject,
	};
}

/**
 * Flatten nested telemetry payloads into string leaf values for scanning.
 */
export function flattenTelemetryStrings(data: unknown): string[] {
	return flattenTelemetryStringsDetailed(data).strings;
}

function looksLikeRootedAbsolutePath(value: string): boolean {
	if (!value.includes('/') && !value.includes('\\')) {
		return false;
	}
	// Strip file:// so rooted home/sensitive checks still apply.
	const canonical = value.replace(/^file:\/\//i, '');
	if (
		ABS_UNIX_HOME_RE.test(canonical)
		|| ABS_WIN_HOME_RE.test(canonical)
		|| ABS_UNIX_SENSITIVE_ROOT_RE.test(canonical)
		|| ABS_WIN_ANY_DRIVE_RE.test(canonical)
	) {
		// RegExp with /g retains lastIndex — reset after test.
		ABS_UNIX_HOME_RE.lastIndex = 0;
		ABS_WIN_HOME_RE.lastIndex = 0;
		ABS_UNIX_SENSITIVE_ROOT_RE.lastIndex = 0;
		ABS_WIN_ANY_DRIVE_RE.lastIndex = 0;
		return true;
	}
	ABS_UNIX_HOME_RE.lastIndex = 0;
	ABS_WIN_HOME_RE.lastIndex = 0;
	ABS_UNIX_SENSITIVE_ROOT_RE.lastIndex = 0;
	ABS_WIN_ANY_DRIVE_RE.lastIndex = 0;
	return /^\/(?:Users|home|tmp|private\/tmp|opt|var\/folders|var\/tmp|etc|root)\//.test(canonical)
		|| /^[A-Za-z]:[\\/]/.test(canonical)
		|| ABS_ROOTED_SEGMENT_RE.test(canonical)
		|| /[A-Za-z]:\/(?:Users|[^/]+)\/[^/]/.test(canonical);
}

function looksLikePath(value: string): boolean {
	// sr2 FP2: rooted absolute paths only — never a rootless slash-segment match
	// (that convicts URLs, relative editor paths, and api/scm/createSourceControl).
	return looksLikeRootedAbsolutePath(value);
}

function detectSecret(value: string): string | undefined {
	for (const entry of SECRET_REGEXES) {
		entry.regex.lastIndex = 0;
		if (entry.regex.test(value)) {
			entry.regex.lastIndex = 0;
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
	if (SAFE_UUID_RE.test(value) || SAFE_VERSION_RE.test(value)) {
		return true;
	}
	// sr2 B1: a 38-char opaque token that is not a UUID/version is not an enum.
	if (value.length > MAX_STRICT_TOKEN_LEN) {
		return false;
	}
	return SAFE_TOKEN_RE.test(value);
}

function isAllowedEventNameSegment(value: string): boolean {
	if (value.length === 0 || value.length > 128) {
		return false;
	}
	return SAFE_EVENT_NAME_SEGMENT_RE.test(value) || SAFE_UUID_RE.test(value) || SAFE_VERSION_RE.test(value);
}

function scanStrings(
	strings: readonly string[],
	markers: readonly string[],
	secretStrings?: readonly string[],
): TelemetryGuardResult {
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

	// sr2 FP1: secret layer runs on real leaves only — not NUL/concat rejoins.
	const secretHaystacks = secretStrings ?? strings;
	for (const s of secretHaystacks) {
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
	const leafStrings = [...flat.leafStrings];
	if (typeof options.eventName === 'string' && options.eventName.length > 0) {
		// Name-shaped rule (sr2 FP2): legal `a/b/c` event names are not paths.
		// A whole event name that *is* a rooted absolute path still convicts (F2).
		const fullName = canonicalizeTelemetryString(options.eventName);
		if (looksLikeRootedAbsolutePath(fullName)) {
			return { hit: true, layer: 'path', detail: '<REDACTED: user-file-path>' };
		}
		for (const part of options.eventName.split(/[/.]/)) {
			if (part.length === 0) {
				continue;
			}
			const canonical = canonicalizeTelemetryString(part);
			leafStrings.push(canonical);
			strings.push(canonical);
		}
	}

	if (failClosedOnDepthAbort && (flat.depthAborted || flat.budgetExceeded)) {
		return {
			hit: true,
			layer: 'shape',
			detail: flat.budgetExceeded ? '<REDACTED: visit-budget>' : '<REDACTED: depth-limit>',
		};
	}
	if (boundMeasurements && (
		flat.oversizedNumberArray
		|| flat.codeUnitLeafCount > MAX_STRICT_CODE_UNIT_LEAVES
		|| flat.booleanLeafCount > MAX_STRICT_BOOLEAN_LEAVES
		// sr1#2: indexed char-code objects are a measurements-lane smuggling
		// channel even when leaf count is under the cap.
		|| flat.indexedCharCodeObject
	)) {
		return { hit: true, layer: 'shape', detail: '<REDACTED: measurements-bound>' };
	}

	const residual = scanStrings(strings, markers, leafStrings);
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
			for (const part of options.eventName.split(/[/.]/)) {
				const canonical = canonicalizeTelemetryString(part);
				if (canonical.length > 0 && !isAllowedEventNameSegment(canonical)) {
					return { hit: true, layer: 'shape', detail: '<REDACTED: disallowed-event-name>' };
				}
			}
		}
	}

	return { hit: false };
}

function collectRawCanonicalLeaves(data: unknown): string[] {
	const out: string[] = [];
	const visited = new WeakSet<object>();
	let nodeCount = 0;
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
		if (value === null || value === undefined || depth > MAX_VISIT_DEPTH || nodeCount > MAX_VISIT_NODES) {
			return;
		}
		if (typeof value === 'string') {
			push(value);
			return;
		}
		if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
			return;
		}
		if (typeof value !== 'object') {
			return;
		}
		if (visited.has(value)) {
			return;
		}
		visited.add(value);
		nodeCount++;
		if (Array.isArray(value)) {
			for (const item of value) {
				if (typeof item === 'number' || typeof item === 'boolean') {
					continue;
				}
				visit(item, depth + 1);
			}
			return;
		}
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
	};
	visit(data, 0);
	return out;
}

/**
 * Redact a telemetry event name before persisting it to telemetry-guard.log (F2).
 */
export function redactTelemetryGuardEventName(eventName: string): string {
	// Name-shaped scan: path layer must not convict legal `a/b/c` event names (FP2).
	for (const part of eventName.split(/[/.]/)) {
		const canonical = canonicalizeTelemetryString(part);
		if (canonical.length === 0) {
			continue;
		}
		if (looksLikePath(canonical)) {
			return '<REDACTED: event-name:path>';
		}
		const secret = detectSecret(canonical);
		if (secret) {
			return '<REDACTED: event-name:secret>';
		}
	}
	if (looksLikePath(canonicalizeTelemetryString(eventName))) {
		return '<REDACTED: event-name:path>';
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
	// Rooted only — rootless ABS_PATH_RE would redact every JS stack frame (FP5).
	return looksLikeRootedAbsolutePath(canonical);
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
	ABS_UNIX_SENSITIVE_ROOT_RE.lastIndex = 0;
	ABS_UNIX_HOME_RE.lastIndex = 0;
	ABS_WIN_ANY_DRIVE_RE.lastIndex = 0;
	ABS_WIN_HOME_RE.lastIndex = 0;
	ABS_UNIX_TMP_RE.lastIndex = 0;
	out = out.replace(ABS_UNIX_SENSITIVE_ROOT_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_UNIX_HOME_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_WIN_ANY_DRIVE_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_WIN_HOME_RE, ' <REDACTED: user-file-path>');
	out = out.replace(ABS_UNIX_TMP_RE, ' <REDACTED: user-file-path>');

	// sr2 S1: space-containing path tails after a rooted redact (e.g.
	// `/Users/alice/My` → REDACTED, leaving `Documents/tax.pdf`). Eat through
	// the next clear delimiter (quote, comma, semicolon, EOL).
	out = out.replace(/<REDACTED: user-file-path>[^"',;\n\r]*/g, '<REDACTED: user-file-path>');

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
	// is not re-matched by the Generic Secret heuristic.
	const held: string[] = [];
	const hold = (marker: string): string => {
		held.push(marker);
		return `\0H${held.length - 1}\0`;
	};
	out = out.replace(/<REDACTED:[^>]*>/g, m => hold(m));
	for (const entry of SECRET_REGEXES) {
		entry.regex.lastIndex = 0;
		out = out.replace(entry.regex, () => hold(`<REDACTED: ${entry.label}>`));
	}
	out = out.replace(/\0H(\d+)\0/g, (_, i) => held[Number(i)] ?? '');

	// Fail closed on residual ROOTED absolute paths only (sr2 FP5). Rootless
	// ABS_PATH_RE would shred every stack frame (`out/vs/...`, node:internal).
	const residualCanonical = canonicalizeTelemetryString(out);
	if (looksLikeRootedAbsolutePath(residualCanonical)) {
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
