/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Per-session opaque-id minter for guard-safe telemetry (u45 perf foundation).
 *
 * Fork twin of Desk Gnome `ArchiveFileIdMap`
 * (`extensions/desk-gnome/src/archive/redact.ts`): monotonic `${prefix}-${n}`
 * tokens, never paths. Core must not import the extension; archive/action-ring
 * consumers share this shape (Desk Gnome may keep a thin re-export later).
 *
 * Stability: same key → same id within one map instance (one session).
 * A new session constructs a new map — ids are not longitudinally joinable.
 */

/** Closed prefixes admitted by `isAllowedExtensionTelemetryString`. */
export type OpaqueIdPrefix = 'file' | 'entity' | 'ext';

export type OpaqueId = `${OpaqueIdPrefix}-${number}`;

/**
 * Monotonic per-session map from an arbitrary key (path, extension id, …)
 * to an opaque `${prefix}-${n}` token. The key never appears in telemetry.
 */
export class SessionOpaqueIdMap {
	private readonly keyToId = new Map<string, OpaqueId>();
	private next = 1;

	constructor(
		private readonly prefix: OpaqueIdPrefix = 'file',
	) { }

	opaqueId(key: string): OpaqueId {
		const existing = this.keyToId.get(key);
		if (existing !== undefined) {
			return existing;
		}
		const id = `${this.prefix}-${this.next}` as OpaqueId;
		this.next += 1;
		this.keyToId.set(key, id);
		return id;
	}

	get size(): number {
		return this.keyToId.size;
	}

	/** Drop all mappings (tests / explicit session reset). */
	clear(): void {
		this.keyToId.clear();
		this.next = 1;
	}
}

/** File-path minter — same contract as Desk Gnome `ArchiveFileIdMap`. */
export class SessionFileIdMap extends SessionOpaqueIdMap {
	constructor() {
		super('file');
	}
}

/** Extension / entity minter (`ext-n`) for latency/CPU/heap attribution. */
export class SessionEntityIdMap extends SessionOpaqueIdMap {
	constructor(prefix: Exclude<OpaqueIdPrefix, 'file'> = 'ext') {
		super(prefix);
	}
}

/** Short hex session token (`sess-` + 6 hex chars). Guard-safe opaque string. */
export function mintSessionId(salt: Uint8Array | string): `sess-${string}` {
	return `sess-${shortHash(salt)}`;
}

/**
 * Salted workspace fingerprint (`ws-` + 6 hex). Roots are mixed with salt so
 * the token is stable within a session and useless offline across sessions.
 */
export function mintWorkspaceId(salt: Uint8Array | string, roots: readonly string[]): `ws-${string}` {
	const material = typeof salt === 'string'
		? `${salt}\0${roots.join('\0')}`
		: `${shortHash(salt)}\0${roots.join('\0')}`;
	return `ws-${shortHash(material)}`;
}

function shortHash(input: Uint8Array | string): string {
	let h = 2166136261;
	if (typeof input === 'string') {
		for (let i = 0; i < input.length; i++) {
			h ^= input.charCodeAt(i);
			h = Math.imul(h, 16777619);
		}
	} else {
		for (let i = 0; i < input.length; i++) {
			h ^= input[i]!;
			h = Math.imul(h, 16777619);
		}
	}
	return (h >>> 0).toString(16).padStart(8, '0').slice(0, 6);
}
