/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

type ProcessEnvLike = { readonly env?: NodeJS.ProcessEnv | Record<string, string | undefined> };

/**
 * Best-effort `process.env` that never throws in the sandboxed renderer
 * (where bare `process` is a ReferenceError). Prefer product.json /
 * IProductService flags on renderer-reachable paths; env overrides apply
 * only when a Node (or Node-like) `process` binding exists.
 *
 * - No args: auto-detect (`typeof process !== 'undefined' ? process : undefined`).
 * - Explicit `undefined` / `null`: simulate renderer (no process) — returns `{}`.
 *   (Default-parameter semantics would otherwise re-bind `undefined` to `process`.)
 */
export function readOptionalProcessEnv(processLike?: ProcessEnvLike | null): NodeJS.ProcessEnv | Record<string, string | undefined> {
	const resolved: ProcessEnvLike | null | undefined = (arguments.length === 0)
		? (typeof process !== 'undefined' ? process : undefined)
		: processLike;
	return resolved?.env ?? {};
}
