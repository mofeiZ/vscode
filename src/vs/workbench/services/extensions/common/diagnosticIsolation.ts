/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Diagnostic isolation policy source (fork).
 *
 * TEMPORARY · OPT-IN · LAST-RESORT. Default set is EMPTY — no extension is
 * isolated unless a caller adds an id, or the clearly-labeled DEMO seed flag
 * is turned on. Per-extension isolation costs an extra LocalProcess extension
 * host (memory + CPU + IPC); never enable this by default.
 *
 * Intended callers (wire later; this module is the clean interface):
 *   - memory-threshold signal (u30 EH memory sampler) → add on alert, remove on cool
 *   - debug-probe-attached signal (debug-telemetry skill) → add while attached, remove on detach
 *
 * APPLY / RESTORE (wiring step — documented, not live-restarted here):
 * Affinity assignment runs at initial host allocation. Once hosts are running,
 * `_computeAffinity` ignores new configured affinities ("Reload window.").
 * After add/remove, trigger a window reload (or a future targeted EH restart)
 * so placement takes effect. Removing an id then reloading restores the
 * extension to the shared host (affinity 0) — that is the auto-restore path.
 *
 * Group integrity is enforced by the tracker: assignment is per dependency /
 * extensionAffinity group; never split a group.
 */

/** DEMO-ONLY seed id. Used only when the demo flag is explicitly ON. */
export const DIAGNOSTIC_ISOLATION_DEMO_SEED_ID = 'interview-toybox.desk-gnome';

/**
 * DEMO-ONLY configuration key. Default false.
 * When true, seeds {@link DIAGNOSTIC_ISOLATION_DEMO_SEED_ID} into the effective
 * isolation set so the existing 2-host proof can reproduce on demand.
 */
export const DIAGNOSTIC_ISOLATION_DEMO_CONFIG_KEY = 'extensions.diagnosticIsolation.demoSeedDeskGnome';

/**
 * DEMO-ONLY product.json field (default false / absent). Same effect as the
 * config key when set true. Prefer the config key in tests.
 */
export const DIAGNOSTIC_ISOLATION_DEMO_PRODUCT_FIELD = 'demoDiagnosticIsolationSeedDeskGnome';

/** DEMO-ONLY env override: set to `1` / `true` to seed desk-gnome. */
export const DIAGNOSTIC_ISOLATION_DEMO_ENV = 'VSCODE_DEMO_DIAGNOSTIC_ISOLATION';

/** Affinity number requested for diagnostically isolated groups (shared diagnostic host). */
export const DIAGNOSTIC_ISOLATION_AFFINITY = 1;

const _diagnosticIsolationSet = new Set<string>();

function normalizeExtensionId(extensionId: string): string {
	return extensionId.trim();
}

/**
 * Add an extension id to the diagnostic-isolation set.
 * Returns true if the id was newly added.
 *
 * Does not restart hosts by itself — see module doc APPLY / RESTORE.
 */
export function addDiagnosticIsolation(extensionId: string): boolean {
	const id = normalizeExtensionId(extensionId);
	if (!id) {
		return false;
	}
	const sizeBefore = _diagnosticIsolationSet.size;
	_diagnosticIsolationSet.add(id);
	return _diagnosticIsolationSet.size > sizeBefore;
}

/**
 * Remove an extension id from the diagnostic-isolation set (auto-restore path).
 * Returns true if the id was present.
 *
 * Does not restart hosts by itself — see module doc APPLY / RESTORE.
 */
export function removeDiagnosticIsolation(extensionId: string): boolean {
	const id = normalizeExtensionId(extensionId);
	if (!id) {
		return false;
	}
	return _diagnosticIsolationSet.delete(id);
}

export function hasDiagnosticIsolation(extensionId: string): boolean {
	return _diagnosticIsolationSet.has(normalizeExtensionId(extensionId));
}

/** Snapshot of currently flagged extension ids (runtime set only; excludes demo seed). */
export function getDiagnosticIsolationIds(): readonly string[] {
	return Array.from(_diagnosticIsolationSet);
}

export function clearDiagnosticIsolation(): void {
	_diagnosticIsolationSet.clear();
}

/** Test-only reset of the runtime set. */
export function _resetDiagnosticIsolationForTests(): void {
	_diagnosticIsolationSet.clear();
}

export function isDiagnosticIsolationDemoEnvEnabled(env: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): boolean {
	const raw = env[DIAGNOSTIC_ISOLATION_DEMO_ENV];
	return raw === '1' || raw === 'true';
}

/**
 * Build the affinity policy map consumed by `_computeAffinity`.
 * Empty by default. Demo seed is opt-in via options / config / product / env.
 */
export function buildDiagnosticIsolationAffinities(options: {
	demoSeedDeskGnome?: boolean;
	productDemoSeed?: boolean;
	env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
} = {}): { [extensionId: string]: number } {
	const ids = new Set(_diagnosticIsolationSet);
	const demoOn = Boolean(options.demoSeedDeskGnome)
		|| Boolean(options.productDemoSeed)
		|| isDiagnosticIsolationDemoEnvEnabled(options.env);
	if (demoOn) {
		ids.add(DIAGNOSTIC_ISOLATION_DEMO_SEED_ID);
	}
	const result: { [extensionId: string]: number } = {};
	for (const id of ids) {
		result[id] = DIAGNOSTIC_ISOLATION_AFFINITY;
	}
	return result;
}
