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
 * Tier-1 access gate (internal builds / employees only in production):
 *   product.json `internalDiagnosticsEnabled: true`
 *   OR env `VSCODE_INTERNAL_DIAGNOSTICS=1`
 * Default absent/false — when the gate is OFF, add/remove commands and
 * `addDiagnosticIsolation` refuse/no-op, and `_computeAffinity` never
 * applies isolation affinities (runtime set and demo seed are inert).
 * Modeled on the same product.json + env pattern as the DEMO seed below
 * (`demoDiagnosticIsolationSeedDeskGnome` / `VSCODE_DEMO_DIAGNOSTIC_ISOLATION`).
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

import product from '../../../../platform/product/common/product.js';

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

/**
 * Tier-1 internal-diagnostics product.json field (default false / absent).
 * When true, enables invasive diagnostic isolation (and future debug probes).
 * Never ship enabled for external / enterprise customers.
 */
export const INTERNAL_DIAGNOSTICS_PRODUCT_FIELD = 'internalDiagnosticsEnabled';

/**
 * Tier-1 internal-diagnostics env override for test / local runs.
 * Set to `1` / `true` to enable invasive diagnostics without a product rebuild.
 */
export const INTERNAL_DIAGNOSTICS_ENV = 'VSCODE_INTERNAL_DIAGNOSTICS';

/** Affinity number requested for diagnostically isolated groups (shared diagnostic host). */
export const DIAGNOSTIC_ISOLATION_AFFINITY = 1;

const _diagnosticIsolationSet = new Set<string>();

/** Test-only override for the Tier-1 gate (`undefined` = consult product/env). */
let _internalDiagnosticsEnabledForTests: boolean | undefined;

function normalizeExtensionId(extensionId: string): string {
	return extensionId.trim();
}

function envFlagEnabled(raw: string | undefined): boolean {
	return raw === '1' || raw === 'true';
}

/**
 * Single Tier-1 access gate for invasive diagnostics (diagnostic isolation,
 * and later debug telemetry probes). Default OFF.
 *
 * Enabled when any of:
 * - env `VSCODE_INTERNAL_DIAGNOSTICS=1` / `true`
 * - product.json `internalDiagnosticsEnabled: true`
 * - test override via {@link _setInternalDiagnosticsEnabledForTests}
 */
export function isInternalDiagnosticsEnabled(options: {
	productEnabled?: boolean;
	env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
} = {}): boolean {
	if (_internalDiagnosticsEnabledForTests !== undefined) {
		return _internalDiagnosticsEnabledForTests;
	}
	const env = options.env ?? process.env;
	if (envFlagEnabled(env[INTERNAL_DIAGNOSTICS_ENV])) {
		return true;
	}
	const productEnabled = options.productEnabled ?? (product.internalDiagnosticsEnabled === true);
	return productEnabled === true;
}

/** Test-only: force the Tier-1 gate on/off. Pass `undefined` to clear. */
export function _setInternalDiagnosticsEnabledForTests(enabled: boolean | undefined): void {
	_internalDiagnosticsEnabledForTests = enabled;
}

/**
 * Add an extension id to the diagnostic-isolation set.
 * Returns true if the id was newly added.
 *
 * Tier-1 gated: refuses (returns false, does not mutate) when
 * {@link isInternalDiagnosticsEnabled} is false.
 *
 * Does not restart hosts by itself — see module doc APPLY / RESTORE.
 */
export function addDiagnosticIsolation(extensionId: string): boolean {
	if (!isInternalDiagnosticsEnabled()) {
		return false;
	}
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
 * Allowed even when the Tier-1 gate is OFF so a previously-enabled session can
 * clear leftover ids; placement remains inert while the gate is OFF.
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

/** Test-only reset of the runtime set (does not clear the gate override). */
export function _resetDiagnosticIsolationForTests(): void {
	_diagnosticIsolationSet.clear();
}

export function isDiagnosticIsolationDemoEnvEnabled(env: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): boolean {
	return envFlagEnabled(env[DIAGNOSTIC_ISOLATION_DEMO_ENV]);
}

/**
 * Build the affinity policy map consumed by `_computeAffinity`.
 * Empty by default. Demo seed is opt-in via options / config / product / env.
 *
 * Tier-1 gated: returns `{}` when {@link isInternalDiagnosticsEnabled} is false,
 * so runtime set contents and demo seed are inert in production.
 */
export function buildDiagnosticIsolationAffinities(options: {
	demoSeedDeskGnome?: boolean;
	productDemoSeed?: boolean;
	env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
	productInternalDiagnostics?: boolean;
} = {}): { [extensionId: string]: number } {
	if (!isInternalDiagnosticsEnabled({
		productEnabled: options.productInternalDiagnostics,
		env: options.env,
	})) {
		return {};
	}
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
