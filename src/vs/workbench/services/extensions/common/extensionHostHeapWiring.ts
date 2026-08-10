/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Leak-diagnosis wiring (u41 / u43): detect → attribute → diagnose.
 *
 * Two lanes (r16):
 * - Tier-0 ATTRIBUTION: always-on allocation sampling → guard-safe
 *   `exthostHeapAttribution`. NOT gated by internal-diagnostics.
 * - Tier-1 SNAPSHOT: raw `.heapsnapshot` pair + local named report. Gated
 *   behind internal-diagnostics; never telemetered.
 *
 * Capture I/O stays in `extensionHostHeapCapture.ts`; analysis in
 * `extensionHostHeapDiagnosis.ts`.
 */

import { join } from '../../../../base/common/path.js';
import { URI } from '../../../../base/common/uri.js';
import { bucketRssMb } from './extensionHostMemoryMonitor.js';
import {
	analyzeSamplingAttribution,
	assertSafeSummaryShape,
	attributeSamplingProfile,
	buildSafeSummary,
	diffClassGroups,
	mergeAttribution,
	pickDominatorShape,
	primaryGrownRetainedBytes,
	type AllocationSamplingProfile,
	type ExtHostHeapAttributionSafeSummary,
	type ExtensionLocationRef,
	type HeapClassGroupSummary,
	type HeapDiagnosisLocalReport,
} from './extensionHostHeapDiagnosis.js';

/** Min wall time between automatic Tier-1 snapshot pairs (r11). */
export const HEAP_CAPTURE_COOLDOWN_MS = 30 * 60_000;

/** Max automatic Tier-1 pairs per EH session (r11). */
export const HEAP_CAPTURE_MAX_PAIRS_PER_SESSION = 2;

/** Default delay between baseline and current snapshots on alert (r11). */
export const HEAP_PAIR_DELAY_MS = 5 * 60_000;

/** Min wall time between Tier-0 attribution emissions (alert or cadence). */
export const HEAP_ATTRIBUTION_COOLDOWN_MS = 5 * 60_000;

/** Public on-demand command (renderer): gate-checks, then delegates to the EH. */
export const HEAP_DIAGNOSIS_COMMAND_ID = '_extensions.heapDiagnosis.captureAndDiagnose';
/** EH-side capture+diagnose implementation (not invoked when the gate is off). */
export const HEAP_DIAGNOSIS_EH_COMMAND_ID = '_extensions.heapDiagnosis._captureAndDiagnoseInHost';

export type HeapCaptureSkipReason =
	| 'gate-off'
	| 'cooldown'
	| 'max-pairs'
	| 'in-flight';

export type HeapAttributionSkipReason =
	| 'cooldown'
	| 'in-flight'
	| 'not-started';

export interface HeapCaptureRateLimitState {
	/** Earliest wall time another automatic pair may start. */
	nextAllowedMs: number;
	/** Successful automatic pairs this session. */
	pairsThisSession: number;
	/** True while a pair (or on-demand run) is in flight. */
	inFlight: boolean;
}

export interface HeapAttributionRateLimitState {
	nextAllowedMs: number;
	inFlight: boolean;
}

export function createHeapCaptureRateLimitState(): HeapCaptureRateLimitState {
	return {
		nextAllowedMs: 0,
		pairsThisSession: 0,
		inFlight: false,
	};
}

export function createHeapAttributionRateLimitState(): HeapAttributionRateLimitState {
	return {
		nextAllowedMs: 0,
		inFlight: false,
	};
}

export function decideAutomaticHeapCapture(
	state: HeapCaptureRateLimitState,
	args: { readonly nowMs: number; readonly gateEnabled: boolean },
): { readonly allow: true; readonly nextState: HeapCaptureRateLimitState } | { readonly allow: false; readonly reason: HeapCaptureSkipReason; readonly nextState: HeapCaptureRateLimitState } {
	if (!args.gateEnabled) {
		return { allow: false, reason: 'gate-off', nextState: state };
	}
	if (state.inFlight) {
		return { allow: false, reason: 'in-flight', nextState: state };
	}
	if (state.pairsThisSession >= HEAP_CAPTURE_MAX_PAIRS_PER_SESSION) {
		return { allow: false, reason: 'max-pairs', nextState: state };
	}
	if (args.nowMs < state.nextAllowedMs) {
		return { allow: false, reason: 'cooldown', nextState: state };
	}
	return {
		allow: true,
		nextState: { ...state, inFlight: true },
	};
}

/** Tier-0 attribution decision — never consults the internal-diagnostics gate. */
export function decideTier0Attribution(
	state: HeapAttributionRateLimitState,
	args: { readonly nowMs: number },
): { readonly allow: true; readonly nextState: HeapAttributionRateLimitState } | { readonly allow: false; readonly reason: HeapAttributionSkipReason; readonly nextState: HeapAttributionRateLimitState } {
	if (state.inFlight) {
		return { allow: false, reason: 'in-flight', nextState: state };
	}
	if (args.nowMs < state.nextAllowedMs) {
		return { allow: false, reason: 'cooldown', nextState: state };
	}
	return {
		allow: true,
		nextState: { ...state, inFlight: true },
	};
}

export function markHeapCaptureFinished(
	state: HeapCaptureRateLimitState,
	args: { readonly nowMs: number; readonly succeeded: boolean; readonly countTowardSessionLimit: boolean },
): HeapCaptureRateLimitState {
	return {
		nextAllowedMs: args.succeeded ? args.nowMs + HEAP_CAPTURE_COOLDOWN_MS : state.nextAllowedMs,
		pairsThisSession: args.countTowardSessionLimit && args.succeeded
			? state.pairsThisSession + 1
			: state.pairsThisSession,
		inFlight: false,
	};
}

export function markTier0AttributionFinished(
	state: HeapAttributionRateLimitState,
	args: { readonly nowMs: number; readonly succeeded: boolean },
): HeapAttributionRateLimitState {
	return {
		nextAllowedMs: args.succeeded ? args.nowMs + HEAP_ATTRIBUTION_COOLDOWN_MS : state.nextAllowedMs,
		inFlight: false,
	};
}

/** Near-heap-limit + diagnostic-dir flags for EH `execArgv` (Tier-1 gated at call site). */
export function nearHeapLimitExecArgv(diagnosticDirFsPath: string): readonly string[] {
	return [
		'--heapsnapshot-near-heap-limit=1',
		`--diagnostic-dir=${diagnosticDirFsPath}`,
	];
}

/**
 * Append near-heap-limit capture flags when the internal-diagnostics gate is on.
 * Does not mutate `execArgv`.
 */
export function withNearHeapLimitExecArgv(
	execArgv: readonly string[],
	diagnosticDirFsPath: string,
	enabled: boolean,
): string[] {
	if (!enabled || !diagnosticDirFsPath) {
		return [...execArgv];
	}
	return [...nearHeapLimitExecArgv(diagnosticDirFsPath), ...execArgv];
}

const HEAP_SNAPSHOT_NAME_RE = /^Heap\..+\.heapsnapshot$/i;

export interface NearHeapSnapshotDirEntry {
	readonly name: string;
	readonly sizeBytes: number;
	readonly mtimeMs: number;
}

/**
 * Numbers-only scan of a diagnostic dir for V8 near-limit snapshots newer than
 * host start. Raw paths/names never leave this helper's return value.
 */
export function inspectNearHeapLimitSnapshots(
	entries: readonly NearHeapSnapshotDirEntry[],
	hostStartedAtMs: number,
): { readonly heapSnapshotCaptured: boolean; readonly heapSnapshotSizeBucketMb: number | null } {
	let best: NearHeapSnapshotDirEntry | undefined;
	for (const e of entries) {
		if (!HEAP_SNAPSHOT_NAME_RE.test(e.name)) {
			continue;
		}
		if (e.mtimeMs < hostStartedAtMs) {
			continue;
		}
		if (!best || e.mtimeMs > best.mtimeMs || (e.mtimeMs === best.mtimeMs && e.sizeBytes > best.sizeBytes)) {
			best = e;
		}
	}
	if (!best) {
		return { heapSnapshotCaptured: false, heapSnapshotSizeBucketMb: null };
	}
	const sizeMb = best.sizeBytes / (1024 * 1024);
	return {
		heapSnapshotCaptured: true,
		heapSnapshotSizeBucketMb: bucketRssMb(sizeMb),
	};
}

export type HeapDiagnosisCommandResult =
	| { readonly ok: true; readonly summary: ExtHostHeapAttributionSafeSummary }
	| { readonly ok: false; readonly reason: 'internal-diagnostics-disabled' | 'in-flight' | 'capture-failed'; readonly detail?: string };

/**
 * Gate check for the on-demand Tier-1 capture+diagnose command. When the flag
 * is off, refuse without touching the heap.
 */
export function refuseHeapDiagnosisCommandIfGatedOff(gateEnabled: boolean): HeapDiagnosisCommandResult | undefined {
	if (!gateEnabled) {
		return { ok: false, reason: 'internal-diagnostics-disabled' };
	}
	return undefined;
}

export interface HeapDiagnosisAnalyzeInput {
	readonly before: readonly HeapClassGroupSummary[];
	readonly after: readonly HeapClassGroupSummary[];
	readonly profile: AllocationSamplingProfile;
	readonly extensionLocations: readonly ExtensionLocationRef[];
	readonly affinity?: number;
	readonly pid?: number;
	readonly snapshotSeq?: number;
}

export interface HeapDiagnosisAnalyzeOutput {
	readonly summary: ExtHostHeapAttributionSafeSummary;
	readonly reportMeta: HeapDiagnosisLocalReport;
}

/** Run the pure analyze half (attribute + diagnose + safe summary). */
export function analyzeHeapCapturePair(input: HeapDiagnosisAnalyzeInput): HeapDiagnosisAnalyzeOutput {
	const grown = diffClassGroups(input.before, input.after);
	const lane1 = attributeSamplingProfile(input.profile, input.extensionLocations);
	const grownBytes = primaryGrownRetainedBytes(grown);
	const attribution = mergeAttribution(lane1, new Map(), grownBytes);
	const dominator = pickDominatorShape(grown, input.after);
	const { summary, reportMeta } = buildSafeSummary({
		attribution,
		grown,
		dominator,
		affinity: input.affinity,
		pid: input.pid,
		snapshotSeq: input.snapshotSeq,
	});
	assertSafeSummaryShape(summary);
	return { summary, reportMeta };
}

export interface HeapDiagnosisCaptureHooks {
	readonly writeSnapshot: (path: string) => string;
	readonly startSampling: (intervalBytes?: number) => Promise<void>;
	/** Non-stopping profile read for Tier-0 continuous sampling. */
	readonly getSamplingProfile: () => Promise<AllocationSamplingProfile>;
	readonly extractClassGroupsFromSnapshot: (path: string) => Promise<HeapClassGroupSummary[]>;
	readonly delay: (ms: number) => Promise<void>;
	readonly nowMs: () => number;
	readonly listExtensionLocations: () => readonly ExtensionLocationRef[];
	readonly artifactDirFsPath: string;
	readonly pid: number;
	readonly affinity: number;
	readonly emitSafeSummary: (summary: ExtHostHeapAttributionSafeSummary) => void;
	readonly logLocalReport: (text: string) => void;
	readonly isGateEnabled: () => boolean;
	/** Override pair delay (tests use 0). */
	readonly pairDelayMs?: number;
	/** Tier-0 continuous sampling interval (bytes). */
	readonly tier0SamplingIntervalBytes?: number;
}

export interface HeapDiagnosisRunResult {
	readonly summary: ExtHostHeapAttributionSafeSummary;
	readonly reportMeta: HeapDiagnosisLocalReport;
	readonly baselinePath: string;
	readonly currentPath: string;
}

export interface HeapAlertDispatchResult {
	readonly attribution: { readonly started: true } | { readonly started: false; readonly reason: HeapAttributionSkipReason };
	readonly snapshot: { readonly started: true } | { readonly started: false; readonly reason: HeapCaptureSkipReason };
}

function heapArtifactPath(dir: string, kind: 'baseline' | 'current', pid: number, seq: number): string {
	const iso = new Date().toISOString().replace(/[:.]/g, '-');
	return join(dir, `heap-${iso}-${pid}-${seq}-${kind}.heapsnapshot`);
}

/**
 * Tier-1: capture a baseline+current snapshot pair (sampling already running),
 * analyze, emit the safe summary, and write the local report.
 * Caller owns rate-limit / gate. Does not stop continuous sampling.
 */
export async function runHeapCaptureAndDiagnose(hooks: HeapDiagnosisCaptureHooks, snapshotSeq: number): Promise<HeapDiagnosisRunResult> {
	const pairDelayMs = hooks.pairDelayMs ?? HEAP_PAIR_DELAY_MS;
	// Ensure sampling is on for the window; Tier-0 may already have started it.
	await hooks.startSampling();
	const baselinePath = hooks.writeSnapshot(heapArtifactPath(hooks.artifactDirFsPath, 'baseline', hooks.pid, snapshotSeq));
	await hooks.delay(pairDelayMs);
	const currentPath = hooks.writeSnapshot(heapArtifactPath(hooks.artifactDirFsPath, 'current', hooks.pid, snapshotSeq));
	const profile = await hooks.getSamplingProfile();
	const before = await hooks.extractClassGroupsFromSnapshot(baselinePath);
	const after = await hooks.extractClassGroupsFromSnapshot(currentPath);
	const analyzed = analyzeHeapCapturePair({
		before,
		after,
		profile,
		extensionLocations: hooks.listExtensionLocations(),
		affinity: hooks.affinity,
		pid: hooks.pid,
		snapshotSeq,
	});
	hooks.logLocalReport(analyzed.reportMeta.text);
	hooks.emitSafeSummary(analyzed.summary);
	return {
		summary: analyzed.summary,
		reportMeta: analyzed.reportMeta,
		baselinePath,
		currentPath,
	};
}

/** Tier-0: flush the continuous sampler into a guard-safe attribution summary. */
export async function runTier0SamplingAttribution(
	hooks: HeapDiagnosisCaptureHooks,
	attributionSeq: number,
): Promise<{ readonly summary: ExtHostHeapAttributionSafeSummary; readonly reportMeta: HeapDiagnosisLocalReport }> {
	await hooks.startSampling(hooks.tier0SamplingIntervalBytes);
	const profile = await hooks.getSamplingProfile();
	const analyzed = analyzeSamplingAttribution({
		profile,
		extensionLocations: hooks.listExtensionLocations(),
		affinity: hooks.affinity,
		pid: hooks.pid,
		snapshotSeq: attributionSeq,
	});
	assertSafeSummaryShape(analyzed.summary);
	hooks.logLocalReport(analyzed.reportMeta.text);
	hooks.emitSafeSummary(analyzed.summary);
	return analyzed;
}

/**
 * Session coordinator: Tier-0 always-on attribution + gated Tier-1 snapshots.
 */
export class HeapDiagnosisCoordinator {
	private _captureState = createHeapCaptureRateLimitState();
	private _attributionState = createHeapAttributionRateLimitState();
	private _snapshotSeq = 0;
	private _attributionSeq = 0;
	private _continuousStarted = false;

	constructor(private readonly _hooks: HeapDiagnosisCaptureHooks) { }

	get state(): HeapCaptureRateLimitState {
		return this._captureState;
	}

	get attributionState(): HeapAttributionRateLimitState {
		return this._attributionState;
	}

	/** Start continuous Tier-0 sampling (always-on; not gate-checked). */
	async startContinuousSampling(): Promise<void> {
		await this._hooks.startSampling(this._hooks.tier0SamplingIntervalBytes);
		this._continuousStarted = true;
	}

	/**
	 * Alert path: Tier-0 attribution is always attempted (not gated).
	 * Tier-1 raw snapshot pair runs only when the internal-diagnostics gate is on.
	 */
	onMemoryAlert(): HeapAlertDispatchResult {
		const attribution = this._startTier0Attribution();
		const snapshot = this._startTier1Snapshot(/*countTowardSessionLimit*/ true);
		return { attribution, snapshot };
	}

	/** Low-cadence Tier-0 flush (not gate-checked). */
	onAttributionCadence(): { readonly started: true } | { readonly started: false; readonly reason: HeapAttributionSkipReason } {
		return this._startTier0Attribution();
	}

	/** On-demand Tier-1 command path (still gate-checked; does not consume session pair budget). */
	async captureAndDiagnoseCommand(): Promise<HeapDiagnosisCommandResult> {
		const refused = refuseHeapDiagnosisCommandIfGatedOff(this._hooks.isGateEnabled());
		if (refused) {
			return refused;
		}
		if (this._captureState.inFlight) {
			return { ok: false, reason: 'in-flight' };
		}
		this._captureState = { ...this._captureState, inFlight: true };
		const seq = ++this._snapshotSeq;
		try {
			const result = await runHeapCaptureAndDiagnose(this._hooks, seq);
			this._captureState = markHeapCaptureFinished(this._captureState, {
				nowMs: this._hooks.nowMs(),
				succeeded: true,
				countTowardSessionLimit: false,
			});
			return { ok: true, summary: result.summary };
		} catch (err) {
			this._captureState = markHeapCaptureFinished(this._captureState, {
				nowMs: this._hooks.nowMs(),
				succeeded: false,
				countTowardSessionLimit: false,
			});
			return {
				ok: false,
				reason: 'capture-failed',
				detail: err instanceof Error ? err.message : String(err),
			};
		}
	}

	private _startTier0Attribution(): { readonly started: true } | { readonly started: false; readonly reason: HeapAttributionSkipReason } {
		if (!this._continuousStarted) {
			// Best-effort: still allow if startContinuousSampling was skipped in tests
			// that inject an already-active getSamplingProfile hook.
		}
		const decision = decideTier0Attribution(this._attributionState, {
			nowMs: this._hooks.nowMs(),
		});
		this._attributionState = decision.nextState;
		if (!decision.allow) {
			return { started: false, reason: decision.reason };
		}
		const seq = ++this._attributionSeq;
		void this._runTier0(seq);
		return { started: true };
	}

	private _startTier1Snapshot(countTowardSessionLimit: boolean): { readonly started: true } | { readonly started: false; readonly reason: HeapCaptureSkipReason } {
		const decision = decideAutomaticHeapCapture(this._captureState, {
			nowMs: this._hooks.nowMs(),
			gateEnabled: this._hooks.isGateEnabled(),
		});
		this._captureState = decision.nextState;
		if (!decision.allow) {
			return { started: false, reason: decision.reason };
		}
		const seq = ++this._snapshotSeq;
		void this._runTier1(seq, countTowardSessionLimit);
		return { started: true };
	}

	private async _runTier0(seq: number): Promise<void> {
		try {
			await runTier0SamplingAttribution(this._hooks, seq);
			this._attributionState = markTier0AttributionFinished(this._attributionState, {
				nowMs: this._hooks.nowMs(),
				succeeded: true,
			});
		} catch {
			this._attributionState = markTier0AttributionFinished(this._attributionState, {
				nowMs: this._hooks.nowMs(),
				succeeded: false,
			});
		}
	}

	private async _runTier1(seq: number, countTowardSessionLimit: boolean): Promise<void> {
		try {
			await runHeapCaptureAndDiagnose(this._hooks, seq);
			this._captureState = markHeapCaptureFinished(this._captureState, {
				nowMs: this._hooks.nowMs(),
				succeeded: true,
				countTowardSessionLimit,
			});
		} catch {
			this._captureState = markHeapCaptureFinished(this._captureState, {
				nowMs: this._hooks.nowMs(),
				succeeded: false,
				countTowardSessionLimit,
			});
		}
	}
}

/** Build extension-location refs from EH registry descriptions. */
export function extensionLocationsFromDescriptions(
	descriptions: ReadonlyArray<{ readonly identifier: { readonly value: string }; readonly extensionLocation: URI }>,
): ExtensionLocationRef[] {
	return descriptions.map(d => ({
		id: d.identifier.value,
		location: d.extensionLocation,
	}));
}
