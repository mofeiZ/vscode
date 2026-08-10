/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Disposable } from '../../../base/common/lifecycle.js';
import { joinPath } from '../../../base/common/resources.js';
import { generateUuid } from '../../../base/common/uuid.js';
import { IConfigurationService } from '../../../platform/configuration/common/configuration.js';
import { CommandsRegistry } from '../../../platform/commands/common/commands.js';
import { IEnvironmentService } from '../../../platform/environment/common/environment.js';
import { ILogger, ILoggerService } from '../../../platform/log/common/log.js';
import { IProductService } from '../../../platform/product/common/productService.js';
import { ClassifiedEvent, IGDPRProperty, OmitMetadata, StrictPropertyCheck } from '../../../platform/telemetry/common/gdprTypings.js';
import { ITelemetryService, TelemetryLevel, TELEMETRY_OLD_SETTING_ID, TELEMETRY_SETTING_ID, ITelemetryData } from '../../../platform/telemetry/common/telemetry.js';
import { detectTelemetryUserData, formatTelemetryGuardViolation } from '../../../platform/telemetry/common/telemetryDataGuard.js';
import { supportsTelemetry } from '../../../platform/telemetry/common/telemetryUtils.js';
import { IWorkspaceContextService } from '../../../platform/workspace/common/workspace.js';
import { IWorkbenchEnvironmentService } from '../../services/environment/common/environmentService.js';
import { extHostNamedCustomer, IExtHostContext } from '../../services/extensions/common/extHostCustomers.js';
import { ExtensionHostKind } from '../../services/extensions/common/extensionHostKind.js';
import { localProcessExtensionHostLogId, localProcessExtensionHostLogsPath } from '../../services/extensions/common/extensionRunningLocation.js';
import { ExtHostContext, ExtHostTelemetryShape, MainContext, MainThreadTelemetryShape } from '../common/extHost.protocol.js';

@extHostNamedCustomer(MainContext.MainThreadTelemetry)
export class MainThreadTelemetry extends Disposable implements MainThreadTelemetryShape {
	private readonly _proxy: ExtHostTelemetryShape;

	private static readonly _name = 'pluginHostTelemetry';

	private readonly _sessionCanary: string;
	private readonly _dataGuardLogger: ILogger;
	/** LocalProcess affinity from u25; stamped onto per-EH memory events. */
	private readonly _affinity: number;

	constructor(
		extHostContext: IExtHostContext,
		@ITelemetryService private readonly _telemetryService: ITelemetryService,
		@IConfigurationService private readonly _configurationService: IConfigurationService,
		@IEnvironmentService private readonly _environmentService: IEnvironmentService,
		@IProductService private readonly _productService: IProductService,
		@IWorkspaceContextService private readonly _workspaceContextService: IWorkspaceContextService,
		@IWorkbenchEnvironmentService private readonly _workbenchEnvironmentService: IWorkbenchEnvironmentService,
		@ILoggerService loggerService: ILoggerService,
	) {
		super();

		this._proxy = extHostContext.getProxy(ExtHostContext.ExtHostTelemetry);
		this._sessionCanary = `ANYARCHIVE_TEL_CANARY_${generateUuid()}`;
		// LocalProcess affinity hosts each get their own telemetry-guard.log; other
		// kinds keep the window default extHostLogsPath (affinity ignored).
		const affinity = extHostContext.affinity ?? 0;
		this._affinity = affinity;
		const guardLogsPath = extHostContext.extensionHostKind === ExtensionHostKind.LocalProcess
			? localProcessExtensionHostLogsPath(this._workbenchEnvironmentService.extHostLogsPath, affinity)
			: this._workbenchEnvironmentService.extHostLogsPath;
		this._dataGuardLogger = this._register(loggerService.createLogger(
			joinPath(guardLogsPath, 'telemetry-guard.log'),
			{
				id: localProcessExtensionHostLogId('telemetryDataGuardMain', extHostContext.extensionHostKind === ExtensionHostKind.LocalProcess ? affinity : 0),
				name: 'Telemetry Data Guard',
				logLevel: 'always',
				hidden: true,
			}
		));

		this._refreshDataGuardMarkers();
		this._register(this._workspaceContextService.onDidChangeWorkspaceFolders(() => this._refreshDataGuardMarkers()));

		if (supportsTelemetry(this._productService, this._environmentService)) {
			this._register(this._configurationService.onDidChangeConfiguration(e => {
				if (e.affectsConfiguration(TELEMETRY_SETTING_ID) || e.affectsConfiguration(TELEMETRY_OLD_SETTING_ID)) {
					this._proxy.$onDidChangeTelemetryLevel(this.telemetryLevel);
				}
			}));
		}
		// sr1#3: propagate session canary so Path B `_dataGuardMarkers` includes it.
		this._proxy.$initializeTelemetryLevel(
			this.telemetryLevel,
			supportsTelemetry(this._productService, this._environmentService),
			this._productService.enabledTelemetryLevels,
			this._sessionCanary,
		);
	}

	private _refreshDataGuardMarkers(): void {
		const folderPaths = this._workspaceContextService.getWorkspace().folders.map(f => f.uri.fsPath);
		this._telemetryService.setDataGuardMarkers?.([...folderPaths, this._sessionCanary]);
	}

	private get telemetryLevel(): TelemetryLevel {
		if (!supportsTelemetry(this._productService, this._environmentService)) {
			return TelemetryLevel.NONE;
		}

		return this._telemetryService.telemetryLevel;
	}

	$publicLog(eventName: string, data: ITelemetryData = Object.create(null)): void {
		// __GDPR__COMMON__ "pluginHostTelemetry" : { "classification": "SystemMetaData", "purpose": "FeatureInsight", "isMeasurement": true }
		data[MainThreadTelemetry._name] = true;

		// Per-EH memory / heap-attribution events: stamp affinity main-thread-side (EH does not know it).
		if (
			eventName === 'exthostMemorySample'
			|| eventName === 'exthostMemoryAlert'
			|| eventName === 'exthostHeapAttribution'
			|| eventName === 'exthostLongTask'
			|| eventName === 'exthostEventLoopLag'
		) {
			data['affinity'] = this._affinity;
		}

		// Pre-check so EH IPC violations are attributed here even if core telemetry is Null.
		const markers = [
			...this._workspaceContextService.getWorkspace().folders.map(f => f.uri.fsPath),
			this._sessionCanary,
		];
		const guard = detectTelemetryUserData(data, {
			markers,
			// See TelemetryService._doLog: Path A uses normalize + bounds, not the
			// Path B string allowlist (keeps first-party EH telemetry working).
			boundMeasurements: true,
			failClosedOnDepthAbort: true,
			eventName,
		});
		if (guard.hit) {
			this._dataGuardLogger.info(formatTelemetryGuardViolation({
				timestamp: new Date().toISOString(),
				eventName,
				layer: guard.layer,
				detail: guard.detail,
				pluginHostTelemetry: true,
				pipe: 'core',
			}));
			return;
		}

		this._telemetryService.publicLog(eventName, data);
	}

	$publicLog2<E extends ClassifiedEvent<OmitMetadata<T>> = never, T extends IGDPRProperty = never>(eventName: string, data?: StrictPropertyCheck<T, E>): void {
		this.$publicLog(eventName, data);
	}
}

/**
 * The core telemetry property under which the Copilot CAPI flight assignment
 * context is surfaced. It mirrors the scope of `abexp.assignmentcontext`.
 */
export const CAPI_ASSIGNMENT_CONTEXT_PROPERTY = 'capi.assignmentcontext';

/**
 * The private command Copilot invokes to forward its CAPI flight assignments
 * into core telemetry. Not part of the public API.
 */
export const SET_CAPI_ASSIGNMENT_CONTEXT_COMMAND = '_telemetry.setCapiAssignmentContext';

const MAX_CAPI_ASSIGNMENT_CONTEXT_LENGTH = 8 * 1024;
const CAPI_ASSIGNMENT_CONTEXT_ENTRY_PATTERN = /^[^:;\s\x00-\x1F\x7F]+:[^;\x00-\x1F\x7F]+$/;

/**
 * Validates a CAPI assignment-context string before it is trusted onto every
 * core telemetry event. Because {@link ITelemetryService.setExperimentProperty}
 * wraps the value in a `TelemetryTrustedValue` (bypassing PII cleaning), the
 * value must be strictly shaped: a non-empty, size-capped list of `key:value`
 * entries separated by `;`, with no whitespace or control characters. Any
 * malformed input is rejected outright.
 */
export function isValidCapiAssignmentContext(value: string): boolean {
	if (value.length === 0 || value.length > MAX_CAPI_ASSIGNMENT_CONTEXT_LENGTH) {
		return false;
	}

	// Tolerate a single trailing separator (`a:b;`) but nothing else empty.
	const entries = value.endsWith(';') ? value.slice(0, -1).split(';') : value.split(';');
	return entries.length > 0 && entries.every(entry => CAPI_ASSIGNMENT_CONTEXT_ENTRY_PATTERN.test(entry));
}

CommandsRegistry.registerCommand(SET_CAPI_ASSIGNMENT_CONTEXT_COMMAND, function (accessor, value: string) {
	if (typeof value !== 'string' || !isValidCapiAssignmentContext(value)) {
		return;
	}

	accessor.get(ITelemetryService).setExperimentProperty(CAPI_ASSIGNMENT_CONTEXT_PROPERTY, value);
});

/**
 * Dev/demo hook: extensions invoke this to exercise Path A
 * (ITelemetryService._doLog with pluginHostTelemetry) with a deliberate
 * user-data payload. Not part of the public API.
 */
export const PROBE_DATA_GUARD_PUBLIC_LOG_COMMAND = '_telemetry.probeDataGuardPublicLog';

CommandsRegistry.registerCommand(PROBE_DATA_GUARD_PUBLIC_LOG_COMMAND, function (accessor, data?: ITelemetryData) {
	const telemetry = accessor.get(ITelemetryService);
	const env = accessor.get(IWorkbenchEnvironmentService);
	const loggerService = accessor.get(ILoggerService);
	const workspace = accessor.get(IWorkspaceContextService);
	const payload: ITelemetryData = {
		...(data && typeof data === 'object' ? data : {}),
		pluginHostTelemetry: true,
	};
	const markers = workspace.getWorkspace().folders.map(f => f.uri.fsPath);
	const guard = detectTelemetryUserData(payload, markers);
	if (guard.hit) {
		const logger = loggerService.createLogger(
			joinPath(env.extHostLogsPath, 'telemetry-guard.log'),
			{
				id: 'telemetryDataGuardProbe',
				name: 'Telemetry Data Guard',
				logLevel: 'always',
				hidden: true,
			}
		);
		logger.info(formatTelemetryGuardViolation({
			timestamp: new Date().toISOString(),
			eventName: 'anyarchive.probe.core',
			layer: guard.layer,
			detail: guard.detail,
			pluginHostTelemetry: true,
			pipe: 'core',
		}));
		return { blocked: true, layer: guard.layer };
	}
	telemetry.publicLog('anyarchive.probe.core', payload);
	return { blocked: false };
});
