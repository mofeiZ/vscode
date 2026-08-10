/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as performance from '../../../base/common/performance.js';
import type * as vscode from 'vscode';
import { createApiFactoryAndRegisterActors } from '../common/extHost.api.impl.js';
import { INodeModuleFactory, RequireInterceptor } from '../common/extHostRequireInterceptor.js';
import { ExtensionActivationTimesBuilder } from '../common/extHostExtensionActivator.js';
import { connectProxyResolver } from './proxyResolver.js';
import { AbstractExtHostExtensionService } from '../common/extHostExtensionService.js';
import { ExtHostDownloadService } from './extHostDownloadService.js';
import { URI } from '../../../base/common/uri.js';
import { Schemas } from '../../../base/common/network.js';
import { IExtensionDescription } from '../../../platform/extensions/common/extensions.js';
import { ExtensionRuntime } from '../common/extHostTypes.js';
import { CLIServer } from './extHostCLIServer.js';
import { realpathSync } from '../../../base/node/pfs.js';
import { ExtHostConsoleForwarder } from './extHostConsoleForwarder.js';
import { ExtHostDiskFileSystemProvider } from './extHostDiskFileSystemProvider.js';
import nodeModule from 'node:module';
import { assertType } from '../../../base/common/types.js';
import { generateUuid } from '../../../base/common/uuid.js';
import { BidirectionalMap } from '../../../base/common/map.js';
import { DisposableStore, toDisposable } from '../../../base/common/lifecycle.js';
import { IntervalTimer, timeout } from '../../../base/common/async.js';
import { joinPath } from '../../../base/common/resources.js';
import { ILogger, ILoggerService } from '../../../platform/log/common/log.js';
import { isInternalDiagnosticsEnabled } from '../../services/extensions/common/diagnosticIsolation.js';
import {
	buildMemoryAlertTelemetryPayload,
	buildMemorySample,
	buildMemoryTelemetryPayload,
	createMemoryAlertState,
	decideMemoryAlert,
	formatMemoryLogLine,
	MEMORY_SAMPLE_INTERVAL_MS,
	MemoryAlertState,
	MemorySampleRing,
	shouldEmitMemorySampleTelemetry,
} from '../../services/extensions/common/extensionHostMemoryMonitor.js';
import {
	extensionLocationsFromDescriptions,
	HEAP_DIAGNOSIS_EH_COMMAND_ID,
	HeapDiagnosisCoordinator,
} from '../../services/extensions/common/extensionHostHeapWiring.js';
import {
	decodeSnapshotFile,
	extractClassGroups,
	startAllocationSampling,
	stopAndGetProfile,
	writeSnapshot,
} from '../../services/extensions/node/extensionHostHeapCapture.js';
import { IExtHostCommands } from '../common/extHostCommands.js';
const require = nodeModule.createRequire(import.meta.url);

class NodeModuleRequireInterceptor extends RequireInterceptor {

	private static _createDataUri(scriptContent: string): string {
		return `data:text/javascript;base64,${Buffer.from(scriptContent).toString('base64')}`;
	}

	private static _vscodeImportFnName = `_VSCODE_IMPORT_VSCODE_API`;

	private readonly _store = new DisposableStore();

	dispose(): void {
		this._store.dispose();
	}

	protected _installInterceptor(): void {
		const that = this;
		const node_module = require('module');
		const originalLoad = node_module._load;
		node_module._load = function load(request: string, parent: { filename: string }, isMain: boolean) {
			request = applyAlternatives(request);
			if (!that._factories.has(request)) {
				return originalLoad.apply(this, arguments);
			}
			return that._factories.get(request)!.load(
				request,
				URI.file(realpathSync(parent.filename)),
				request => originalLoad.apply(this, [request, parent, isMain])
			);
		};

		const originalLookup = node_module._resolveLookupPaths;
		node_module._resolveLookupPaths = (request: string, parent: unknown) => {
			return originalLookup.call(this, applyAlternatives(request), parent);
		};

		const originalResolveFilename = node_module._resolveFilename;
		node_module._resolveFilename = function resolveFilename(request: string, parent: unknown, isMain: boolean, options?: { paths?: string[] }) {
			if (request === 'vsda' && Array.isArray(options?.paths) && options.paths.length === 0) {
				// ESM: ever since we moved to ESM, `require.main` will be `undefined` for extensions
				// Some extensions have been using `require.resolve('vsda', { paths: require.main.paths })`
				// to find the `vsda` module in our app root. To be backwards compatible with this pattern,
				// we help by filling in the `paths` array with the node modules paths of the current module.
				options.paths = node_module._nodeModulePaths(import.meta.dirname);
			}
			return originalResolveFilename.call(this, request, parent, isMain, options);
		};

		const applyAlternatives = (request: string) => {
			for (const alternativeModuleName of that._alternatives) {
				const alternative = alternativeModuleName(request);
				if (alternative) {
					request = alternative;
					break;
				}
			}
			return request;
		};

		const apiInstances = new BidirectionalMap<typeof vscode, string>();
		const apiImportDataUrl = new Map<string, string>();

		// define a global function that can be used to get API instances given a random key
		Object.defineProperty(globalThis, NodeModuleRequireInterceptor._vscodeImportFnName, {
			enumerable: false,
			configurable: false,
			writable: false,
			value: (key: string) => {
				return apiInstances.getKey(key);
			}
		});

		let apiModuleFactory: INodeModuleFactory | undefined;

		const lookup = (url: string): string => {
			// Get the vscode-module factory - which is the same logic that's also used by
			// the CommonJS require interceptor
			if (!apiModuleFactory) {
				apiModuleFactory = this._factories.get('vscode');
				assertType(apiModuleFactory);
			}

			const uri = URI.parse(url);

			// Get or create the API instance. The interface is per extension and extensions are
			// looked up by the uri (e.data.url) and path containment.
			const apiInstance = apiModuleFactory.load('_not_used', uri, () => { throw new Error('CANNOT LOAD MODULE from here.'); });
			let key = apiInstances.get(apiInstance);
			if (!key) {
				key = generateUuid();
				apiInstances.set(apiInstance, key);
			}

			// Create and cache a data-url which is the import script for the API instance
			let scriptDataUrlSrc = apiImportDataUrl.get(key);
			if (!scriptDataUrlSrc) {
				const jsCode = `const _vscodeInstance = globalThis.${NodeModuleRequireInterceptor._vscodeImportFnName}('${key}');\n\n${Object.keys(apiInstance).map((name => `export const ${name} = _vscodeInstance['${name}'];`)).join('\n')}`;
				scriptDataUrlSrc = NodeModuleRequireInterceptor._createDataUri(jsCode);
				apiImportDataUrl.set(key, scriptDataUrlSrc);
			}
			return scriptDataUrlSrc;
		};
		const hooks = nodeModule.registerHooks({
			resolve: (specifier, context, nextResolve) => {
				if (specifier !== 'vscode' || !context.parentURL) {
					return nextResolve(specifier, context);
				}
				const otherUrl = lookup(context.parentURL);
				return {
					url: otherUrl,
					shortCircuit: true,
				};
			},
		});
		this._store.add(toDisposable(() => hooks.deregister()));
	}
}

export class ExtHostExtensionService extends AbstractExtHostExtensionService {

	readonly extensionRuntime = ExtensionRuntime.Node;

	private _memorySampleSeq = 0;
	private _memoryAlertState: MemoryAlertState = createMemoryAlertState();
	private readonly _memorySampleRing = new MemorySampleRing();
	private _memoryLogger: ILogger | undefined;
	private _heapDiagnosis: HeapDiagnosisCoordinator | undefined;

	protected async _beforeAlmostReadyToRunExtensions(): Promise<void> {
		// make sure console.log calls make it to the render
		this._instaService.createInstance(ExtHostConsoleForwarder);

		// initialize API and register actors
		const extensionApiFactory = this._instaService.invokeFunction(createApiFactoryAndRegisterActors);

		// Register Download command
		this._instaService.createInstance(ExtHostDownloadService);

		// Register CLI Server for ipc
		if (this._initData.remote.isRemote && this._initData.remote.authority) {
			const cliServer = this._instaService.createInstance(CLIServer);
			process.env['VSCODE_IPC_HOOK_CLI'] = cliServer.ipcHandlePath;
		}

		// Register local file system shortcut
		this._instaService.createInstance(ExtHostDiskFileSystemProvider);

		// Module loading tricks based on `module._load`.
		// `module._load` intercepts `require(...)`.
		// Module loading tricks based on `module.registerHooks`.
		// `module.registerHooks` is a generic interceptor that intercepts `require(...)`, `import ...`, and `import(...)`.
		await this._store.add(this._instaService.createInstance(NodeModuleRequireInterceptor, extensionApiFactory, { mine: this._myRegistry, all: this._globalRegistry }))
			.install();

		performance.mark('code/extHost/didInitAPI');

		// Do this when extension service exists, but extensions are not being activated yet.
		const configProvider = await this._extHostConfiguration.getConfigProvider();
		await connectProxyResolver(this._extHostWorkspace, configProvider, this, this._logService, this._mainThreadTelemetryProxy, this._initData, this._store);
		performance.mark('code/extHost/didInitProxyResolver');

		// Per-EH memory sampler (numbers/buckets only → guarded Path A + local metrics).
		this._startExtensionHostMemoryMonitor();
		this._startHeapDiagnosisWiring();
	}

	private _startHeapDiagnosisWiring(): void {
		const artifactDirFsPath = this._initData.logsLocation.fsPath;
		this._heapDiagnosis = new HeapDiagnosisCoordinator({
			writeSnapshot,
			startSampling: startAllocationSampling,
			stopAndGetProfile,
			extractClassGroupsFromSnapshot: async (path) => extractClassGroups(await decodeSnapshotFile(path)),
			delay: (ms) => timeout(ms),
			nowMs: () => Date.now(),
			listExtensionLocations: () => extensionLocationsFromDescriptions(this._myRegistry.getAllExtensionDescriptions()),
			artifactDirFsPath,
			pid: this._hostUtils.pid ?? process.pid,
			affinity: 0, // stamped main-thread-side on telemetry emit
			emitSafeSummary: (summary) => {
				type ExtHostHeapAttributionClassification = {
					owner: 'anyarchive';
					comment: 'Guard-safe heap attribution summary after alert/on-demand capture. Opaque ids + buckets only.';
					schema: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Summary schema version' };
					affinity: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Host affinity (main-stamped)' };
					pid: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Opaque process id' };
					snapshotSeq: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Capture pair sequence' };
					extensions: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; comment: 'Top opaque extension attribution rows' };
					grownClassGroups: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; comment: 'Top opaque grown class-group rows' };
					topDominatorRetainedBucketMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Top dominator retained bucket MB' };
					dominatorDepth: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Dominator depth shape' };
					dominatorFanout: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Dominator fanout shape' };
					retainedTopSharePct: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Top dominator share of growth' };
					retainerPathLen: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Retainer path length shape' };
				};
				this._mainThreadTelemetryProxy.$publicLog2<typeof summary, ExtHostHeapAttributionClassification>(
					'exthostHeapAttribution',
					summary,
				);
			},
			logLocalReport: (text) => {
				this._memoryLogger?.info(text);
				this._logService.info(`[exthostHeapDiagnosis]\n${text}`);
			},
			isGateEnabled: () => isInternalDiagnosticsEnabled(),
		});

		const commands = this._instaService.invokeFunction(accessor => accessor.get(IExtHostCommands));
		this._store.add(commands.registerCommand(true, HEAP_DIAGNOSIS_EH_COMMAND_ID, async () => {
			if (!this._heapDiagnosis) {
				return { ok: false, reason: 'capture-failed', detail: 'not-initialized' };
			}
			return this._heapDiagnosis.captureAndDiagnoseCommand();
		}));
	}

	private _startExtensionHostMemoryMonitor(): void {
		const loggerService = this._instaService.invokeFunction(accessor => accessor.get(ILoggerService));
		this._memoryLogger = this._store.add(loggerService.createLogger(
			joinPath(this._initData.logsLocation, 'exthost-memory.log'),
			{
				id: 'exthostMemory',
				name: 'Extension Host Memory',
				logLevel: 'always',
				hidden: true,
			}
		));

		const timer = this._store.add(new IntervalTimer());
		const takeSample = () => {
			try {
				this._takeExtensionHostMemorySample();
			} catch (err) {
				this._logService.warn('[exthostMemory] sample failed', err);
			}
		};
		// Baseline immediately, then every ~30s.
		takeSample();
		timer.cancelAndSet(takeSample, MEMORY_SAMPLE_INTERVAL_MS);
	}

	private _takeExtensionHostMemorySample(): void {
		this._memorySampleSeq++;
		const sample = buildMemorySample({
			usage: process.memoryUsage(),
			uptimeSec: process.uptime(),
			sampleSeq: this._memorySampleSeq,
			pid: this._hostUtils.pid ?? process.pid,
			tsMs: Date.now(),
			ring: this._memorySampleRing,
		});

		this._memoryLogger?.info(formatMemoryLogLine(sample, 'SAMPLE'));

		type ExtHostMemorySampleClassification = {
			owner: 'anyarchive';
			comment: 'Per-extension-host memory heartbeat (bucketed RSS + heap). Numbers only.';
			rssBucketMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'RSS bucket edge in MB' };
			heapUsedMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'V8 heapUsed in MB' };
			heapTotalMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'V8 heapTotal in MB' };
			externalMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'V8 external memory in MB' };
			growthMbPerMin: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'RSS growth rate MB/min over recent samples' };
			uptimeSec: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Process uptime seconds' };
			sampleSeq: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Monotonic sample sequence' };
			pid: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Opaque process id' };
		};
		type ExtHostMemorySampleEvent = {
			rssBucketMb: number;
			heapUsedMb: number;
			heapTotalMb: number;
			externalMb: number;
			growthMbPerMin: number;
			uptimeSec: number;
			sampleSeq: number;
			pid: number;
		};

		if (shouldEmitMemorySampleTelemetry(sample.sampleSeq)) {
			this._mainThreadTelemetryProxy.$publicLog2<ExtHostMemorySampleEvent, ExtHostMemorySampleClassification>(
				'exthostMemorySample',
				buildMemoryTelemetryPayload(sample),
			);
		}

		const decision = decideMemoryAlert(
			{ rssBucketMb: sample.rssBucketMb, growthMbPerMin: sample.growthMbPerMin },
			this._memoryAlertState,
			{ nowMs: sample.tsMs },
		);
		this._memoryAlertState = decision.nextState;
		if (!decision.fire || !decision.trigger) {
			return;
		}

		const alertLine = formatMemoryLogLine(sample, 'ALERT', decision.trigger);
		this._memoryLogger?.info(alertLine);
		// Numbers-only breadcrumb in the EH/window log for discoverability (parity with u5 stderr trick).
		this._logService.warn(`[exthostMemory] ${alertLine}`);

		type ExtHostMemoryAlertClassification = {
			owner: 'anyarchive';
			comment: 'Per-extension-host memory alert (level crossing or growth rate). Numbers/enums only.';
			rssBucketMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'RSS bucket edge in MB' };
			heapUsedMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'V8 heapUsed in MB' };
			heapTotalMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'V8 heapTotal in MB' };
			externalMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'V8 external memory in MB' };
			growthMbPerMin: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'RSS growth rate MB/min over recent samples' };
			uptimeSec: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Process uptime seconds' };
			sampleSeq: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Monotonic sample sequence' };
			pid: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Opaque process id' };
			trigger: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; comment: 'level | growth' };
			thresholdBucketMb: { classification: 'SystemMetaData'; purpose: 'PerformanceAndHealth'; isMeasurement: true; comment: 'Configured level threshold bucket MB' };
		};
		type ExtHostMemoryAlertEvent = ExtHostMemorySampleEvent & {
			trigger: string;
			thresholdBucketMb: number;
		};

		this._mainThreadTelemetryProxy.$publicLog2<ExtHostMemoryAlertEvent, ExtHostMemoryAlertClassification>(
			'exthostMemoryAlert',
			buildMemoryAlertTelemetryPayload(sample, decision.trigger, decision.thresholdBucketMb ?? 3072),
		);

		// DETECT → ATTRIBUTE/DIAGNOSE: rate-limited heap snapshot pair + safe summary.
		// Automatic capture is Tier-1 (internal-diagnostics gate); sampler alert itself stays Tier-0.
		const heap = this._heapDiagnosis?.onMemoryAlert();
		if (heap && !heap.started) {
			this._logService.trace(`[exthostHeapDiagnosis] alert capture skipped: ${heap.reason}`);
		}
	}

	protected _getEntryPoint(extensionDescription: IExtensionDescription): string | undefined {
		return extensionDescription.main;
	}

	private async _doLoadModule<T>(extension: IExtensionDescription | null, module: URI, activationTimesBuilder: ExtensionActivationTimesBuilder, mode: 'esm' | 'cjs'): Promise<T> {
		if (module.scheme !== Schemas.file) {
			throw new Error(`Cannot load URI: '${module}', must be of file-scheme`);
		}
		let r: T | null = null;
		activationTimesBuilder.codeLoadingStart();
		this._logService.trace(`ExtensionService#loadModule [${mode}] -> ${module.toString(true)}`);
		this._logService.flush();
		const extensionId = extension?.identifier.value;
		if (extension) {
			await this._extHostLocalizationService.initializeLocalizedMessages(extension);
		}
		try {
			if (extensionId) {
				performance.mark(`code/extHost/willLoadExtensionCode/${extensionId}`);
			}
			if (mode === 'esm') {
				r = <T>await import(module.toString(true));
			} else {
				r = <T>require(module.fsPath);
			}
		} finally {
			if (extensionId) {
				performance.mark(`code/extHost/didLoadExtensionCode/${extensionId}`);
			}
			activationTimesBuilder.codeLoadingStop();
		}
		return r;
	}

	protected async _loadCommonJSModule<T>(extension: IExtensionDescription | null, module: URI, activationTimesBuilder: ExtensionActivationTimesBuilder): Promise<T> {
		return this._doLoadModule<T>(extension, module, activationTimesBuilder, 'cjs');
	}

	protected async _loadESMModule<T>(extension: IExtensionDescription | null, module: URI, activationTimesBuilder: ExtensionActivationTimesBuilder): Promise<T> {
		return this._doLoadModule<T>(extension, module, activationTimesBuilder, 'esm');
	}

	public async $setRemoteEnvironment(env: { [key: string]: string | null }): Promise<void> {
		if (!this._initData.remote.isRemote) {
			return;
		}

		for (const key in env) {
			const value = env[key];
			if (value === null) {
				delete process.env[key];
			} else {
				process.env[key] = value;
			}
		}
	}
}
