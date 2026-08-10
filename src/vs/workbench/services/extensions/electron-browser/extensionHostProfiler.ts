/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IExtensionHostProfile, IExtensionService, ProfileSession } from '../common/extensions.js';
import { IExtensionDescription } from '../../../../platform/extensions/common/extensions.js';
import { Schemas } from '../../../../base/common/network.js';
import { URI } from '../../../../base/common/uri.js';
import { IV8InspectProfilingService, IV8Profile } from '../../../../platform/profiling/common/profiling.js';
import { createSingleCallFunction } from '../../../../base/common/functional.js';
import { distillProfileByUrlCategory } from '../common/profileDistill.js';

export class ExtensionHostProfiler {

	constructor(
		private readonly _host: string,
		private readonly _port: number,
		@IExtensionService private readonly _extensionService: IExtensionService,
		@IV8InspectProfilingService private readonly _profilingService: IV8InspectProfilingService,
	) {
	}

	public async start(): Promise<ProfileSession> {

		const id = await this._profilingService.startProfiling({ host: this._host, port: this._port });

		return {
			stop: createSingleCallFunction(async () => {
				const profile = await this._profilingService.stopProfiling(id);
				await this._extensionService.whenInstalledExtensionsRegistered();
				const extensions = this._extensionService.extensions;
				return this._distill(profile, extensions);
			})
		};
	}

	private _distill(profile: IV8Profile, extensions: readonly IExtensionDescription[]): IExtensionHostProfile {
		// Same install-path keys as the pre-extract `_distill` (URI.file(fsPath)).
		const categories: Array<[string, string]> = [];
		for (const extension of extensions) {
			if (extension.extensionLocation.scheme === Schemas.file) {
				categories.push([URI.file(extension.extensionLocation.fsPath).toString(true), extension.identifier.value]);
			}
		}
		const distilled = distillProfileByUrlCategory(profile, categories);
		return {
			startTime: distilled.startTime,
			endTime: distilled.endTime,
			deltas: distilled.deltas,
			ids: distilled.ids,
			data: profile,
			getAggregatedTimes: () => distilled.getAggregatedTimes(),
		};
	}
}
