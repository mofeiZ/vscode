/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { dirname, joinPath } from '../../../../base/common/resources.js';
import { URI } from '../../../../base/common/uri.js';
import { ExtensionHostKind } from './extensionHostKind.js';

export class LocalProcessRunningLocation {
	public readonly kind = ExtensionHostKind.LocalProcess;
	constructor(
		public readonly affinity: number
	) { }
	public equals(other: ExtensionRunningLocation) {
		return (this.kind === other.kind && this.affinity === other.affinity);
	}
	public asString(): string {
		if (this.affinity === 0) {
			return 'LocalProcess';
		}
		return `LocalProcess${this.affinity}`;
	}
}

export class LocalWebWorkerRunningLocation {
	public readonly kind = ExtensionHostKind.LocalWebWorker;
	constructor(
		public readonly affinity: number
	) { }
	public equals(other: ExtensionRunningLocation) {
		return (this.kind === other.kind && this.affinity === other.affinity);
	}
	public asString(): string {
		if (this.affinity === 0) {
			return 'LocalWebWorker';
		}
		return `LocalWebWorker${this.affinity}`;
	}
}

export class RemoteRunningLocation {
	public readonly kind = ExtensionHostKind.Remote;
	public readonly affinity = 0;
	public equals(other: ExtensionRunningLocation) {
		return (this.kind === other.kind);
	}
	public asString(): string {
		return 'Remote';
	}
}

export type ExtensionRunningLocation = LocalProcessRunningLocation | LocalWebWorkerRunningLocation | RemoteRunningLocation;

/**
 * Per-affinity log root for local process extension hosts.
 * Affinity 0 keeps the window default (`…/exthost`); affinity N uses sibling `…/exthostN`
 * so stderr / telemetry-guard from an isolated host do not share files with the default host.
 */
export function localProcessExtensionHostLogsPath(extHostLogsPath: URI, affinity: number): URI {
	if (!affinity) {
		return extHostLogsPath;
	}
	return joinPath(dirname(extHostLogsPath), `exthost${affinity}`);
}

/** Distinct logger id when multiple local process hosts register under the same window. */
export function localProcessExtensionHostLogId(baseId: string, affinity: number): string {
	return affinity ? `${baseId}.${affinity}` : baseId;
}
