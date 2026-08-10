/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { defineDebugProbe } from '../logDebugProbe.js';

/**
 * Registry smoke probe for the debug-telemetry scaffold (u33).
 * Not wired to production call sites — exists so enumerate has a real module
 * and agents can copy the shape.
 */
export const DbgScaffoldSmoke = defineDebugProbe({
	probeId: 'dbg-scaffold-smoke',
	owner: 'agent:u33',
	createdAt: '2026-08-10',
	issueRef: 'anyarchive#u33',
	issue: 'anyarchive#u33',
	ttlDays: 90,
	expiresAt: '2026-11-08',
	comment: 'Scaffold smoke: numeric bucket only; no call sites.',
	gdpr: {
		owner: 'agent:u33',
		comment: 'Numeric smoke measurement; no user data.',
		rssMb: { classification: 'SystemMetaData', purpose: 'PerformanceAndHealth', comment: 'RSS in MB', isMeasurement: true },
		bucket: { classification: 'SystemMetaData', purpose: 'PerformanceAndHealth', comment: 'severity bucket enum' },
	},
} as const);
