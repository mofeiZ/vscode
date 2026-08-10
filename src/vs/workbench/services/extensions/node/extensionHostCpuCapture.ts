/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * In-EH short CPU sampling profile (r15 Category B / P-B Layer 2).
 *
 * Uses in-process `node:inspector` `Profiler.*` — same transport choice as
 * r11 heap allocation sampling. Raw `.cpuprofile` stays local; only the
 * guard-safe summary from `extensionHostCpuMonitor` is telemetered.
 */

import type { Session } from 'node:inspector';
import type { IV8Profile } from '../../../../platform/profiling/common/profiling.js';
import { CPU_PROFILE_DURATION_MS } from '../common/extensionHostCpuMonitor.js';
import { timeout } from '../../../../base/common/async.js';

let cpuProfileInFlight = false;

export function isCpuProfileInFlight(): boolean {
	return cpuProfileInFlight;
}

/**
 * Capture a short V8 sampling profile in-process.
 * Returns undefined if another capture is already running or inspector fails.
 */
export async function captureShortCpuProfile(durationMs: number = CPU_PROFILE_DURATION_MS): Promise<IV8Profile | undefined> {
	if (cpuProfileInFlight) {
		return undefined;
	}
	cpuProfileInFlight = true;
	let session: Session | undefined;
	try {
		const inspector = await import('node:inspector');
		session = new inspector.Session();
		session.connect();
		await post(session, 'Profiler.enable');
		await post(session, 'Profiler.start');
		await timeout(durationMs);
		const result = await post(session, 'Profiler.stop') as { profile: IV8Profile };
		try {
			await post(session, 'Profiler.disable');
		} catch {
			// best-effort
		}
		return result.profile;
	} catch {
		return undefined;
	} finally {
		if (session) {
			try {
				session.disconnect();
			} catch {
				// best-effort
			}
		}
		cpuProfileInFlight = false;
	}
}

function post(session: Session, method: string, params?: Record<string, unknown>): Promise<unknown> {
	return new Promise((resolve, reject) => {
		session.post(method, params ?? {}, (err, result) => {
			if (err) {
				reject(err);
			} else {
				resolve(result);
			}
		});
	});
}
