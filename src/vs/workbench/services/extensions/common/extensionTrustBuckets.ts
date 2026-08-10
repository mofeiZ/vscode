/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Trust-bucket affinity policy (fork).
 *
 * Opt-in production posture: when enabled, first-party/builtin extensions stay
 * on the default LocalProcess host (affinity 0) and third-party extensions are
 * placed on a separate host (affinity 1). Default OFF — no topology change
 * until product.json `trustBucketingEnabled` or env `VSCODE_TRUST_BUCKETING=1`.
 *
 * Group integrity is mandatory: callers must assign affinities per dependency /
 * extensionAffinity group after merge (never split a group). This module
 * classifies groups; `_computeAffinity` enforces the group-atomic write.
 *
 * Known consumers of builtins-with-consumable-APIs (especially vscode.git) are
 * co-located with those builtins on the trusted host so sync `.exports` /
 * `getAPI()` keep working (r14). Manifest hard-deps already merge via the
 * tracker; this allowlist covers undeclared runtime-exports consumers.
 *
 * Composes under diagnostic isolation and the user affinity setting:
 *   user > diagnostic isolation > trust bucket baseline
 *
 * Follow-ups (NOT in this unit): per-affinity crash containment (§2.6),
 * failure-quarantine ledger (Design B).
 */

import product from '../../../../platform/product/common/product.js';
import { ExtensionIdentifier, ExtensionIdentifierMap, IExtensionDescription } from '../../../../platform/extensions/common/extensions.js';
import { readOptionalProcessEnv } from './rendererSafeEnv.js';

/** product.json field (default false / absent). */
export const TRUST_BUCKETING_PRODUCT_FIELD = 'trustBucketingEnabled';

/** Env override for test / local runs: `1` / `true` enables trust bucketing. */
export const TRUST_BUCKETING_ENV = 'VSCODE_TRUST_BUCKETING';

/** Trusted / first-party bucket — default host (preserves startup semantics). */
export const TRUSTED_BUCKET_AFFINITY = 0;

/** Third-party bucket — one shared host for the untrusted population. */
export const THIRD_PARTY_BUCKET_AFFINITY = 1;

/**
 * Configured affinity number used by diagnostic isolation when trust bucketing
 * is also on, so the diagnostic host does not collide with the third-party bucket.
 * When trust bucketing is off, diagnostic isolation keeps using its own constant (1).
 */
export const DIAGNOSTIC_ISOLATION_AFFINITY_WITH_TRUST = 2;

/**
 * Builtins that expose a same-host consumable API (`.exports` / `getAPI`).
 * Their known third-party consumers must co-locate with them.
 */
export const BUILTIN_API_PROVIDER_IDS: readonly string[] = [
	'vscode.git',
	'vscode.git-base',
	'vscode.markdown-language-features',
	'vscode.typescript-language-features',
	'vscode.references-view',
	'vscode.ipynb',
];

/**
 * Known third-party consumers of {@link BUILTIN_API_PROVIDER_IDS} that omit
 * `extensionDependencies` but call `getExtension(...).exports` at runtime.
 * These stay on the trusted host with their provider (r14 prefer-completeness).
 */
export const DEFAULT_KNOWN_BUILTIN_API_CONSUMERS: Readonly<Record<string, readonly string[]>> = {
	'eamodio.gitlens': ['vscode.git', 'vscode.git-base'],
};

export interface ITrustBucketPolicy {
	readonly trustedPublishers?: readonly string[];
	readonly trustedExtensionIds?: readonly string[];
	readonly knownBuiltinApiConsumers?: Readonly<Record<string, readonly string[]>>;
}

/** Test-only override for the enablement gate (`undefined` = consult product/env). */
let _trustBucketingEnabledForTests: boolean | undefined;

function envFlagEnabled(raw: string | undefined): boolean {
	return raw === '1' || raw === 'true';
}

/**
 * Trust-bucketing enablement gate. Default OFF.
 *
 * Enabled when any of:
 * - env `VSCODE_TRUST_BUCKETING=1` / `true` (Node / test harness only)
 * - product.json `trustBucketingEnabled: true` (renderer-safe via product accessor)
 * - test override via {@link _setTrustBucketingEnabledForTests}
 *
 * Never throws when `process` is undefined (sandboxed workbench).
 */
export function isTrustBucketingEnabled(options: {
	productEnabled?: boolean;
	env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
} = {}): boolean {
	if (_trustBucketingEnabledForTests !== undefined) {
		return _trustBucketingEnabledForTests;
	}
	const env = options.env ?? readOptionalProcessEnv();
	if (envFlagEnabled(env[TRUST_BUCKETING_ENV])) {
		return true;
	}
	const productEnabled = options.productEnabled ?? (product.trustBucketingEnabled === true);
	return productEnabled === true;
}

/** Test-only: force the trust-bucketing gate on/off. Pass `undefined` to clear. */
export function _setTrustBucketingEnabledForTests(enabled: boolean | undefined): void {
	_trustBucketingEnabledForTests = enabled;
}

/**
 * Trusted iff builtin (not user-sideload builtin), trusted publisher, or exact id allowlist.
 */
export function isTrustedExtension(ext: IExtensionDescription, policy: ITrustBucketPolicy = {}): boolean {
	// Platform builtins are trusted; user-controlled "user builtin" sideloads are not.
	if (ext.isBuiltin && !ext.isUserBuiltin) {
		return true;
	}
	const id = ext.identifier.value;
	const trustedIds = policy.trustedExtensionIds;
	if (trustedIds) {
		for (const trustedId of trustedIds) {
			if (ExtensionIdentifier.equals(trustedId, id)) {
				return true;
			}
		}
	}
	const trustedPublishers = policy.trustedPublishers;
	if (trustedPublishers && ext.publisher) {
		const publisher = ext.publisher.toLowerCase();
		for (const p of trustedPublishers) {
			if (p.toLowerCase() === publisher) {
				return true;
			}
		}
	}
	return false;
}

function isKnownBuiltinApiConsumer(extensionId: string, policy: ITrustBucketPolicy): boolean {
	const map = policy.knownBuiltinApiConsumers ?? DEFAULT_KNOWN_BUILTIN_API_CONSUMERS;
	for (const consumerId of Object.keys(map)) {
		if (ExtensionIdentifier.equals(consumerId, extensionId)) {
			return true;
		}
	}
	return false;
}

function groupContainsBuiltinApiProvider(memberIds: readonly string[]): boolean {
	for (const id of memberIds) {
		for (const providerId of BUILTIN_API_PROVIDER_IDS) {
			if (ExtensionIdentifier.equals(providerId, id)) {
				return true;
			}
		}
	}
	return false;
}

export interface ITrustBucketAffinitiesResult {
	/** Extension id → configured affinity (only third-party bucket members; trusted omitted). */
	readonly affinities: { [extensionId: string]: number };
	/** Trusted extension ids demoted into the third-party bucket via group merge. */
	readonly dilutedTrustedIds: string[];
}

/**
 * Classify dependency/colocation groups into trust buckets.
 *
 * - A group is trusted (affinity 0, omitted from map) when every member is trusted,
 *   OR when it contains an allowlisted builtin API provider and we keep that
 *   provider's known consumers on the trusted host (r14).
 * - Otherwise the group goes to the third-party bucket (affinity 1).
 * - Known builtin-API consumers without a hard dep are omitted from the map so
 *   they remain on affinity 0 with their provider.
 *
 * Assigns per GROUP — never splits members. Call only after dependency /
 * extensionAffinity merge.
 */
export function buildTrustBucketAffinities(
	extensions: Iterable<IExtensionDescription>,
	groups: ExtensionIdentifierMap<number>,
	policy: ITrustBucketPolicy = {},
): ITrustBucketAffinitiesResult {
	const extById = new ExtensionIdentifierMap<IExtensionDescription>();
	for (const ext of extensions) {
		extById.set(ext.identifier, ext);
	}

	// Collect members per group number.
	const membersByGroup = new Map<number, string[]>();
	for (const [idKey, group] of groups) {
		let members = membersByGroup.get(group);
		if (!members) {
			members = [];
			membersByGroup.set(group, members);
		}
		members.push(idKey);
	}

	const affinities: { [extensionId: string]: number } = {};
	const dilutedTrustedIds: string[] = [];

	for (const [, memberIds] of membersByGroup) {
		let hasUntrusted = false;
		let hasAllowlistedConsumer = false;
		const trustedInGroup: string[] = [];

		for (const id of memberIds) {
			const ext = extById.get(id);
			if (!ext) {
				continue;
			}
			if (isTrustedExtension(ext, policy)) {
				trustedInGroup.push(ext.identifier.value);
				continue;
			}
			if (isKnownBuiltinApiConsumer(ext.identifier.value, policy)) {
				hasAllowlistedConsumer = true;
				continue;
			}
			hasUntrusted = true;
		}

		// Trusted-only / allowlisted-consumer-only groups stay on affinity 0.
		if (!hasUntrusted) {
			continue;
		}
		// Prefer product completeness: groups that include a consumable-API
		// builtin keep their known consumers on the trusted host (r14).
		if (hasAllowlistedConsumer && groupContainsBuiltinApiProvider(memberIds)) {
			continue;
		}

		for (const id of memberIds) {
			const ext = extById.get(id);
			if (!ext) {
				continue;
			}
			affinities[ext.identifier.value] = THIRD_PARTY_BUCKET_AFFINITY;
		}
		for (const trustedId of trustedInGroup) {
			dilutedTrustedIds.push(trustedId);
		}
	}

	return { affinities, dilutedTrustedIds };
}

/**
 * Resolve the default product policy (publishers / ids / consumers) for the tracker.
 */
export function resolveTrustBucketPolicyFromProduct(productConfig: {
	trustedExtensionBucketPublishers?: readonly string[];
	trustedExtensionBucketIds?: readonly string[];
} = product): ITrustBucketPolicy {
	return {
		trustedPublishers: productConfig.trustedExtensionBucketPublishers,
		trustedExtensionIds: productConfig.trustedExtensionBucketIds,
		knownBuiltinApiConsumers: DEFAULT_KNOWN_BUILTIN_API_CONSUMERS,
	};
}
