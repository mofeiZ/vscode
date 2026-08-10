/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import assert from 'assert';
import { URI } from '../../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../../base/test/common/utils.js';
import { TestConfigurationService } from '../../../../../platform/configuration/test/common/testConfigurationService.js';
import { ExtensionIdentifier, IExtensionDescription } from '../../../../../platform/extensions/common/extensions.js';
import { NullLogService } from '../../../../../platform/log/common/log.js';
import {
	_resetDiagnosticIsolationForTests,
	_setInternalDiagnosticsEnabledForTests,
	addDiagnosticIsolation,
	DIAGNOSTIC_ISOLATION_DEMO_CONFIG_KEY,
	DIAGNOSTIC_ISOLATION_DEMO_SEED_ID,
	getDiagnosticIsolationIds,
	INTERNAL_DIAGNOSTICS_ENV,
	isDiagnosticIsolationDemoEnvEnabled,
	isInternalDiagnosticsEnabled,
	removeDiagnosticIsolation,
} from '../../common/diagnosticIsolation.js';
import { ExtensionRunningLocationTracker } from '../../common/extensionRunningLocationTracker.js';
import { ExtensionHostKind, IExtensionHostKindPicker } from '../../common/extensionHostKind.js';
import { IExtensionManifestPropertiesService } from '../../common/extensionManifestPropertiesService.js';
import { IReadOnlyExtensionDescriptionRegistry } from '../../common/extensionDescriptionRegistry.js';
import { localProcessExtensionHostLogId, localProcessExtensionHostLogsPath } from '../../common/extensionRunningLocation.js';
import {
	_setTrustBucketingEnabledForTests,
	isTrustBucketingEnabled,
	isTrustedExtension,
	THIRD_PARTY_BUCKET_AFFINITY,
	TRUST_BUCKETING_ENV,
} from '../../common/extensionTrustBuckets.js';
import { readOptionalProcessEnv } from '../../common/rendererSafeEnv.js';
import { IWorkbenchEnvironmentService } from '../../../environment/common/environmentService.js';

function createExtension(id: string, deps?: string[], extensionAffinity?: string[], opts?: { isBuiltin?: boolean; isUserBuiltin?: boolean; publisher?: string }): IExtensionDescription {
	const publisher = opts?.publisher ?? (id.includes('.') ? id.split('.')[0] : 'test');
	return <IExtensionDescription>{
		identifier: new ExtensionIdentifier(id),
		extensionLocation: URI.parse(`file:///test/${id}`),
		name: id,
		publisher,
		version: '1.0.0',
		engines: { vscode: '*' },
		main: 'main.js',
		extensionDependencies: deps,
		extensionAffinity: extensionAffinity,
		enabledApiProposals: extensionAffinity ? ['extensionAffinity'] : undefined,
		isBuiltin: opts?.isBuiltin ?? false,
		isUserBuiltin: opts?.isUserBuiltin ?? false,
	};
}

suite('ExtensionRunningLocationTracker - extensionAffinity', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	setup(() => {
		// Existing isolation tests exercise Tier-1 behavior with the gate ON.
		_setInternalDiagnosticsEnabledForTests(true);
	});

	teardown(() => {
		_resetDiagnosticIsolationForTests();
		_setInternalDiagnosticsEnabledForTests(undefined);
	});

	function createTracker(
		extensions: IExtensionDescription[],
		configuredAffinities: { [extensionId: string]: number } = {},
		isExtensionDevelopment = false,
		extraConfig: { [key: string]: unknown } = {},
	): ExtensionRunningLocationTracker {
		const registry: IReadOnlyExtensionDescriptionRegistry = {
			getAllExtensionDescriptions: () => extensions,
			getExtensionDescription: (id: string | ExtensionIdentifier) => extensions.find(e => e.identifier.value === (typeof id === 'string' ? id : id.value)),
			getExtensionDescriptionByUUID: () => undefined,
			getExtensionDescriptionByIdOrUUID: () => undefined,
			containsActivationEvent: () => false,
			containsExtension: () => false,
			getExtensionDescriptionsForActivationEvent: () => [],
		};

		const extensionHostKindPicker: IExtensionHostKindPicker = {
			pickExtensionHostKind: () => ExtensionHostKind.LocalProcess,
		};

		const environmentService = <IWorkbenchEnvironmentService>{
			isExtensionDevelopment,
			extensionDevelopmentKind: undefined,
		};

		const configurationService = new TestConfigurationService();
		configurationService.setUserConfiguration('extensions.experimental.affinity', configuredAffinities);
		for (const [key, value] of Object.entries(extraConfig)) {
			configurationService.setUserConfiguration(key, value);
		}

		const logService = new NullLogService();

		const extensionManifestPropertiesService = {
			getExtensionKind: () => ['workspace'],
		} as unknown as IExtensionManifestPropertiesService;

		return new ExtensionRunningLocationTracker(
			registry,
			extensionHostKindPicker,
			environmentService,
			configurationService,
			logService,
			extensionManifestPropertiesService
		);
	}

	test('extensions with extensionAffinity should have the same affinity', () => {
		const extA = createExtension('publisher.extA');
		const extB = createExtension('publisher.extB', undefined, ['publisher.extA']);

		const tracker = createTracker([extA, extB]);
		const runningLocations = tracker.computeRunningLocation([extA, extB], [], true);

		const locA = runningLocations.get(extA.identifier);
		const locB = runningLocations.get(extB.identifier);

		assert.ok(locA, 'Extension A should have a running location');
		assert.ok(locB, 'Extension B should have a running location');
		assert.strictEqual(locA!.affinity, locB!.affinity, 'Extensions with extensionAffinity should have the same affinity');
	});

	test('transitive extensionAffinity should group all extensions together', () => {
		const extA = createExtension('publisher.extA');
		const extB = createExtension('publisher.extB', undefined, ['publisher.extA']);
		const extC = createExtension('publisher.extC', undefined, ['publisher.extB']);

		const tracker = createTracker([extA, extB, extC]);
		const runningLocations = tracker.computeRunningLocation([extA, extB, extC], [], true);

		const locA = runningLocations.get(extA.identifier);
		const locB = runningLocations.get(extB.identifier);
		const locC = runningLocations.get(extC.identifier);

		assert.ok(locA && locB && locC, 'All extensions should have running locations');
		assert.strictEqual(locA!.affinity, locB!.affinity, 'A and B should have the same affinity');
		assert.strictEqual(locB!.affinity, locC!.affinity, 'B and C should have the same affinity');
	});

	test('extensionAffinity with non-installed extension should be ignored', () => {
		const extA = createExtension('publisher.extA', undefined, ['publisher.notInstalled']);
		const extB = createExtension('publisher.extB');

		const tracker = createTracker([extA, extB]);
		const runningLocations = tracker.computeRunningLocation([extA, extB], [], true);

		const locA = runningLocations.get(extA.identifier);
		const locB = runningLocations.get(extB.identifier);

		assert.ok(locA && locB, 'Both extensions should have running locations');
		// They should not be grouped together since the extensionAffinity target doesn't exist
		// (Unless they would naturally have affinity 0, which they both do by default)
	});

	test('extensionAffinity combined with extensionDependencies', () => {
		const extA = createExtension('publisher.extA');
		const extB = createExtension('publisher.extB', ['publisher.extA']);
		const extC = createExtension('publisher.extC', undefined, ['publisher.extA']);

		const tracker = createTracker([extA, extB, extC]);
		const runningLocations = tracker.computeRunningLocation([extA, extB, extC], [], true);

		const locA = runningLocations.get(extA.identifier);
		const locB = runningLocations.get(extB.identifier);
		const locC = runningLocations.get(extC.identifier);

		assert.ok(locA && locB && locC, 'All extensions should have running locations');
		// B depends on A, C has extensionAffinity to A - all should be in the same group
		assert.strictEqual(locA!.affinity, locB!.affinity, 'A and B (dependency) should have the same affinity');
		assert.strictEqual(locA!.affinity, locC!.affinity, 'A and C (extensionAffinity) should have the same affinity');
	});

	test('user configured affinity should override extensionAffinity', () => {
		const extA = createExtension('publisher.extA');
		const extB = createExtension('publisher.extB', undefined, ['publisher.extA']);

		const tracker = createTracker([extA, extB], {
			'publisher.extA': 1,
			'publisher.extB': 2,
		});
		const runningLocations = tracker.computeRunningLocation([extA, extB], [], true);

		const locA = runningLocations.get(extA.identifier);
		const locB = runningLocations.get(extB.identifier);

		assert.ok(locA && locB, 'Both extensions should have running locations');
		// With user-configured affinities, they should be in different groups
		// Note: The actual behavior depends on the order of operations in _computeAffinity
		// The user config creates separate affinities, but grouping happens first
	});

	test('one-way extensionAffinity is sufficient', () => {
		// Only extB declares extensionAffinity, extA doesn't need to know about extB
		const extA = createExtension('publisher.extA');
		const extB = createExtension('publisher.extB', undefined, ['publisher.extA']);

		const tracker = createTracker([extA, extB]);
		const runningLocations = tracker.computeRunningLocation([extA, extB], [], true);

		const locA = runningLocations.get(extA.identifier);
		const locB = runningLocations.get(extB.identifier);

		assert.ok(locA && locB, 'Both extensions should have running locations');
		assert.strictEqual(locA!.affinity, locB!.affinity, 'One-way extensionAffinity should be sufficient to group extensions');
	});

	test('empty diagnostic isolation set keeps all extensions on affinity 0', () => {
		const deskGnome = createExtension(DIAGNOSTIC_ISOLATION_DEMO_SEED_ID);
		const other = createExtension('publisher.other');

		const tracker = createTracker([deskGnome, other]);
		const runningLocations = tracker.computeRunningLocation([deskGnome, other], [], true);

		const locDesk = runningLocations.get(deskGnome.identifier);
		const locOther = runningLocations.get(other.identifier);

		assert.ok(locDesk && locOther);
		assert.strictEqual(locDesk!.affinity, 0, 'Default-off policy must not isolate desk-gnome');
		assert.strictEqual(locOther!.affinity, 0);
	});

	test('internal diagnostics gate OFF refuses add and does not isolate', () => {
		_setInternalDiagnosticsEnabledForTests(false);
		assert.strictEqual(isInternalDiagnosticsEnabled(), false);

		const suspect = createExtension('publisher.suspect');
		const other = createExtension('publisher.other');

		assert.strictEqual(addDiagnosticIsolation('publisher.suspect'), false, 'add refuses when gate OFF');
		assert.deepStrictEqual(getDiagnosticIsolationIds(), [], 'set stays empty when gate OFF');

		const tracker = createTracker([suspect, other]);
		const runningLocations = tracker.computeRunningLocation([suspect, other], [], true);

		assert.strictEqual(runningLocations.get(suspect.identifier)!.affinity, 0, '_computeAffinity must not isolate when gate OFF');
		assert.strictEqual(runningLocations.get(other.identifier)!.affinity, 0);
	});

	test('internal diagnostics gate OFF makes a pre-seeded set inert in _computeAffinity', () => {
		// Enable briefly to populate the set, then disable — placement must stay inert.
		_setInternalDiagnosticsEnabledForTests(true);
		assert.strictEqual(addDiagnosticIsolation('publisher.suspect'), true);
		_setInternalDiagnosticsEnabledForTests(false);

		const suspect = createExtension('publisher.suspect');
		const other = createExtension('publisher.other');
		const tracker = createTracker([suspect, other]);
		const runningLocations = tracker.computeRunningLocation([suspect, other], [], true);

		assert.deepStrictEqual(getDiagnosticIsolationIds(), ['publisher.suspect'], 'set may still hold ids');
		assert.strictEqual(runningLocations.get(suspect.identifier)!.affinity, 0, 'gate OFF ⇒ affinities empty');
		assert.strictEqual(runningLocations.get(other.identifier)!.affinity, 0);
	});

	test('internal diagnostics gate ON allows add and isolates the flagged group', () => {
		_setInternalDiagnosticsEnabledForTests(true);
		assert.strictEqual(isInternalDiagnosticsEnabled(), true);

		const suspect = createExtension('publisher.suspect');
		const other = createExtension('publisher.other');

		assert.strictEqual(addDiagnosticIsolation('publisher.suspect'), true);
		assert.strictEqual(addDiagnosticIsolation('publisher.suspect'), false, 'idempotent add');

		const tracker = createTracker([suspect, other]);
		const runningLocations = tracker.computeRunningLocation([suspect, other], [], true);

		const locSuspect = runningLocations.get(suspect.identifier);
		const locOther = runningLocations.get(other.identifier);

		assert.ok(locSuspect && locOther);
		assert.strictEqual(locSuspect!.affinity, 1, 'Flagged extension lands on its own host');
		assert.strictEqual(locOther!.affinity, 0, 'Unflagged extensions stay on the shared host');
	});

	test('diagnostic isolation set places flagged id group on its own affinity', () => {
		const suspect = createExtension('publisher.suspect');
		const other = createExtension('publisher.other');

		assert.strictEqual(addDiagnosticIsolation('publisher.suspect'), true);
		assert.strictEqual(addDiagnosticIsolation('publisher.suspect'), false, 'idempotent add');

		const tracker = createTracker([suspect, other]);
		const runningLocations = tracker.computeRunningLocation([suspect, other], [], true);

		const locSuspect = runningLocations.get(suspect.identifier);
		const locOther = runningLocations.get(other.identifier);

		assert.ok(locSuspect && locOther);
		assert.strictEqual(locSuspect!.affinity, 1, 'Flagged extension lands on its own host');
		assert.strictEqual(locOther!.affinity, 0, 'Unflagged extensions stay on the shared host');
	});

	test('diagnostic isolation assigns per dependency group and does not split it', () => {
		const suspect = createExtension('publisher.suspect', ['publisher.sharedApi']);
		const sharedApi = createExtension('publisher.sharedApi');
		const other = createExtension('publisher.other');

		addDiagnosticIsolation('publisher.suspect');

		const tracker = createTracker([suspect, sharedApi, other]);
		const runningLocations = tracker.computeRunningLocation([suspect, sharedApi, other], [], true);

		const locSuspect = runningLocations.get(suspect.identifier);
		const locShared = runningLocations.get(sharedApi.identifier);
		const locOther = runningLocations.get(other.identifier);

		assert.ok(locSuspect && locShared && locOther);
		assert.strictEqual(locSuspect!.affinity, 1);
		assert.strictEqual(locShared!.affinity, 1, 'Dependency group must share the isolation affinity');
		assert.strictEqual(locOther!.affinity, 0);
	});

	test('demo flag seeds desk-gnome into the isolation set', () => {
		const deskGnome = createExtension(DIAGNOSTIC_ISOLATION_DEMO_SEED_ID);
		const other = createExtension('publisher.other');

		const tracker = createTracker([deskGnome, other], {}, false, {
			[DIAGNOSTIC_ISOLATION_DEMO_CONFIG_KEY]: true,
		});
		const runningLocations = tracker.computeRunningLocation([deskGnome, other], [], true);

		const locDesk = runningLocations.get(deskGnome.identifier);
		const locOther = runningLocations.get(other.identifier);

		assert.ok(locDesk && locOther);
		assert.strictEqual(locDesk!.affinity, 1, 'Demo seed must place desk-gnome on affinity 1');
		assert.strictEqual(locOther!.affinity, 0);
	});

	test('removeDiagnosticIsolation restores shared-host placement on next compute', () => {
		const suspect = createExtension('publisher.suspect');
		const other = createExtension('publisher.other');

		addDiagnosticIsolation('publisher.suspect');
		assert.strictEqual(removeDiagnosticIsolation('publisher.suspect'), true);

		const tracker = createTracker([suspect, other]);
		const runningLocations = tracker.computeRunningLocation([suspect, other], [], true);

		assert.strictEqual(runningLocations.get(suspect.identifier)!.affinity, 0);
		assert.strictEqual(runningLocations.get(other.identifier)!.affinity, 0);
	});

	test('tracker add/remove wrappers mutate the shared isolation set', () => {
		const tracker = createTracker([]);
		assert.deepStrictEqual(tracker.getDiagnosticIsolationIds(), []);
		assert.strictEqual(tracker.addDiagnosticIsolation('publisher.suspect'), true);
		assert.deepStrictEqual(tracker.getDiagnosticIsolationIds(), ['publisher.suspect']);
		assert.strictEqual(tracker.removeDiagnosticIsolation('publisher.suspect'), true);
		assert.deepStrictEqual(tracker.getDiagnosticIsolationIds(), []);
	});

	test('user affinity setting overrides diagnostic isolation policy', () => {
		const suspect = createExtension('publisher.suspect');
		const vim = createExtension('vscodevim.vim');

		addDiagnosticIsolation('publisher.suspect');

		const tracker = createTracker([suspect, vim], {
			'publisher.suspect': 2,
			'vscodevim.vim': 1,
		});
		const runningLocations = tracker.computeRunningLocation([suspect, vim], [], true);

		const locSuspect = runningLocations.get(suspect.identifier);
		const locVim = runningLocations.get(vim.identifier);

		assert.ok(locSuspect && locVim);
		assert.notStrictEqual(locSuspect!.affinity, locVim!.affinity, 'User-configured values must win over policy on the same id');
		assert.ok(locSuspect!.affinity > 0 && locVim!.affinity > 0);
	});

	test('isExtensionDevelopment ignores diagnostic isolation and user setting', () => {
		const suspect = createExtension('publisher.suspect');
		addDiagnosticIsolation('publisher.suspect');

		const tracker = createTracker([suspect], {
			'publisher.suspect': 2,
		}, true);
		const runningLocations = tracker.computeRunningLocation([suspect], [], true);

		const loc = runningLocations.get(suspect.identifier);
		assert.ok(loc);
		assert.strictEqual(loc!.affinity, 0, 'Debug / extensionDevelopmentPath must skip affinity');
	});

	test('localProcessExtensionHostLogsPath suffixes by affinity', () => {
		const base = URI.file('/tmp/logs/window1/exthost');
		assert.strictEqual(localProcessExtensionHostLogsPath(base, 0).fsPath, base.fsPath);
		assert.strictEqual(localProcessExtensionHostLogsPath(base, 1).fsPath, '/tmp/logs/window1/exthost1');
		assert.strictEqual(localProcessExtensionHostLogsPath(base, 2).fsPath, '/tmp/logs/window1/exthost2');
		assert.strictEqual(localProcessExtensionHostLogId('exthostStderr', 0), 'exthostStderr');
		assert.strictEqual(localProcessExtensionHostLogId('exthostStderr', 1), 'exthostStderr.1');
	});
});

suite('ExtensionRunningLocationTracker - trust bucketing', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	setup(() => {
		_setInternalDiagnosticsEnabledForTests(false);
		_setTrustBucketingEnabledForTests(undefined);
	});

	teardown(() => {
		_resetDiagnosticIsolationForTests();
		_setInternalDiagnosticsEnabledForTests(undefined);
		_setTrustBucketingEnabledForTests(undefined);
	});

	function createTracker(
		extensions: IExtensionDescription[],
		configuredAffinities: { [extensionId: string]: number } = {},
		isExtensionDevelopment = false,
	): ExtensionRunningLocationTracker {
		const registry: IReadOnlyExtensionDescriptionRegistry = {
			getAllExtensionDescriptions: () => extensions,
			getExtensionDescription: (id: string | ExtensionIdentifier) => extensions.find(e => e.identifier.value === (typeof id === 'string' ? id : id.value)),
			getExtensionDescriptionByUUID: () => undefined,
			getExtensionDescriptionByIdOrUUID: () => undefined,
			containsActivationEvent: () => false,
			containsExtension: () => false,
			getExtensionDescriptionsForActivationEvent: () => [],
		};

		const extensionHostKindPicker: IExtensionHostKindPicker = {
			pickExtensionHostKind: () => ExtensionHostKind.LocalProcess,
		};

		const environmentService = <IWorkbenchEnvironmentService>{
			isExtensionDevelopment,
			extensionDevelopmentKind: undefined,
		};

		const configurationService = new TestConfigurationService();
		configurationService.setUserConfiguration('extensions.experimental.affinity', configuredAffinities);

		const logService = new NullLogService();
		const extensionManifestPropertiesService = {
			getExtensionKind: () => ['workspace'],
		} as unknown as IExtensionManifestPropertiesService;

		return new ExtensionRunningLocationTracker(
			registry,
			extensionHostKindPicker,
			environmentService,
			configurationService,
			logService,
			extensionManifestPropertiesService
		);
	}

	test('isTrustedExtension: builtins trusted, userBuiltin and marketplace not', () => {
		const builtin = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const userBuiltin = createExtension('my.sideload', undefined, undefined, { isBuiltin: true, isUserBuiltin: true });
		const marketplace = createExtension('eamodio.gitlens');
		assert.strictEqual(isTrustedExtension(builtin), true);
		assert.strictEqual(isTrustedExtension(userBuiltin), false);
		assert.strictEqual(isTrustedExtension(marketplace), false);
		assert.strictEqual(isTrustedExtension(marketplace, { trustedPublishers: ['eamodio'] }), true);
		assert.strictEqual(isTrustedExtension(marketplace, { trustedExtensionIds: ['eamodio.gitlens'] }), true);
	});

	test('flag OFF: builtin and marketplace stay on affinity 0 (no topology change)', () => {
		_setTrustBucketingEnabledForTests(false);
		assert.strictEqual(isTrustBucketingEnabled(), false);

		const builtin = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const marketplace = createExtension('publisher.prettier');

		const tracker = createTracker([builtin, marketplace]);
		const runningLocations = tracker.computeRunningLocation([builtin, marketplace], [], true);

		assert.strictEqual(runningLocations.get(builtin.identifier)!.affinity, 0);
		assert.strictEqual(runningLocations.get(marketplace.identifier)!.affinity, 0);
	});

	test('flag ON: builtin and marketplace land on different affinities', () => {
		_setTrustBucketingEnabledForTests(true);

		const builtin = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const marketplace = createExtension('publisher.prettier');

		const tracker = createTracker([builtin, marketplace]);
		tracker.initializeRunningLocation([builtin, marketplace], []);

		assert.strictEqual(tracker.getRunningLocation(builtin.identifier)!.affinity, 0, 'builtin stays on trusted host');
		assert.strictEqual(tracker.getRunningLocation(marketplace.identifier)!.affinity, THIRD_PARTY_BUCKET_AFFINITY, 'marketplace on third-party host');
		assert.strictEqual(tracker.maxLocalProcessAffinity, THIRD_PARTY_BUCKET_AFFINITY);
	});

	test('flag ON: dependency group stays together (dilutes trusted into 3P host)', () => {
		_setTrustBucketingEnabledForTests(true);

		const sharedApi = createExtension('vscode.sharedApi', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const consumer = createExtension('publisher.consumer', ['vscode.sharedApi']);
		const unrelated = createExtension('publisher.unrelated');

		const tracker = createTracker([sharedApi, consumer, unrelated]);
		const runningLocations = tracker.computeRunningLocation([sharedApi, consumer, unrelated], [], true);

		const locShared = runningLocations.get(sharedApi.identifier)!;
		const locConsumer = runningLocations.get(consumer.identifier)!;
		const locUnrelated = runningLocations.get(unrelated.identifier)!;

		assert.strictEqual(locShared.affinity, locConsumer.affinity, 'dependency group must not be split');
		assert.strictEqual(locShared.affinity, THIRD_PARTY_BUCKET_AFFINITY, 'mixed group goes to third-party bucket');
		assert.strictEqual(locUnrelated.affinity, THIRD_PARTY_BUCKET_AFFINITY);
	});

	test('flag ON: vscode.git API consumer (GitLens) co-locates with vscode.git', () => {
		_setTrustBucketingEnabledForTests(true);

		const git = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const gitBase = createExtension('vscode.git-base', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const gitlens = createExtension('eamodio.gitlens');
		const prettier = createExtension('esbenp.prettier-vscode');

		const tracker = createTracker([git, gitBase, gitlens, prettier]);
		const runningLocations = tracker.computeRunningLocation([git, gitBase, gitlens, prettier], [], true);

		const locGit = runningLocations.get(git.identifier)!;
		const locGitBase = runningLocations.get(gitBase.identifier)!;
		const locGitlens = runningLocations.get(gitlens.identifier)!;
		const locPrettier = runningLocations.get(prettier.identifier)!;

		assert.strictEqual(locGit.affinity, 0);
		assert.strictEqual(locGitBase.affinity, 0);
		assert.strictEqual(locGitlens.affinity, locGit.affinity, 'GitLens must co-locate with vscode.git');
		assert.strictEqual(locPrettier.affinity, THIRD_PARTY_BUCKET_AFFINITY, 'unrelated 3P still split');
		assert.notStrictEqual(locGitlens.affinity, locPrettier.affinity);
	});

	test('flag ON: zero third-party extensions ⇒ maxAffinity 0 (no extra host)', () => {
		_setTrustBucketingEnabledForTests(true);

		const git = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const theme = createExtension('vscode.theme-defaults', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });

		const tracker = createTracker([git, theme]);
		tracker.initializeRunningLocation([git, theme], []);

		assert.strictEqual(tracker.getRunningLocation(git.identifier)!.affinity, 0);
		assert.strictEqual(tracker.getRunningLocation(theme.identifier)!.affinity, 0);
		assert.strictEqual(tracker.maxLocalProcessAffinity, 0);
	});

	test('flag ON: isExtensionDevelopment skips trust bucketing', () => {
		_setTrustBucketingEnabledForTests(true);

		const builtin = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const marketplace = createExtension('publisher.prettier');

		const tracker = createTracker([builtin, marketplace], {}, true);
		const runningLocations = tracker.computeRunningLocation([builtin, marketplace], [], true);

		assert.strictEqual(runningLocations.get(builtin.identifier)!.affinity, 0);
		assert.strictEqual(runningLocations.get(marketplace.identifier)!.affinity, 0);
	});

	test('flag ON: diagnostic isolation further isolates a third-party suspect', () => {
		_setTrustBucketingEnabledForTests(true);
		_setInternalDiagnosticsEnabledForTests(true);

		const builtin = createExtension('vscode.git', undefined, undefined, { isBuiltin: true, publisher: 'vscode' });
		const suspect = createExtension('publisher.suspect');
		const other3p = createExtension('publisher.other');

		addDiagnosticIsolation('publisher.suspect');

		const tracker = createTracker([builtin, suspect, other3p]);
		const runningLocations = tracker.computeRunningLocation([builtin, suspect, other3p], [], true);

		const locBuiltin = runningLocations.get(builtin.identifier)!;
		const locSuspect = runningLocations.get(suspect.identifier)!;
		const locOther = runningLocations.get(other3p.identifier)!;

		assert.strictEqual(locBuiltin.affinity, 0, 'trusted baseline');
		assert.ok(locOther.affinity > 0, 'ordinary 3P on a non-trusted host');
		assert.ok(locSuspect.affinity > 0, 'suspect isolated');
		assert.notStrictEqual(locSuspect.affinity, locOther.affinity, 'diagnostic isolation is a further host beyond the 3P bucket');
		assert.notStrictEqual(locSuspect.affinity, locBuiltin.affinity);
	});
});

suite('Renderer-safe gate env reads', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	teardown(() => {
		_setInternalDiagnosticsEnabledForTests(undefined);
		_setTrustBucketingEnabledForTests(undefined);
	});

	test('gates return false (do not throw) when process is undefined (renderer)', () => {
		_setInternalDiagnosticsEnabledForTests(undefined);
		_setTrustBucketingEnabledForTests(undefined);

		// Simulate sandboxed workbench: no Node `process` binding.
		const rendererEnv = readOptionalProcessEnv(undefined);
		assert.deepStrictEqual(rendererEnv, {});

		assert.doesNotThrow(() => {
			assert.strictEqual(
				isInternalDiagnosticsEnabled({ productEnabled: false, env: rendererEnv }),
				false,
			);
			assert.strictEqual(
				isTrustBucketingEnabled({ productEnabled: false, env: rendererEnv }),
				false,
			);
			assert.strictEqual(isDiagnosticIsolationDemoEnvEnabled(rendererEnv), false);
		});
	});

	test('gates still honor product + env flags when set', () => {
		_setInternalDiagnosticsEnabledForTests(undefined);
		_setTrustBucketingEnabledForTests(undefined);

		const noProcess = readOptionalProcessEnv(undefined);
		assert.strictEqual(
			isInternalDiagnosticsEnabled({ productEnabled: true, env: noProcess }),
			true,
			'product.json / IProductService path enables without process',
		);
		assert.strictEqual(
			isTrustBucketingEnabled({ productEnabled: true, env: noProcess }),
			true,
			'product.json / IProductService path enables without process',
		);

		assert.strictEqual(
			isInternalDiagnosticsEnabled({
				productEnabled: false,
				env: { [INTERNAL_DIAGNOSTICS_ENV]: '1' },
			}),
			true,
		);
		assert.strictEqual(
			isTrustBucketingEnabled({
				productEnabled: false,
				env: { [TRUST_BUCKETING_ENV]: 'true' },
			}),
			true,
		);
	});
});
