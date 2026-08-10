#!/usr/bin/env node
// Usage-aware deletion check for a debug probe (decision table in SKILL.md).
// Usage: node check-usage.mjs --probe-id <id> --expires-at <ISO> [--issue-closed true|false|unknown]
//        [--grace-days 14] [--staleness-days 30] [--fixtures <usage.json>]
// Backend wiring, in priority order:
//   1. PROBE_USAGE_CMD env var: a command invoked as `$PROBE_USAGE_CMD <probeId>`,
//      must print ProbeUsage JSON: {lastFiredAt, firesLast30d, queryRefsLast90d}.
//      (Wrap a Datadog/warehouse MCP or CLI query in it when one is available.)
//   2. --fixtures file with the same JSON (for tests, or for pasting MCP results).
//   3. Stub: source:"stub", null usage — decision degrades to flag-for-review / grace logic.
// No dependencies; Node >= 18.

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const args = process.argv.slice(2);
function opt(name, dflt) {
	const i = args.indexOf(name);
	return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : dflt;
}

const probeId = opt('--probe-id', null);
const expiresAt = opt('--expires-at', null);
if (!probeId || !expiresAt) {
	console.error('required: --probe-id <id> --expires-at <ISO date>');
	process.exit(2);
}
const issueClosed = opt('--issue-closed', 'unknown'); // true | false | unknown
const graceDays = Number(opt('--grace-days', '14'));
const stalenessDays = Number(opt('--staleness-days', '30'));
const fixtures = opt('--fixtures', null);

function fetchUsage() {
	const cmd = process.env.PROBE_USAGE_CMD;
	if (cmd) {
		try {
			const raw = execFileSync(cmd, [probeId], { encoding: 'utf8', timeout: 60_000 });
			return { ...JSON.parse(raw), source: 'backend' };
		} catch (err) {
			console.error(`PROBE_USAGE_CMD failed (${err.message}); falling back to stub`);
		}
	}
	if (fixtures) {
		try {
			return { ...JSON.parse(readFileSync(fixtures, 'utf8')), source: 'backend' };
		} catch (err) {
			console.error(`fixtures unreadable (${err.message}); falling back to stub`);
		}
	}
	return { lastFiredAt: null, firesLast30d: null, queryRefsLast90d: null, source: 'stub' };
}

const usage = fetchUsage();
const now = Date.now();
const exp = Date.parse(expiresAt);
const dayMs = 86400_000;

let decision;
let reason;
if (!Number.isFinite(exp)) {
	decision = 'flag-for-review';
	reason = 'unparseable expiresAt';
} else if (now < exp) {
	decision = 'keep';
	reason = 'not yet expired; runtime gate still open';
} else if (usage.source === 'stub') {
	const pastGrace = now > exp + graceDays * dayMs;
	decision = pastGrace ? 'delete' : 'flag-for-review';
	reason = pastGrace
		? `expired ${Math.floor((now - exp) / dayMs)}d ago, past ${graceDays}d grace, no usage backend — data-safe (runtime gate already silenced it); note the missing backend in the PR`
		: `expired but within ${graceDays}d grace and no usage backend available`;
} else {
	const refs = usage.queryRefsLast90d ?? 0;
	// "Fired recently" relative to expiry: still emitting within stalenessDays before the gate closed.
	const firedNearExpiry = usage.lastFiredAt !== null && (exp - Date.parse(usage.lastFiredAt)) < stalenessDays * dayMs;
	if (refs > 0 || firedNearExpiry || issueClosed === 'false') {
		decision = 'renew-or-promote';
		reason = `still in use (queryRefs=${refs}, firedNearExpiry=${firedNearExpiry}, issueClosed=${issueClosed}) — bump expiresAt with justification, or promote to a permanent GDPR-declared event`;
	} else if (issueClosed === 'unknown') {
		decision = 'flag-for-review';
		reason = 'no usage signal, but issue status unknown — confirm the ticket is closed before deleting';
	} else {
		decision = 'delete';
		reason = 'expired, issue closed, no fires near expiry, no query/dashboard references in 90d';
	}
}

console.log(JSON.stringify({ probeId, expiresAt, ...usage, decision, reason }, null, 2));
