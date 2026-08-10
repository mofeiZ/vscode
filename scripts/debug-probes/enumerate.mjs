#!/usr/bin/env node
// Enumerate debug telemetry probes in the fork: metadata + expiry + call sites.
// Usage: node enumerate.mjs [--repo <fork-root>] [--probes-dir <rel>] [--expired] [--grace-days 14]
// Exit codes: 0 ok; 1 with --expired if any probe is expired beyond the grace period.
// Aligns with work-notes/.cursor/skills/debug-telemetry-probes/scripts/enumerate-probes.mjs
// plus issueRef / ttlDays from the u33 scaffold manifest slice.
// No dependencies; Node >= 18.

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { homedir } from 'node:os';

const args = process.argv.slice(2);
function flag(name) { return args.includes(name); }
function opt(name, dflt) {
	const i = args.indexOf(name);
	return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : dflt;
}

const repo = opt('--repo', join(homedir(), 'Downloads', 'vscode'));
const probesDirRel = opt('--probes-dir', 'src/vs/platform/telemetry/common/debugProbes/probes');
const graceDays = Number(opt('--grace-days', '14'));
const onlyExpired = flag('--expired');
const probesDir = join(repo, probesDirRel);

if (!existsSync(probesDir)) {
	console.log(JSON.stringify({ probes: [], note: `probes dir missing: ${probesDir} — fork scaffolding not implemented yet` }, null, 2));
	process.exit(0);
}

// Metadata must be a statically parseable object literal (hard rule 4).
// Word-boundary so `issue` does not match `issueRef`.
const FIELD_RE = (f) => new RegExp(`\\b${f}\\s*:\\s*'([^']*)'`);
const NUM_RE = (f) => new RegExp(`\\b${f}\\s*:\\s*(\\d+)`);
function parseProbe(file) {
	const text = readFileSync(file, 'utf8');
	const get = (f) => (text.match(FIELD_RE(f)) ?? [])[1] ?? null;
	const getNum = (f) => {
		const m = text.match(NUM_RE(f));
		return m ? Number(m[1]) : null;
	};
	const issue = get('issue') ?? get('issueRef');
	const issueRef = get('issueRef') ?? get('issue');
	return {
		probeId: get('probeId'),
		owner: get('owner'),
		createdAt: get('createdAt'),
		issue,
		issueRef,
		ttlDays: getNum('ttlDays'),
		expiresAt: get('expiresAt'),
		comment: get('comment'),
		module: relative(repo, file),
	};
}

function* walkTsFiles(dir) {
	for (const entry of readdirSync(dir)) {
		if (entry === 'node_modules' || entry.startsWith('.')) { continue; }
		const p = join(dir, entry);
		const st = statSync(p);
		if (st.isDirectory()) { yield* walkTsFiles(p); }
		else if (/\.(ts|tsx|mts|cts)$/.test(entry)) { yield p; }
	}
}

const probeFiles = readdirSync(probesDir).filter(f => f.endsWith('.ts')).map(f => join(probesDir, f));
const probes = probeFiles.map(parseProbe);
const ids = new Set(probes.map(p => p.probeId).filter(Boolean));

// One pass over src/ to find call sites for all probe ids.
const callSites = new Map([...ids].map(id => [id, []]));
if (ids.size > 0) {
	for (const file of walkTsFiles(join(repo, 'src'))) {
		if (file.startsWith(probesDir)) { continue; } // the probe module itself is not a call site
		const text = readFileSync(file, 'utf8');
		for (const id of ids) {
			if (!text.includes(id)) { continue; }
			const lines = text.split('\n');
			for (let i = 0; i < lines.length; i++) {
				if (lines[i].includes(id)) {
					callSites.get(id).push(`${relative(repo, file)}:${i + 1}`);
				}
			}
		}
	}
}

const now = Date.now();
const graceMs = graceDays * 86400_000;
let pastGrace = false;
const out = probes.map(p => {
	const exp = p.expiresAt ? Date.parse(p.expiresAt) : NaN;
	const expired = Number.isFinite(exp) ? now > exp : true; // unparseable expiry = treat as expired (fail toward review)
	const expiredPastGrace = Number.isFinite(exp) ? now > exp + graceMs : true;
	if (expiredPastGrace) { pastGrace = true; }
	const status = !Number.isFinite(exp) ? 'invalid-expiry'
		: expiredPastGrace ? 'expired-past-grace'
			: expired ? 'expired'
				: 'active';
	return { ...p, expired, expiredPastGrace, status, callSites: callSites.get(p.probeId) ?? [] };
}).filter(p => !onlyExpired || p.expired);

console.log(JSON.stringify({ probes: out }, null, 2));
process.exit(onlyExpired && pastGrace ? 1 : 0);
