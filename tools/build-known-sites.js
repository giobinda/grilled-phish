#!/usr/bin/env node
/*
 * Builds data/known-sites.txt: the most visited websites, in popularity order,
 * from the Tranco list (https://tranco-list.eu, research-grade ranking that
 * combines Chrome UX Report, Cloudflare Radar, Cisco Umbrella, Majestic and
 * Farsight, averaged over 30 days so it is hard to manipulate).
 *
 * Usage:  node tools/build-known-sites.js [--top 100000] [--list-id 947W2]
 * No dependencies; needs Node 18+.
 *
 * Entries that Grilled Phish's own brand rules flag as fakes (popular typo-
 * squatters such as instragram.com) are removed, so they can never count as
 * "well-known". They are listed in data/known-sites-dropped.txt for review.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const D = require('../lib/detector.js');
const L = require('../lib/list-verify.js');

const args = process.argv.slice(2);
const arg = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};
const TOP = Number(arg('top', 100000));
const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'data', 'known-sites.txt');
const DROPPED = path.join(ROOT, 'data', 'known-sites-dropped.txt');
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

async function fetchRetry(url, tries = 5) {
  for (let i = 1; ; i++) {
    const res = await fetch(url, { redirect: 'follow' });
    if (res.ok) return res;
    if (i >= tries) throw new Error(`${url} -> HTTP ${res.status}`);
    await new Promise((r) => setTimeout(r, 2000 * i)); // Tranco rate-limits bursts
  }
}

(async () => {
  let listId = arg('list-id');
  let created = '';
  if (!listId) {
    const meta = await (await fetchRetry('https://tranco-list.eu/api/lists/date/latest')).json();
    listId = meta.list_id;
    created = meta.created_on?.slice(0, 10) || '';
  }
  console.log(`Downloading Tranco list ${listId}, top ${TOP}…`);
  const csv = await (await fetchRetry(`https://tranco-list.eu/download/${listId}/${TOP}`)).text();

  const kept = [];
  const seen = new Set();
  const dropped = [];
  for (const line of csv.split(/\r?\n/)) {
    const [rank, raw] = line.split(',');
    if (!raw) continue;
    const d = raw.trim().toLowerCase();
    if (!DOMAIN_RE.test(d) || seen.has(d)) { dropped.push(`${rank}\t${d}\tinvalid or duplicate`); continue; }
    if (d.endsWith('.arpa')) { dropped.push(`${rank}\t${d}\treverse-DNS entry`); continue; }
    const r = D.analyzeUrl(`https://${d}/`);
    // 'sameLabel' alone = a brand's own site on another ending (google.ru): keep.
    if (r.verdict === 'danger' && r.codes.some((c) => c !== 'sameLabel')) {
      dropped.push(`${rank}\t${d}\tlooks like a fake of ${r.impersonates}: ${r.reasons[0]}`);
      continue;
    }
    seen.add(d);
    kept.push(d);
  }
  if (kept.length < 1000) throw new Error(`Only ${kept.length} domains - refusing to write a broken list`);

  // Serial = build time (YYYYMMDDHHMM). The extension only accepts lists newer than
  // the one it has, so an attacker can't replay an old (validly signed) list.
  const now = new Date();
  const serial = now.toISOString().replace(/\D/g, '').slice(0, 12);
  const header = [
    '# Grilled Phish - well-known websites, most visited first.',
    `# Source: Tranco list ${listId} (https://tranco-list.eu/list/${listId})${created ? ', created ' + created : ''}`,
    `# Built: ${now.toISOString().slice(0, 10)}, ${kept.length} domains. "Known" means popular, not safe.`,
    `# Serial: ${serial}`,
  ];
  const text = header.concat(kept).join('\n') + '\n';

  // Compare with the list currently in the repo: stricter than the extension's
  // own limit, and summarised for the person approving the signature.
  let previous = null;
  if (fs.existsSync(OUT)) {
    const old = fs.readFileSync(OUT, 'utf8');
    try { previous = L.parseList(L.splitSigned(old)?.body ?? old); } catch { previous = null; }
  }
  const next = L.parseList(text);
  const sanity = L.checkListSanity(next, previous, { maxChurn: 0.25 });
  if (!sanity.ok && !args.includes('--force')) throw new Error(`New list rejected: ${sanity.reason} (use --force to override)`);

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, text); // unsigned: tools/sign-list.js adds the signature
  fs.writeFileSync(DROPPED, ['# rank\tdomain\treason', ...dropped].join('\n') + '\n');
  console.log(`Wrote ${kept.length} domains to ${path.relative(ROOT, OUT)} (${dropped.length} dropped, see ${path.relative(ROOT, DROPPED)})`);

  // Change summary (also shown on the GitHub run page, for the approval step).
  const oldSet = new Set(previous?.domains || []);
  const newSet = new Set(kept);
  const added = kept.filter((d) => !oldSet.has(d));
  const removed = (previous?.domains || []).filter((d) => !newSet.has(d));
  const summary = [
    '## Well-known sites list',
    '',
    `- Tranco list: \`${listId}\`, serial \`${serial}\`, **${kept.length}** domains`,
    `- Compared with the current list: **+${added.length}** added, **-${removed.length}** removed`,
    `- Dropped as fakes/invalid: ${dropped.length} (see \`data/known-sites-dropped.txt\`)`,
    '',
    '**Highest-ranked additions** (check nothing here looks like a scam copy):',
    '',
    added.slice(0, 25).map((d) => `\`${d}\``).join(', ') || '_none_',
    '',
  ].join('\n');
  console.log('\n' + summary);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + '\n');
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `changed=${added.length + removed.length > 0}\n`);
})().catch((e) => { console.error(e.message || e); process.exit(1); });
