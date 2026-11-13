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

  const header = [
    '# Grilled Phish - well-known websites, most visited first.',
    `# Source: Tranco list ${listId} (https://tranco-list.eu/list/${listId})${created ? ', created ' + created : ''}`,
    `# Built: ${new Date().toISOString().slice(0, 10)}, ${kept.length} domains. "Known" means popular, not safe.`,
  ];
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, header.concat(kept).join('\n') + '\n');
  fs.writeFileSync(DROPPED, ['# rank\tdomain\treason', ...dropped].join('\n') + '\n');
  console.log(`Wrote ${kept.length} domains to ${path.relative(ROOT, OUT)} (${dropped.length} dropped, see ${path.relative(ROOT, DROPPED)})`);
})().catch((e) => { console.error(e.message || e); process.exit(1); });
