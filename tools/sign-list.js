#!/usr/bin/env node
/*
 * Signs data/known-sites.txt in place (appends a "#sig:" line).
 *
 *   LIST_SIGNING_KEY="$(cat key.pem)" node tools/sign-list.js      # CI
 *   node tools/sign-list.js --key ~/.config/grilled-phish/list-signing-key.pem
 *
 * Refuses to sign a list that fails the sanity rules, and checks the result
 * against the public keys shipped in the extension before writing it.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const L = require('../lib/list-verify.js');
const KEYS = require('../lib/list-public-key.js');

const args = process.argv.slice(2);
const keyArg = args.includes('--key') ? args[args.indexOf('--key') + 1] : null;
const LIST = path.join(__dirname, '..', 'data', 'known-sites.txt');

(async () => {
  let pem = process.env.LIST_SIGNING_KEY;
  if (!pem) {
    const file = keyArg || path.join(os.homedir(), '.config', 'grilled-phish', 'list-signing-key.pem');
    if (!fs.existsSync(file)) throw new Error(`No key: set LIST_SIGNING_KEY or pass --key (looked for ${file})`);
    pem = fs.readFileSync(file, 'utf8');
  }

  let text = fs.readFileSync(LIST, 'utf8');
  const existing = L.splitSigned(text);
  if (existing) text = existing.body; // re-signing: drop the old signature
  if (!text.endsWith('\n')) text += '\n';

  const sanity = L.checkListSanity(L.parseList(text), null);
  if (!sanity.ok) throw new Error(`Refusing to sign: ${sanity.reason}`);

  const sig = crypto.sign('sha256', Buffer.from(text, 'utf8'), { key: pem, dsaEncoding: 'ieee-p1363' });
  const signed = `${text}${L.SIG_PREFIX}${sig.toString('base64')}\n`;
  if (!(await L.verifySignedList(signed, KEYS))) {
    throw new Error('Signature does not match any public key in lib/list-public-key.js (wrong key?)');
  }
  fs.writeFileSync(LIST, signed);
  console.log(`Signed ${path.relative(process.cwd(), LIST)} (serial ${L.parseList(text).serial})`);
})().catch((e) => { console.error(e.message || e); process.exit(1); });
