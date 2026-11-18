const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const L = require('../lib/list-verify.js');
const SHIPPED_KEYS = require('../lib/list-public-key.js');

// A throwaway key pair for the tests (never the real signing key).
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PUB = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const OTHER_PUB = other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

const sign = (text, key = privateKey) =>
  `${text}#sig:${crypto.sign('sha256', Buffer.from(text), { key, dsaEncoding: 'ieee-p1363' }).toString('base64')}\n`;

const makeList = (serial, extra = [], n = 2000) => {
  const domains = [...L.MUST_HAVE, ...extra];
  for (let i = 0; domains.length < n; i++) domains.push(`site${i}.com`);
  return `# Source: test\n# Serial: ${serial}\n${domains.join('\n')}\n`;
};

test('valid signature verifies', async () => {
  assert.strictEqual(await L.verifySignedList(sign(makeList(1)), [PUB]), true);
});

test('any change to the list breaks the signature', async () => {
  const signed = sign(makeList(1));
  const tampered = signed.replace('site5.com', 'paypa1.com');
  assert.notStrictEqual(tampered, signed);
  assert.strictEqual(await L.verifySignedList(tampered, [PUB]), false);
  // Even a change only in a comment line is rejected.
  assert.strictEqual(await L.verifySignedList(signed.replace('# Source: test', '# Source: tset'), [PUB]), false);
});

test('signature by a different key is rejected', async () => {
  assert.strictEqual(await L.verifySignedList(sign(makeList(1), other.privateKey), [PUB]), false);
  assert.strictEqual(await L.verifySignedList(sign(makeList(1)), [OTHER_PUB, PUB]), true); // key rotation
});

test('missing or garbage signature is rejected', async () => {
  assert.strictEqual(await L.verifySignedList(makeList(1), [PUB]), false);
  assert.strictEqual(await L.verifySignedList(makeList(1) + '#sig:AAAA\n', [PUB]), false);
  assert.strictEqual(await L.verifySignedList(makeList(1) + '#sig:' + 'A'.repeat(88) + '\n', [PUB]), false);
  assert.strictEqual(await L.verifySignedList(null, [PUB]), false);
});

test('sanity: older or same serial is refused (no replay of old lists)', () => {
  const cur = L.parseList(makeList(202611130000));
  assert.match(L.checkListSanity(L.parseList(makeList(202611120000)), cur).reason, /not newer/);
  assert.match(L.checkListSanity(L.parseList(makeList(202611130000)), cur).reason, /not newer/);
  assert.strictEqual(L.checkListSanity(L.parseList(makeList(202611140000)), cur).ok, true);
});

test('sanity: essential sites must be present', () => {
  const text = makeList(202611140000).replace('\npaypal.com\n', '\n');
  assert.match(L.checkListSanity(L.parseList(text), null).reason, /paypal\.com/);
});

test('sanity: too many removals at once are refused', () => {
  const cur = L.parseList(makeList(202611130000, [], 4000));
  const next = L.parseList(makeList(202611140000, [], 2000)); // drops half
  assert.match(L.checkListSanity(next, cur).reason, /removed at once/);
});

test('sanity: a list dated in the future is refused (it would block all later updates)', () => {
  const now = Date.parse('2026-11-18T12:00:00Z');
  const cur = L.parseList(makeList(202611130000));
  const check = (serial) => L.checkListSanity(L.parseList(makeList(serial)), cur, { now });
  assert.match(check(999999999999999).reason, /future|valid date/);
  assert.match(check(202612010000).reason, /future/);          // two weeks ahead
  assert.strictEqual(check(202611191000).ok, true);             // small clock difference is fine
  assert.match(check(202613010000).reason, /valid date/);      // month 13
  assert.match(check(202602300000).reason, /valid date/);      // 30 February
  assert.match(L.checkListSanity(L.parseList(makeList(2)), null, { now }).reason, /valid date/);
});

test('parseList rejects malformed lists', () => {
  assert.throws(() => L.parseList('# Serial: 1\ngoogle.com\n'), /entries/);
  assert.throws(() => L.parseList(makeList(1, ['not a domain'])), /invalid entry/);
  assert.throws(() => L.parseList(makeList(1, ['google.com'])), /duplicate/);
});

test('the shipped list is signed with the shipped public key', async () => {
  const text = fs.readFileSync(path.join(__dirname, '..', 'data', 'known-sites.txt'), 'utf8');
  assert.strictEqual(await L.verifySignedList(text, SHIPPED_KEYS), true);
  const parsed = L.parseList(L.splitSigned(text).body);
  assert.ok(parsed.serial > 202600000000);
  assert.strictEqual(L.checkListSanity(parsed, null).ok, true);
});
