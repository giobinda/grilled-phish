// Checks the extension's translations (_locales/*/messages.json):
// every key the code uses exists, every language has every key with the same
// $1/$2 placeholders, markup stays minimal, and the English text built into
// lib/detector.js (used outside the browser) matches _locales/en.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const locales = Object.fromEntries(fs.readdirSync(path.join(ROOT, '_locales')).map((d) =>
  [d, JSON.parse(read(`_locales/${d}/messages.json`))]));
const EN = locales.en;
const holes = (s) => [...new Set(s.match(/\$\d/g) || [])].sort().join(',');

test('every key used in the code exists in English', () => {
  const used = new Set();
  const code = ['lib/detector.js', 'content/content.js', 'background.js', 'popup/popup.js', 'options/options.js']
    .map(read).join('\n');
  for (const m of code.matchAll(/\b(?:T|L|GP_T|getMessage)\('([A-Za-z0-9_]+)'/g)) used.add(m[1]);
  const html = ['popup/popup.html', 'options/options.html'].map(read).join('\n');
  for (const m of html.matchAll(/data-i18n(?:-html|-placeholder)?="([A-Za-z0-9_]+)"/g)) used.add(m[1]);
  for (const m of read('manifest.json').matchAll(/__MSG_([A-Za-z0-9_]+)__/g)) used.add(m[1]);
  assert.ok(used.size > 80, `found only ${used.size} keys`);
  for (const k of used) assert.ok(EN[k], `missing English message ${k}`);
  for (const k of Object.keys(EN)) assert.ok(used.has(k), `unused message ${k}`);
});

for (const [lang, msgs] of Object.entries(locales)) {
  test(`${lang}: complete, same placeholders, safe markup`, () => {
    for (const [k, v] of Object.entries(EN)) {
      assert.ok(msgs[k]?.message, `${lang} missing ${k}`);
      assert.strictEqual(holes(msgs[k].message), holes(v.message), `${lang} ${k} placeholders`);
      for (const tag of msgs[k].message.match(/<[^>]*>/g) || []) assert.match(tag, /^<\/?(strong|code)>$/, `${lang} ${k}`);
    }
    for (const k of Object.keys(msgs)) assert.ok(EN[k], `${lang} has extra key ${k}`);
    assert.ok(msgs.extName.message.length <= 45 && msgs.extDescription.message.length <= 132, `${lang} store limits`);
  });
}

test('detector English fallback matches _locales/en', () => {
  // Same detector, once with a fake chrome.i18n backed by _locales/en, once without.
  const load = (withI18n) => {
    delete require.cache[require.resolve('../lib/detector.js')];
    globalThis.chrome = withI18n ? { i18n: { getMessage: (k, subs = []) =>
      (EN[k]?.message || '').replace(/\$(\d)/g, (_, n) => subs[n - 1] ?? '') } } : undefined;
    const D = require('../lib/detector.js');
    delete globalThis.chrome;
    return D;
  };
  const urls = ['http://8.8.8.8/x', 'https://xn--pypal-4ve.com/', 'https://paypa1.com/', 'https://paypal.com.secure-login.net/',
    'https://paypal-secure-login.com/', 'https://arnazon.com/', 'https://faceb00k.com/'];
  const plain = load(false), viaEn = load(true);
  for (const u of urls) {
    assert.deepStrictEqual(viaEn.analyzeUrl(u, { linkText: 'paypal.com' }).reasons, plain.analyzeUrl(u, { linkText: 'paypal.com' }).reasons, u);
  }
  for (const d of [0, 1, 5, 90, 1000]) assert.strictEqual(viaEn.describeAge(d), plain.describeAge(d));
  const created = new Date(Date.now() - 3 * 86400000).toISOString();
  assert.deepStrictEqual(viaEn.applyDomainAge(viaEn.analyzeUrl('https://x-shop.com/'), created).reasons,
    plain.applyDomainAge(plain.analyzeUrl('https://x-shop.com/'), created).reasons);
});
