// Every translation of the guide must have the same structure as English,
// and may only use the small set of markup the page expects.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const dir = path.join(__dirname, '..', 'learn', 'i18n');
const ctx = { GP_LEARN_I18N: {} };
vm.createContext(ctx);
for (const f of fs.readdirSync(dir)) vm.runInContext(fs.readFileSync(path.join(dir, f), 'utf8'), ctx, { filename: f });
const T = ctx.GP_LEARN_I18N;
const learnJs = fs.readFileSync(path.join(__dirname, '..', 'learn', 'learn.js'), 'utf8');
const LANGS = Object.keys(vm.runInNewContext(`(${learnJs.match(/const LANGS = (\{[\s\S]*?\});/)[1]})`));

const strings = (v) => (typeof v === 'string' ? [v] : Array.isArray(v) ? v.flatMap(strings)
  : v && typeof v === 'object' ? Object.values(v).flatMap(strings) : []);

test('every listed language has a file and vice versa', () => {
  assert.deepStrictEqual([...LANGS].sort(), Object.keys(T).sort());
});

for (const code of Object.keys(T)) {
  test(`${code}: same keys and list lengths as English`, () => {
    const t = T[code];
    for (const [k, v] of Object.entries(T.en)) {
      assert.ok(k in t, `missing ${k}`);
      if (Array.isArray(v)) assert.strictEqual(t[k].length, v.length, `${k} length`);
      if (k === 'src') for (const s of Object.keys(v)) assert.ok(t.src[s], `missing src.${s}`);
    }
  });
  test(`${code}: only simple markup, https links`, () => {
    for (const s of strings(T[code])) {
      for (const tag of s.match(/<\/?([a-z]+)[^>]*>/gi) || []) {
        assert.match(tag, /^<\/?(strong|b|code)>$/, `unexpected markup ${tag}`);
      }
    }
    for (const l of [...T[code].local.more, ...T[code].local.report]) {
      assert.match(l.href, /^https:\/\/[^/]+\//);
      assert.ok(l.label && l.desc);
    }
  });
}
