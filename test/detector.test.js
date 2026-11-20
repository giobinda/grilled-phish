const test = require('node:test');
const assert = require('node:assert');
const { domainToASCII } = require('node:url');
const D = require('../lib/detector.js');

const check = (url, opts) => D.analyzeUrl(url, opts);
const puny = (unicodeHost) => 'https://' + domainToASCII(unicodeHost) + '/';

test('punycode decoder matches Node', () => {
  for (const h of ['pаypal.com', 'аррӏе.com', 'münchen.de', '日本語.jp', 'ɡoogle.com']) {
    assert.strictEqual(D.toUnicodeHost(domainToASCII(h)), h);
  }
});

const DANGER = [
  [puny('pаypal.com'), 'PayPal', 'Cyrillic a'],
  [puny('аррӏе.com'), 'Apple', 'all-Cyrillic apple'],
  [puny('ɡoogle.com'), 'Google', 'Latin script g'],
  [puny('paypál.com'), 'PayPal', 'accent'],
  ['https://paypa1.com/', 'PayPal', 'digit 1'],
  ['https://arnazon.com/', 'Amazon', 'rn for m'],
  ['https://g00gle.com/', 'Google', 'zeros'],
  ['https://paypal.xyz/', 'PayPal', 'wrong TLD'],
  ['https://amazom.com/', 'Amazon', 'typo'],
  ['https://netfilx.com/', 'Netflix', 'transposition'],
  ['https://www.paypal.com.secure-verify.xyz/', 'PayPal', 'brand as subdomain'],
  ['https://paypal-login.netlify.app/', 'PayPal', 'free hosting'],
  ['https://paypal-secure-login.com/', 'PayPal', 'bait words'],
  ['https://amazonrefund.net/', 'Amazon', 'glued bait'],
  ['https://my-chase.com/', 'Chase', 'my- prefix'],
  ['https://dhl-parcel-tracking.top/', 'DHL', 'delivery scam'],
  ['https://poste-italiane-verifica.com/', null, 'poste'],
  ['https://45.12.33.9/login', null, 'raw IP'],
];
for (const [url, brand, why] of DANGER) {
  test(`danger: ${why} (${url})`, () => {
    const r = check(url);
    assert.strictEqual(r.verdict, 'danger', JSON.stringify(r));
    if (brand) assert.strictEqual(r.impersonates, brand);
  });
}

test('danger: link text shows paypal.com but goes elsewhere', () => {
  const r = check('https://evil.example/x', { linkText: 'https://www.paypal.com/signin' });
  assert.strictEqual(r.verdict, 'danger');
  assert.strictEqual(r.impersonates, 'PayPal');
});

test('user trusted bank: look-alike is caught, real one is trusted', () => {
  const trusted = ['bancamiaonline.it'];
  assert.strictEqual(check('https://www.bancamiaonline.it/', { trusted }).verdict, 'trusted');
  assert.strictEqual(check('https://bancamiaonIine.it/', { trusted }).verdict, 'danger');
  assert.strictEqual(check('https://bancamiaonline.com/', { trusted }).verdict, 'danger');
  assert.strictEqual(check('https://bancamiaonline.it.login-check.ru/', { trusted }).verdict, 'danger');
});

const TRUSTED = ['https://www.paypal.com/', 'https://accounts.google.com/', 'https://google.co.uk/',
  'https://www.amazon.it/', 'https://login.microsoftonline.com/', 'https://x.com/', 'https://poste.it/'];
for (const url of TRUSTED) test(`trusted: ${url}`, () => assert.strictEqual(check(url).verdict, 'trusted'));

const UNKNOWN = ['https://wikipedia.org/', 'https://github.com/', 'https://apple-pie-recipes.com/',
  'https://apply.com/', 'https://ample.com/', 'https://abode.com/', 'https://stream.com/', 'https://cloud.com/',
  'https://revolt.chat/', 'https://chaser.com/', 'https://googleplex.example/', 'https://bbc.co.uk/',
  'https://upstairs.com/', 'https://pastebin.com/', 'https://booking-tips.blog/', 'https://192.168.1.1/',
  'https://münchen.de/', 'https://news.ycombinator.com/', 'https://nytimes.com/', 'https://stackoverflow.com/',
  'https://reddit.com/', 'https://repubblica.it/', 'https://corriere.it/', 'https://zalando.it/',
  'https://ikea.com/', 'https://mediaworld.it/', 'https://unieuro.it/', 'https://subito.it/',
  'https://idealista.it/', 'https://trenitalia.com/', 'https://italotreno.it/', 'https://fineco.it/',
  'https://bancobpm.it/', 'https://mozilla.org/', 'https://cloudflare.com/', 'https://shopify.com/'];
for (const url of UNKNOWN) test(`not flagged: ${url}`, () => {
  const r = check(url);
  assert.notStrictEqual(r.verdict, 'danger', JSON.stringify(r.reasons));
});

// ------------------------------------------------------------ domain age
const NOW = Date.parse('2026-11-13T12:00:00Z');
const daysAgo = (n) => new Date(NOW - n * 86400000).toISOString();

test('age: lookup domain', () => {
  assert.strictEqual(D.ageLookupDomain('https://shop.best-deals.xyz/a'), 'best-deals.xyz');
  assert.strictEqual(D.ageLookupDomain('https://www.bbc.co.uk/'), 'bbc.co.uk');
  assert.strictEqual(D.ageLookupDomain('https://paypal-login.netlify.app/'), null);
  assert.strictEqual(D.ageLookupDomain('https://45.1.2.3/'), null);
  assert.strictEqual(D.ageLookupDomain('http://localhost:8080/'), null);
  assert.strictEqual(D.ageLookupDomain('mailto:a@b.com'), null);
});

test('age: 3-day-old unknown site gets a mild caution, not a block', () => {
  const r = D.applyDomainAge(D.analyzeUrl('https://best-deals-4u.shop/'), daysAgo(3), { now: NOW });
  assert.strictEqual(r.verdict, 'caution');
  assert.strictEqual(r.ageDays, 3);
  assert.match(r.reasons.at(-1), /only 3 days ago/);
});

test('age: created today / yesterday wording', () => {
  assert.match(D.applyDomainAge(D.analyzeUrl('https://x-shop.com/'), daysAgo(0), { now: NOW }).reasons[0], /created today/);
  assert.match(D.applyDomainAge(D.analyzeUrl('https://x-shop.com/'), daysAgo(1), { now: NOW }).reasons[0], /created yesterday/);
});

test('age: old site stays unknown, threshold respected', () => {
  assert.strictEqual(D.applyDomainAge(D.analyzeUrl('https://wikipedia.org/'), '2001-01-13T00:12:14Z', { now: NOW }).verdict, 'unknown');
  assert.strictEqual(D.applyDomainAge(D.analyzeUrl('https://x-shop.com/'), daysAgo(45), { now: NOW, maxDays: 30 }).verdict, 'unknown');
  assert.strictEqual(D.applyDomainAge(D.analyzeUrl('https://x-shop.com/'), daysAgo(45), { now: NOW, maxDays: 90 }).verdict, 'caution');
});

test('age: never overrides trusted, adds reason to existing danger', () => {
  assert.strictEqual(D.applyDomainAge(D.analyzeUrl('https://paypal.com/'), daysAgo(2), { now: NOW }).verdict, 'trusted');
  const r = D.applyDomainAge(D.analyzeUrl('https://paypa1.com/'), daysAgo(2), { now: NOW });
  assert.strictEqual(r.verdict, 'danger');
  assert.strictEqual(r.reasons.length, 2);
  assert.strictEqual(r.impersonates, 'PayPal');
});

test('age: a new look-alike of a well-known site is still blocked, not just cautioned', () => {
  const idx = D.buildKnownIndex(['mywebsite.com']);
  const created = daysAgo(3);
  let r = D.applyKnownSites(D.analyzeUrl('https://mywebslte.com/'), { ...D.knownSiteInfo('mywebslte.com', idx), created }, { now: NOW });
  r = D.applyDomainAge(r, created, { now: NOW });
  assert.strictEqual(r.verdict, 'danger');
});

test('strict mode turns a mild caution into a full block, and changes nothing else', () => {
  const young = D.applyDomainAge(D.analyzeUrl('https://best-deals-4u.shop/'), daysAgo(3), { now: NOW });
  assert.strictEqual(D.applyStrict(young, false).verdict, 'caution');
  assert.strictEqual(D.applyStrict(young, true).verdict, 'danger');
  for (const u of ['https://paypal.com/', 'https://wikipedia.org/', 'https://paypa1.com/']) {
    const r = D.analyzeUrl(u);
    assert.strictEqual(D.applyStrict(r, true).verdict, r.verdict, u);
  }
});

test('age: missing or bad date changes nothing', () => {
  const base = D.analyzeUrl('https://x-shop.com/');
  assert.strictEqual(D.applyDomainAge(base, null), base);
  assert.strictEqual(D.applyDomainAge(base, 'garbage'), base);
});

test('age: describeAge', () => {
  assert.strictEqual(D.describeAge(400), '13 months ago');
  assert.strictEqual(D.describeAge(9000), '24 years ago');
});

// ------------------------------------------------------------ well-known sites database
const fs = require('node:fs');
const path = require('node:path');
const NOW2 = Date.parse('2026-11-13T12:00:00Z');
const ago = (n) => new Date(NOW2 - n * 86400000).toISOString();
const small = D.buildKnownIndex(['mywebsite.com', 'online-shop.it', 'telia.com', 'bbc.co.uk']);
const db = (url, index, extra = {}) => {
  const host = new URL(url).hostname;
  return D.applyKnownSites(D.analyzeUrl(url), { ...D.knownSiteInfo(host, index), ...extra }, { now: NOW2 });
};

test('db: the user example MYWEBSlTE.com (capital I -> l) is caught when new', () => {
  const info = D.knownSiteInfo('mywebslte.com', small);
  assert.strictEqual(info.lookalike.domain, 'mywebsite.com');
  assert.strictEqual(info.lookalike.strong, false);
  const r = db('https://MYWEBSlTE.com/', small, { created: ago(6) });
  assert.strictEqual(r.verdict, 'danger');
  assert.strictEqual(r.realDomains[0], 'mywebsite.com');
  assert.match(r.reasons[0], /almost identical to "mywebsite.com"/);
});

test('db: letter swap on an old established site is NOT blocked', () => {
  assert.notStrictEqual(db('https://tella.com/', small, { created: ago(9000) }).verdict, 'danger');
  assert.notStrictEqual(db('https://mywebslte.com/', small, {}).verdict, 'danger'); // age unknown
});

test('db: letter swap of a well-known name that is not registered is blocked', () => {
  const real = D.buildKnownIndex(['stackoverflow.com']);
  const r = db('https://stackoverfIow.com/questions', real, { unregistered: true });
  assert.strictEqual(r.verdict, 'danger');
  assert.strictEqual(r.realDomains[0], 'stackoverflow.com');
  // Not registered alone is not a reason: only for look-alikes of well-known names.
  assert.notStrictEqual(db('https://some-new-bakery.com/', real, { unregistered: true }).verdict, 'danger');
});

test('db: only the shipped list can mark a site as known (a stolen signing key cannot exempt addresses)', () => {
  const base = new Set(['stackoverflow.com', 'mywebsite.com']);
  // A downloaded list that sneaks a fake in, even ranked above the real site.
  const idx = D.buildKnownIndex(['stackoverfiow.com', 'stackoverflow.com', 'mywebsite.com', 'newshop.com'], { base });
  const fake = D.knownSiteInfo('stackoverfiow.com', idx);
  assert.strictEqual(fake.known, null);
  assert.strictEqual(fake.lookalike.domain, 'stackoverflow.com');
  assert.strictEqual(db('https://stackoverfIow.com/', idx, { unregistered: true }).verdict, 'danger');
  // The real site stays known; a genuinely new downloaded site is simply checked like any other.
  assert.ok(D.knownSiteInfo('stackoverflow.com', idx).known);
  assert.strictEqual(D.knownSiteInfo('newshop.com', idx).known, null);
  // Without a base (tests, tools) every listed domain counts, as before.
  assert.ok(D.knownSiteInfo('newshop.com', D.buildKnownIndex(['newshop.com'])).known);
});

test('typo: addresses one keystroke away from a very popular site get a suggestion', () => {
  const idx = D.buildKnownIndex(['google.com', 'github.com', 'wikipedia.org', 'amazon.co.uk', 'hulu.com', 'site2.com', 'my-shop.com']);
  const s = (h) => D.typoSuggestion(h, idx)?.domain ?? null;
  assert.strictEqual(s('githhub.com'), 'github.com');      // extra letter
  assert.strictEqual(s('gihub.com'), 'github.com');        // missing letter
  assert.strictEqual(s('gihtub.com'), 'github.com');       // swapped letters
  assert.strictEqual(s('www.githib.com'), 'github.com');   // wrong letter, with www
  assert.strictEqual(s('wikipedai.org'), 'wikipedia.org');
  assert.strictEqual(s('amazn.co.uk'), 'amazon.co.uk');
  // Not typos: the site itself, another ending, short names, numbers, hyphens, two mistakes.
  for (const h of ['github.com', 'github.io', 'hula.com', 'site3.com', 'myshop.com', 'gthhub.com', 'gooogle.org']) {
    assert.strictEqual(s(h), null, h);
  }
});

test('typo: added downloaded names are never suggested (only the shipped list)', () => {
  const idx = D.buildKnownIndex(['github.com', 'evilsite.com'], { base: new Set(['github.com']) });
  assert.strictEqual(D.typoSuggestion('evilsitee.com', idx), null);
  assert.strictEqual(D.typoSuggestion('githhub.com', idx).domain, 'github.com');
});

test('db: hidden digits / foreign letters are blocked immediately', () => {
  assert.strictEqual(db('https://myweb5ite.com/', small).verdict, 'unknown'); // 5 is not a look-alike digit
  assert.strictEqual(db('https://mywebs1te.com/', small).verdict, 'danger');
  assert.strictEqual(db(puny('mywebsіte.com'), small).verdict, 'danger'); // Ukrainian і
});

test('db: hyphen-only difference and same name on another ending are allowed', () => {
  assert.notStrictEqual(db('https://my-website.com/', small).verdict, 'danger');
  assert.notStrictEqual(db('https://mywebsite.net/', small).verdict, 'danger');
});

test('db: well-known address used as a prefix is blocked', () => {
  const r = db('https://mywebsite.com.secure-check.xyz/', small);
  assert.strictEqual(r.verdict, 'danger');
  assert.match(r.reasons[0], /starts with "mywebsite.com"/);
});

test('db: known sites, longer endings, hosting', () => {
  assert.strictEqual(D.knownSiteInfo('news.bbc.co.uk', small).known, 4);
  assert.strictEqual(D.knownSiteInfo('evil.github.io', D.buildKnownIndex(['github.io'])).known, null);
  assert.strictEqual(D.knownSiteInfo('letras.mus.br', D.buildKnownIndex(['letras.mus.br'])).known, 1);
});

const DATA = path.join(__dirname, '..', 'data', 'known-sites.txt');
test('db (real list): brands\' own country sites are no longer blocked', { skip: !fs.existsSync(DATA) }, () => {
  const real = D.buildKnownIndex(fs.readFileSync(DATA, 'utf8').split('\n'));
  assert.ok(real.size > 50000);
  for (const u of ['https://google.ru/', 'https://amazon.co.za/', 'https://www.google.co.id/', 'https://santander.com.br/']) {
    assert.notStrictEqual(db(u, real).verdict, 'danger', u);
  }
  // Popular typo-squatters were removed from the list and stay blocked.
  assert.strictEqual(D.knownSiteInfo('instragram.com', real).known, null);
  assert.strictEqual(db('https://instragram.com/', real).verdict, 'danger');
  // Look-alikes of sites outside the 40 built-in brands:
  const wiki = db('https://wikipedla.org/', real, { created: ago(3) });
  assert.strictEqual(wiki.verdict, 'danger');
  assert.strictEqual(wiki.impersonates, 'wikipedia.org');
  assert.strictEqual(db('https://g1thub.com/', real).verdict, 'danger');
  assert.strictEqual(db('https://repubbIica.it/', real, { created: ago(10) }).verdict, 'danger');
});
