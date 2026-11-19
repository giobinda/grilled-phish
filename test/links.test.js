// Grilled Phish must never become a way to send people to a website.
// Every web address in the shipped extension must be on this list; adding one
// is a deliberate decision that shows up in review.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SHIPPED = ['manifest.json', 'background.js', 'lib', 'content', 'popup', 'options', 'learn', 'warn', '_locales'];
const ALLOWED = {
  // Our only website.
  'github.com': /^https:\/\/github\.com\/giobinda\/grilled-phish$/,
  // Signed list updates (data only, never shown to the user).
  'cdn.jsdelivr.net': /^https:\/\/cdn\.jsdelivr\.net\/gh\/giobinda\/grilled-phish@main\//,
  'raw.githubusercontent.com': /^https:\/\/raw\.githubusercontent\.com\/giobinda\/grilled-phish\//,
  // Age check: the official registry directory (data only).
  'data.iana.org': /^https:\/\/data\.iana\.org\/rdap\//,
  // The guide: official / non-profit sources, practice quiz, reporting.
  ...Object.fromEntries([
    'www.cisa.gov', 'www.ncsc.gov.uk', 'www.aarp.org', 'safebrowsing.google.com', 'reportfraud.ftc.gov',
    'phishingquiz.withgoogle.com', 'www.commissariatodips.it', 'www.incibe.es', 'www.cybermalveillance.gouv.fr',
    'www.internet-signalement.gouv.fr', 'www.phishing-initiative.fr', 'www.bsi.bund.de', 'www.verbraucherzentrale.de',
    'cartilha.cert.br', 'www.cncs.gov.pt', 'www.antiphishing.jp', 'cybercrime.gov.in', 'cert.gov.ua',
    'cyberpolice.gov.ua', 'bank.gov.ua',
  ].map((h) => [h, /./])),
};

function files(p) {
  const full = path.join(ROOT, p);
  return fs.statSync(full).isDirectory() ? fs.readdirSync(full).flatMap((f) => files(path.join(p, f))) : [p];
}

test('the extension only contains approved web addresses', () => {
  const found = [];
  for (const f of SHIPPED.flatMap(files)) {
    if (!/\.(js|json|html|css)$/.test(f)) continue;
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    for (const m of text.matchAll(/\bhttps?:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?=[/"'`?#\s)]|$)[^"'`\s)<>]*/gi)) {
      found.push(m[1]);
      const rule = ALLOWED[m[1].toLowerCase()];
      assert.ok(rule, `${f}: unapproved address ${m[0]}`);
      assert.match(m[0].replace(/[`'"]$/, ''), rule, `${f}: ${m[0]}`);
      assert.ok(m[0].startsWith('https://'), `${f}: not https: ${m[0]}`);
    }
  }
  assert.ok(found.includes('github.com') && found.length > 20);
});

test('extension pages contain no remote scripts, frames or forms', () => {
  for (const f of SHIPPED.flatMap(files).filter((x) => x.endsWith('.html'))) {
    const html = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.doesNotMatch(html, /<script[^>]+src=["']https?:/i, f);
    assert.doesNotMatch(html, /<(iframe|form[^>]+action|link[^>]+href=["']https?:)/i, f);
  }
});
