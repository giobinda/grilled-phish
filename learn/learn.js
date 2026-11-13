/*
 * Builds the "how to spot a scam" guide in the reader's language.
 *
 * Translations live in i18n/<code>.js, each one adding an object to
 * GP_LEARN_I18N. The strings are bundled with the extension (never downloaded),
 * so they may contain simple markup: <strong>, <b>, <code>.
 * To add a language: copy i18n/en.js, translate the values, add the code to LANGS.
 */
'use strict';

const LANGS = {
  en: 'English', es: 'Español', zh: '中文', hi: 'हिन्दी', ar: 'العربية', fr: 'Français',
  pt: 'Português', uk: 'Українська', ja: '日本語', de: 'Deutsch', it: 'Italiano', id: 'Bahasa Indonesia',
};
const RTL = new Set(['ar']);
// The project's only website. Grilled Phish never contacts anyone; see the "never" section.
const OFFICIAL_SITE = 'https://github.com/giobinda/grilled-phish';
globalThis.GP_LEARN_I18N = {};

// International sources, in English. Each translation describes them in its own language.
const SOURCES = {
  more: [
    { key: 'cisa', href: 'https://www.cisa.gov/secure-our-world/recognize-and-report-phishing', label: 'Recognize and report phishing' },
    { key: 'ncsc', href: 'https://www.ncsc.gov.uk/collection/phishing-scams', label: 'Phishing: spot and report scam emails, texts, websites and calls' },
    { key: 'aarp', href: 'https://www.aarp.org/money/scams-fraud/', label: 'AARP Scams & Fraud' },
  ],
  report: [
    { key: 'google', href: 'https://safebrowsing.google.com/safebrowsing/report_phish/', label: 'Google Safe Browsing', translated: true },
    { key: 'ftc', href: 'https://reportfraud.ftc.gov/', label: 'ReportFraud.ftc.gov' },
    { key: 'ncscReport', href: 'https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email', label: 'NCSC: report a scam email' },
  ],
};

const LOOKALIKES = [
  ['a<mark>rn</mark>azon.com', 'amazon.com'],
  ['paypa<mark>1</mark>.com', 'paypal.com'],
  ['g<mark>0</mark>ogle.com', 'google.com'],
  ['<mark>vv</mark>ellsfargo.com', 'wellsfargo.com'],
  ['ap<mark>р</mark>le.com', 'apple.com'],
];

function pickLanguage() {
  const fromUrl = new URLSearchParams(location.search).get('lang');
  if (fromUrl && LANGS[fromUrl]) return fromUrl;
  try {
    const saved = localStorage.getItem('gpLearnLang');
    if (saved && LANGS[saved]) return saved;
  } catch { /* storage unavailable */ }
  for (const l of navigator.languages || [navigator.language || 'en']) {
    const code = String(l).toLowerCase().split('-')[0];
    if (LANGS[code]) return code;
  }
  return 'en';
}

function load(code) {
  if (GP_LEARN_I18N[code]) return Promise.resolve(GP_LEARN_I18N[code]);
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = `i18n/${code}.js`;
    s.onload = () => (GP_LEARN_I18N[code] ? resolve(GP_LEARN_I18N[code]) : reject(new Error(code)));
    s.onerror = () => reject(new Error(code));
    document.head.appendChild(s);
  });
}

function h(tag, attrs = {}, html) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (html != null) e.innerHTML = html; // bundled translation strings only
  return e;
}

function list(tag, cls, items) {
  const ul = h(tag, { class: cls });
  items.forEach((it) => ul.appendChild(h('li', {}, it)));
  return ul;
}

function links(items, t) {
  const ul = h('ul', { class: 'links' });
  for (const it of items) {
    const li = h('li');
    const a = h('a', { href: it.href, target: '_blank', rel: 'noopener noreferrer' });
    a.textContent = it.label;
    li.appendChild(a);
    if (it.english && t.inEnglish) li.appendChild(h('em', { class: 'en' })).textContent = ` ${t.inEnglish}`;
    li.appendChild(h('span', {}, it.desc));
    ul.appendChild(li);
  }
  return ul;
}

function render(t, code) {
  const en = GP_LEARN_I18N.en || {};
  const app = document.getElementById('app');
  app.textContent = '';
  document.documentElement.lang = code;
  document.documentElement.dir = RTL.has(code) ? 'rtl' : 'ltr';
  document.title = t.title;

  const h1 = h('h1');
  h1.appendChild(h('img', { src: '../icons/icon-128.png', alt: '', class: 'logo' }));
  h1.appendChild(document.createElement('span')).textContent = t.title;
  app.append(h1, h('p', { class: 'lead' }, t.lead));

  app.append(h('h2', {}, t.whatH), ...t.what.map((p) => h('p', {}, p)));

  app.append(h('h2', {}, t.addrH), h('p', {}, t.addr));
  const ex = h('div', { class: 'examples' });
  const card = (cls, tag, url, note) => {
    const d = h('div', { class: `ex ${cls}` });
    d.append(h('span', { class: 'tag' }, tag), h('code', {}, url));
    if (note) d.appendChild(h('p', {}, note));
    return d;
  };
  ex.append(
    card('ok', `✅ ${t.real}`, 'https://www.<b>paypal.com</b>/signin'),
    card('bad', `⛔ ${t.fake}`, 'https://paypal.com.<b>secure-login.net</b>/signin', t.fake1),
    card('bad', `⛔ ${t.fake}`, 'https://www.<b>paypal-account-help.com</b>', t.fake2),
  );
  app.appendChild(ex);

  app.append(h('h2', {}, t.lettersH), h('p', {}, t.letters));
  const table = h('table', { class: 'pairs' });
  const head = h('tr');
  [t.thFake, t.thReal, t.thTrick].forEach((x) => head.appendChild(h('th', {}, x)));
  table.appendChild(head);
  LOOKALIKES.forEach(([fake, real], i) => {
    const tr = h('tr');
    tr.append(h('td', {}, `<code>${fake}</code>`), h('td', {}, `<code>${real}</code>`), h('td', {}, t.tricks[i]));
    table.appendChild(tr);
  });
  app.append(table, h('p', {}, t.lettersAfter));

  app.append(h('h2', {}, t.signsH), h('p', {}, t.signsIntro), list('ul', 'signs', t.signs));
  app.append(h('h2', {}, t.rulesH), list('ol', 'rules', t.rules));
  app.append(h('h2', {}, t.gpH), list('ul', 'signs', t.gp), h('p', { class: 'note' }, t.gpNote));
  app.append(h('h2', {}, t.clickedH), h('p', {}, t.clickedIntro), list('ol', 'rules', t.clicked));

  app.append(h('h2', {}, t.neverH), list('ul', 'never', t.never), h('p', { class: 'note' }, `<strong>${t.neverScam}</strong>`));
  const site = h('p', { class: 'official' });
  site.append(h('span', {}, `${t.neverSite} `));
  const siteLink = h('a', { href: OFFICIAL_SITE, target: '_blank', rel: 'noopener noreferrer' });
  siteLink.appendChild(h('code')).textContent = OFFICIAL_SITE.replace('https://', '');
  site.appendChild(siteLink);
  app.appendChild(site);

  app.appendChild(h('h2', {}, t.practiceH));
  const pr = h('p');
  const quiz = h('a', { href: `https://phishingquiz.withgoogle.com/?hl=${code}`, target: '_blank', rel: 'noopener noreferrer' });
  quiz.textContent = 'Phishing Quiz — Google Jigsaw';
  pr.append(quiz, h('span', {}, `: ${t.practice}`));
  app.appendChild(pr);

  const describe = (items) => items.map((s) => ({
    ...s, desc: t.src[s.key] || en.src?.[s.key] || '', english: !s.translated && code !== 'en',
  }));
  const local = t.local || {};
  app.append(h('h2', {}, t.moreH), links([...(local.more || []), ...describe(SOURCES.more)], t));
  app.append(h('h2', {}, t.reportH), links([...(local.report || []), ...describe(SOURCES.report)], t));
  app.appendChild(h('p', { class: 'hint' }, t.disclaimer));
  if (t.machine) app.appendChild(h('p', { class: 'hint' }, t.machine));
}

(async () => {
  const sel = document.getElementById('lang');
  for (const [code, name] of Object.entries(LANGS)) {
    const o = document.createElement('option');
    o.value = code;
    o.textContent = name;
    sel.appendChild(o);
  }
  const show = async (code) => {
    await load('en'); // fallback for any missing string
    let t;
    try { t = await load(code); } catch { code = 'en'; t = GP_LEARN_I18N.en; }
    render({ ...GP_LEARN_I18N.en, ...t }, code);
    sel.value = code;
    sel.setAttribute('aria-label', t.langLabel || 'Language');
  };
  sel.addEventListener('change', () => {
    try { localStorage.setItem('gpLearnLang', sel.value); } catch { /* ignore */ }
    show(sel.value);
  });
  await show(pickLanguage());
})();
