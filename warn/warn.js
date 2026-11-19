/*
 * Grilled Phish - full-page warning shown INSTEAD of a site, before it loads:
 *   - a certainly fake address (opened from the address bar, a bookmark, another app);
 *   - an address typed with a likely mistake ("githhub.com" -> github.com?).
 * Extension page, not reachable by websites. The verdict is recomputed by the
 * background worker; the query string only says which address was requested.
 */
'use strict';

const T = globalThis.GP_T;
const WAIT_SECONDS = 5;
const target = new URLSearchParams(location.search).get('u') || '';
const box = document.getElementById('box');

const el = (tag, attrs = {}, text) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text != null) n.textContent = text;
  return n;
};
const hostOf = (u) => { try { return new URL(u).hostname; } catch { return ''; } };
const send = (msg) => chrome.runtime.sendMessage(msg).catch(() => null);

async function goBack() {
  await send({ type: 'goBack', url: target });
  if (history.length > 1) history.back();
  else chrome.tabs.getCurrent((t) => t && chrome.tabs.remove(t.id));
}

async function proceed(url, type = 'allowNav') {
  await send({ type, url });
  location.replace(url);
}

// The address, with letters that differ from the real name highlighted.
function domainBox(shown, real) {
  const d = el('div', { class: 'domain' });
  const a = Array.from(shown);
  const b = real ? Array.from(real) : [];
  a.forEach((ch, i) => {
    const s = el('span', {}, ch);
    if (/[^\x00-\x7f]/.test(ch) || (b.length === a.length && b[i] !== ch)) s.className = 'odd';
    d.appendChild(s);
  });
  return d;
}

// Who is showing this page, so nobody mistakes it for a virus or the website's own message.
function brandBar(message) {
  const bar = el('div', { class: 'brand' });
  const logo = el('img', { src: '../icons/icon-48.png', alt: '', width: '40', height: '40' });
  const text = el('div');
  text.append(el('strong', {}, 'Grilled Phish'), el('span', {}, message));
  bar.append(logo, text);
  return bar;
}

function learnButton() {
  const b = el('button', { class: 'learn', type: 'button' }, T('dlgLearn'));
  b.addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('learn/learn.html') }));
  return b;
}

function renderDanger(r) {
  box.appendChild(brandBar(T('navBrandDanger')));
  box.appendChild(el('h1', {}, T('navTitle')));
  box.appendChild(el('p', {}, r.impersonates ? T('dlgPretending', r.impersonates) : T('dlgTrick')));
  box.appendChild(el('div', { class: 'label' }, T('navAddress')));
  box.appendChild(domainBox(r.displayHost || hostOf(target), r.realDomains?.[0] && r.displayHost?.endsWith(r.registrable)
    ? r.displayHost.slice(0, r.displayHost.length - r.registrable.length) + r.realDomains[0] : null));
  if (r.realDomains?.length) {
    box.appendChild(el('div', { class: 'label' }, T('dlgRealSite', r.impersonates)));
    box.appendChild(el('div', { class: 'domain real' }, r.realDomains[0]));
  }
  box.appendChild(el('div', { class: 'label' }, T('dlgWhy')));
  const ul = el('ul');
  r.reasons.forEach((t) => ul.appendChild(el('li', {}, t)));
  box.appendChild(ul);

  const safe = el('button', { class: 'safe', type: 'button' }, T('dlgGoBack'));
  safe.addEventListener('click', goBack);
  box.appendChild(safe);
  if (r.realDomains?.length) {
    // Only the real site's front page: never carry over the rest of a fake address.
    const real = el('button', { class: 'second', type: 'button' }, T('typoGo', r.realDomains[0]));
    real.addEventListener('click', () => location.replace(`https://${r.realDomains[0]}/`));
    box.appendChild(real);
  }
  box.appendChild(learnButton());

  const details = el('details');
  details.appendChild(el('summary', {}, T('dlgKnow')));
  details.appendChild(el('p', { class: 'phone' }, T('dlgPhone')));
  const risky = el('div', { class: 'risky' });
  const label = el('label');
  const check = el('input', { type: 'checkbox' });
  label.append(check, el('span', {}, T('dlgConfirmLink')));
  const anyway = el('button', { class: 'anyway', type: 'button', disabled: '' }, T('dlgWait', WAIT_SECONDS));
  risky.append(label, anyway);
  details.appendChild(risky);
  box.appendChild(details);

  // Same rule as the in-page dialog: tick the box, then wait 5 seconds.
  let left = WAIT_SECONDS, timer = null;
  const update = () => {
    anyway.disabled = !(check.checked && left <= 0);
    anyway.textContent = left > 0 ? T('dlgWait', left) : T('navOpen');
  };
  details.addEventListener('toggle', () => {
    if (!details.open || timer) return;
    timer = setInterval(() => { left--; update(); if (left <= 0) clearInterval(timer); }, 1000);
  });
  check.addEventListener('change', update);
  anyway.addEventListener('click', (e) => {
    if (!e.isTrusted || anyway.disabled) return;
    proceed(target);
  });
  safe.focus();
}

function renderTypo(typo) {
  document.body.classList.add('typo');
  const typed = hostOf(target);
  const u = new URL(target);
  // Keep the rest of what was typed ("githhub.com/me" -> "github.com/me").
  const fixed = `https://${typed.startsWith('www.') ? 'www.' : ''}${typo.domain}${u.pathname}${u.search}${u.hash}`;

  box.appendChild(brandBar(T('navBrandTypo')));
  box.appendChild(el('h1', {}, T('typoTitle', typo.domain)));
  box.appendChild(el('p', {}, T('typoText', typed, typo.domain)));
  box.appendChild(el('div', { class: 'label' }, T('navAddress')));
  box.appendChild(domainBox(typed));
  box.appendChild(el('div', { class: 'label' }, T('dlgRealSite', typo.domain)));
  box.appendChild(el('div', { class: 'domain real' }, typo.domain));

  const go = el('button', { class: 'safe', type: 'button' }, T('typoGo', typo.domain));
  go.addEventListener('click', () => location.replace(fixed));
  box.appendChild(go);
  const meant = el('button', { class: 'second', type: 'button' }, T('typoMeant', typed));
  meant.addEventListener('click', (e) => { if (e.isTrusted) proceed(target, 'typoOk'); });
  box.appendChild(meant);
  box.appendChild(el('p', { class: 'note' }, T('typoNote')));
  go.focus();
}

(async () => {
  if (!/^https?:\/\//i.test(target)) { history.back(); return; }
  // The background worker may be waking up: ask twice before giving up.
  let info = await send({ type: 'navInfo', url: target });
  if (!info) { await new Promise((r) => setTimeout(r, 700)); info = await send({ type: 'navInfo', url: target }); }
  if (info?.danger) renderDanger(info.danger);
  else if (info?.typo) renderTypo(info.typo);
  else { location.replace(target); return; } // nothing wrong (any more): just go
  box.hidden = false;
})();
