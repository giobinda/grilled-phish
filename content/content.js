/*
 * Link Guardian - content script.
 *  - Puts a red box around dangerous links and disables them.
 *  - Clicking one opens a big warning; opening it anyway needs a checkbox
 *    plus a 5 second wait.
 *  - If the current page itself is a fake, shows a red banner and locks
 *    password / card fields behind the same warning.
 */
(() => {
  'use strict';
  if (window.__linkGuardianLoaded) return;
  window.__linkGuardianLoaded = true;

  const D = globalThis.LinkGuardDetector;
  const ATTR = 'data-linkguard';
  const BADGE_ATTR = 'data-linkguard-badge';
  const UNLOCK_SECONDS = 5;

  let trusted = [];
  let ageCheck = true;
  let ageDays = 30;
  const MAX_AGE_LOOKUPS_PER_PAGE = 50;
  const ageInfo = new Map();      // registrable domain -> ISO date | null
  const ageRequested = new Set();
  let agePending = new Set();
  let ageTimer = null;
  let pageBannerShown = false;
  const resultCache = new Map();
  const blocked = new WeakMap(); // <a> -> analysis result
  let dialogOpen = false;
  let passwordsUnlocked = false;
  let pageResult = null;

  // ---------------------------------------------------------------- styles
  const PAGE_CSS = `
    [${ATTR}="blocked"] {
      outline: 4px solid #d40000 !important;
      outline-offset: 2px !important;
      background: rgba(255, 0, 0, 0.12) !important;
      border-radius: 3px !important;
      cursor: not-allowed !important;
      text-decoration: line-through #d40000 2px !important;
    }
    [${ATTR}="blocked"] * { cursor: not-allowed !important; }
    span[${BADGE_ATTR}] {
      all: initial !important;
      display: inline-block !important;
      margin: 0 4px !important;
      padding: 2px 8px !important;
      background: #d40000 !important;
      color: #fff !important;
      font: bold 14px/1.4 system-ui, sans-serif !important;
      border-radius: 4px !important;
      cursor: pointer !important;
      vertical-align: middle !important;
      white-space: nowrap !important;
    }
  `;

  function injectPageStyle() {
    if (document.getElementById('linkguard-style')) return;
    const style = document.createElement('style');
    style.id = 'linkguard-style';
    style.textContent = PAGE_CSS;
    (document.head || document.documentElement).appendChild(style);
  }

  // ---------------------------------------------------------------- analysis
  // Three layers:
  //  1. local rules (detector.js), instant;
  //  2. well-known sites database (background, local, no network);
  //  3. domain age from the registry (background, network, optional).
  const MAX_DB_LOOKUPS_PER_PAGE = 400;
  const dbInfo = new Map();          // hostname -> { known, lookalike }
  const dbRequested = new Set();
  let dbPending = new Set();
  let dbTimer = null;

  const hostOf = (href) => { try { return new URL(href).hostname.toLowerCase(); } catch { return ''; } };

  function analyze(href, text) {
    const key = href + '\u0000' + text;
    if (resultCache.has(key)) return resultCache.get(key);
    let r = D.analyzeUrl(href, { trusted, linkText: text });
    if (r.verdict !== 'unknown' && r.verdict !== 'danger') { resultCache.set(key, r); return r; }

    const host = hostOf(href);
    const info = dbInfo.get(host);
    if (!info) {
      queueDbLookup(host);
      // Don't flash a red box on google.ru while the database answer is on its way.
      if (r.codes.length && r.codes.every((c) => c === 'sameLabel')) return { ...r, verdict: 'unknown' };
      return r; // not cached: recomputed when the answer arrives
    }

    const ageDomain = D.ageLookupDomain(href);
    const created = ageDomain ? ageInfo.get(ageDomain) : undefined;
    r = D.applyKnownSites(r, { ...info, created });
    if (!info.known && ageCheck && ageDomain) {
      if (ageInfo.has(ageDomain)) r = D.applyDomainAge(r, created, { maxDays: ageDays });
      else queueAgeLookup(ageDomain, info.lookalike && !info.lookalike.strong);
    }
    resultCache.set(key, r);
    return r;
  }

  function queueDbLookup(host) {
    if (!host || dbRequested.has(host) || dbRequested.size >= MAX_DB_LOOKUPS_PER_PAGE) return;
    dbRequested.add(host);
    dbPending.add(host);
    clearTimeout(dbTimer);
    dbTimer = setTimeout(flushDbLookups, 50);
  }

  async function flushDbLookups() {
    const hosts = [...dbPending];
    dbPending = new Set();
    if (!hosts.length) return;
    let answers = {};
    try {
      answers = (await chrome.runtime.sendMessage({ type: 'domainInfo', hosts })) || {};
    } catch { /* background unavailable */ }
    for (const h of hosts) dbInfo.set(h, answers[h] || { known: null, lookalike: null });
    refresh();
  }

  // ---------------------------------------------------------------- domain age
  // `priority`: a letter-swap look-alike needs its age to be decided, so it
  // bypasses the per-page limit.
  function queueAgeLookup(domain, priority) {
    if (ageRequested.has(domain)) return;
    if (!priority && ageRequested.size >= MAX_AGE_LOOKUPS_PER_PAGE) return;
    ageRequested.add(domain);
    agePending.add(domain);
    clearTimeout(ageTimer);
    ageTimer = setTimeout(flushAgeLookups, 300);
  }

  async function flushAgeLookups() {
    const domains = [...agePending];
    agePending = new Set();
    if (!domains.length) return;
    let answers = {};
    try {
      answers = (await chrome.runtime.sendMessage({ type: 'domainAges', domains })) || {};
    } catch {
      return; // extension reloaded or background unavailable: just skip the age check
    }
    let changed = false;
    for (const d of domains) {
      const created = answers[d]?.created || null;
      ageInfo.set(d, created);
      if (created && D.daysSince(created) < 365) changed = true;
    }
    if (changed) refresh();
  }

  function refresh() {
    resultCache.clear();
    checkPage();
    scan(document);
  }

  function processLink(a) {
    const href = a.href && typeof a.href === 'string' ? a.href : a.getAttribute('href');
    if (!href) return;
    const text = (a.textContent || '').trim().slice(0, 200);
    const r = analyze(href, text);
    if (r.verdict === 'danger') block(a, r);
    else if (a.getAttribute(ATTR) === 'blocked') unblock(a);
  }

  function block(a, r) {
    blocked.set(a, r);
    if (a.getAttribute(ATTR) === 'blocked') return;
    a.setAttribute(ATTR, 'blocked');
    a.setAttribute('aria-disabled', 'true');
    a.setAttribute('title', 'Blocked by Link Guardian: this link is probably a scam');
    const badge = document.createElement('span');
    badge.setAttribute(BADGE_ATTR, '');
    badge.setAttribute('role', 'button');
    badge.textContent = '⛔ Fake site — blocked';
    badge.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openWarning(blocked.get(a), { kind: 'link', href: a.href, target: a.target });
    });
    a.after(badge);
    a.__linkGuardBadge = badge;
  }

  function unblock(a) {
    blocked.delete(a);
    a.removeAttribute(ATTR);
    a.removeAttribute('aria-disabled');
    a.removeAttribute('title');
    a.__linkGuardBadge?.remove();
  }

  function scan(rootNode) {
    if (rootNode.nodeType !== 1 && rootNode.nodeType !== 9 && rootNode.nodeType !== 11) return;
    if (rootNode.matches?.('a[href], area[href]')) processLink(rootNode);
    rootNode.querySelectorAll?.('a[href], area[href]').forEach(processLink);
  }

  function rescanAll() {
    resultCache.clear();
    scan(document);
  }

  // ---------------------------------------------------------------- blocking clicks
  function findBlockedLink(e) {
    for (const el of e.composedPath()) {
      if (el instanceof Element && el.getAttribute(ATTR) === 'blocked') return el;
    }
    return null;
  }

  function stop(e) {
    e.preventDefault();
    e.stopImmediatePropagation();
  }

  function onActivate(e) {
    const a = findBlockedLink(e);
    if (!a) return;
    stop(e);
    if (e.type === 'click' || e.type === 'auxclick') {
      openWarning(blocked.get(a), { kind: 'link', href: a.href, target: a.target });
    }
  }

  // Capture phase on window so we run before the page's own handlers.
  for (const type of ['click', 'auxclick', 'mousedown', 'mouseup', 'contextmenu', 'dragstart']) {
    window.addEventListener(type, onActivate, true);
  }
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && findBlockedLink(e)) {
      stop(e);
      const a = findBlockedLink(e);
      openWarning(blocked.get(a), { kind: 'link', href: a.href, target: a.target });
    }
  }, true);

  // ---------------------------------------------------------------- warning dialog
  const DIALOG_CSS = `
    :host { all: initial; }
    .backdrop {
      position: fixed; inset: 0; z-index: 2147483647;
      background: rgba(0, 0, 0, 0.75);
      display: flex; align-items: center; justify-content: center;
      padding: 16px; box-sizing: border-box;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    }
    .box {
      background: #fff; color: #111; max-width: 640px; width: 100%;
      max-height: calc(100vh - 32px); overflow: auto;
      border: 8px solid #d40000; border-radius: 16px; padding: 28px;
      box-sizing: border-box; box-shadow: 0 20px 60px rgba(0,0,0,.5);
    }
    h1 { margin: 0 0 12px; font-size: 30px; line-height: 1.2; color: #b00000; }
    p, li, label { font-size: 20px; line-height: 1.5; }
    .label { margin: 18px 0 4px; font-weight: 600; color: #444; font-size: 18px; }
    .domain {
      font: bold 30px/1.4 ui-monospace, "DejaVu Sans Mono", Menlo, Consolas, monospace;
      letter-spacing: 0.08em; word-break: break-all;
      background: #fff1f1; border: 2px solid #d40000; border-radius: 8px; padding: 10px 14px;
    }
    .domain.real { background: #effaf0; border-color: #1a7f37; color: #0b5d22; }
    .domain .odd { background: #d40000; color: #fff; border-radius: 4px; padding: 0 2px; }
    .domain .owner { text-decoration: underline 3px; }
    ul { padding-left: 24px; margin: 8px 0; }
    .safe {
      display: block; width: 100%; margin: 24px 0 8px; padding: 18px;
      font-size: 24px; font-weight: bold; color: #fff; background: #1a7f37;
      border: none; border-radius: 12px; cursor: pointer;
    }
    .safe:focus { outline: 4px solid #0b5d22; outline-offset: 3px; }
    details { margin-top: 20px; border-top: 1px solid #ddd; padding-top: 12px; }
    summary { font-size: 16px; color: #666; cursor: pointer; }
    .risky { margin-top: 12px; }
    .risky label { display: flex; gap: 10px; align-items: flex-start; font-size: 17px; }
    .risky input { width: 24px; height: 24px; flex: none; margin-top: 3px; }
    .anyway {
      margin-top: 12px; padding: 10px 16px; font-size: 16px;
      background: #fff; color: #b00000; border: 2px solid #b00000; border-radius: 8px; cursor: pointer;
    }
    .anyway:disabled { color: #999; border-color: #ccc; cursor: not-allowed; }
  `;

  // Shows the domain with foreign/look-alike characters highlighted in red.
  // With `realDomain`, letters that differ from the real name are highlighted too
  // ("stackoverf[i]ow" vs "stackoverflow").
  function renderDomain(container, displayHost, registrable, realDomain) {
    const regDisplay = D.toUnicodeHost(registrable);
    const ownerStart = displayHost.length - regDisplay.length;
    const fakeName = Array.from(regDisplay.split('.')[0]);
    const realName = realDomain ? Array.from(realDomain.split('.')[0]) : [];
    const differs = new Set();
    if (realName.length === fakeName.length) {
      fakeName.forEach((ch, i) => { if (ch !== realName[i]) differs.add(ownerStart + i); });
    }
    Array.from(displayHost).forEach((ch, i) => {
      const span = document.createElement('span');
      span.textContent = ch;
      const classes = [];
      if (/[^\x00-\x7f]/.test(ch)) {
        classes.push('odd');
        span.title = `Not a normal letter: U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
      } else if (differs.has(i)) {
        classes.push('odd');
        span.title = 'This letter is different from the real website';
      } else if (/[01]/.test(ch) && i >= ownerStart) {
        classes.push('odd');
        span.title = ch === '0' ? 'This is the number zero, not the letter O' : 'This is the number one, not the letter L';
      }
      if (i >= ownerStart) classes.push('owner');
      span.className = classes.join(' ');
      container.appendChild(span);
    });
  }

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text != null) node.textContent = text;
    return node;
  }

  /**
   * @param r       analysis result
   * @param action  { kind: 'link', href, target } | { kind: 'password', field }
   */
  function openWarning(r, action) {
    if (!r || dialogOpen) return;
    dialogOpen = true;
    const previousFocus = document.activeElement;

    const host = el('div');
    host.style.cssText = 'all: initial !important;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = el('style');
    style.textContent = DIALOG_CSS;
    shadow.appendChild(style);

    const backdrop = el('div', { class: 'backdrop' });
    const box = el('div', { class: 'box', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'lg-title' });
    backdrop.appendChild(box);
    shadow.appendChild(backdrop);

    const isPassword = action.kind === 'password';
    box.appendChild(el('h1', { id: 'lg-title' }, isPassword
      ? '⛔ STOP — do not type your password here'
      : '⛔ STOP — this link is probably a scam'));

    if (r.impersonates) {
      box.appendChild(el('p', {}, `It is pretending to be ${r.impersonates}, but it is NOT ${r.impersonates}.`));
    } else if (r.ageDays != null && r.reasons.length === 1) {
      box.appendChild(el('p', {}, `This website is brand new (${D.describeAge(r.ageDays)}). Most scams use websites like this.`));
    } else {
      box.appendChild(el('p', {}, 'This website is trying to trick you.'));
    }

    box.appendChild(el('div', { class: 'label' }, isPassword ? 'You are really on:' : 'This link really goes to:'));
    const fake = el('div', { class: 'domain' });
    renderDomain(fake, r.displayHost, r.registrable, r.realDomains?.[0]);
    box.appendChild(fake);

    if (r.realDomains?.length) {
      box.appendChild(el('div', { class: 'label' }, `The real ${r.impersonates} website is:`));
      box.appendChild(el('div', { class: 'domain real' }, r.realDomains[0]));
    }

    box.appendChild(el('div', { class: 'label' }, 'Why we think so:'));
    const ul = el('ul');
    r.reasons.forEach((reason) => ul.appendChild(el('li', {}, reason)));
    box.appendChild(ul);

    const safeBtn = el('button', { class: 'safe', type: 'button' },
      isPassword ? '← Leave this site (safe)' : '← Go back, do not open it (safe)');
    box.appendChild(safeBtn);

    // The "I really, really want to" path, hidden behind a disclosure.
    const details = el('details');
    details.appendChild(el('summary', {}, 'I know what I am doing…'));
    const risky = el('div', { class: 'risky' });
    const label = el('label');
    const check = el('input', { type: 'checkbox' });
    label.appendChild(check);
    label.appendChild(el('span', {}, isPassword
      ? 'I understand this site may steal my password or my money, and I still want to type here.'
      : 'I understand this site may steal my passwords or my money, and I still want to open it.'));
    risky.appendChild(label);
    const anyway = el('button', { class: 'anyway', type: 'button', disabled: '' },
      isPassword ? 'Unlock the fields anyway' : 'Open the link anyway');
    risky.appendChild(anyway);
    details.appendChild(risky);
    box.appendChild(details);

    let timer = null;
    check.addEventListener('change', () => {
      clearInterval(timer);
      anyway.disabled = true;
      if (!check.checked) {
        anyway.textContent = isPassword ? 'Unlock the fields anyway' : 'Open the link anyway';
        return;
      }
      let left = UNLOCK_SECONDS;
      anyway.textContent = `Please wait ${left}s and think about it…`;
      timer = setInterval(() => {
        left -= 1;
        if (left > 0) {
          anyway.textContent = `Please wait ${left}s and think about it…`;
        } else {
          clearInterval(timer);
          anyway.disabled = false;
          anyway.textContent = isPassword ? 'Unlock the fields anyway' : 'Open the link anyway';
        }
      }, 1000);
    });

    const close = () => {
      clearInterval(timer);
      host.remove();
      document.removeEventListener('keydown', onKey, true);
      dialogOpen = false;
    };

    const goSafe = () => {
      close();
      if (isPassword) {
        if (history.length > 1) history.back();
        else location.replace('about:blank');
      } else {
        previousFocus?.focus?.();
      }
    };

    // Keep keyboard focus inside the dialog; Esc = the safe choice.
    const onKey = (e) => {
      if (e.key === 'Escape') { stop(e); goSafe(); return; }
      if (e.key === 'Tab') {
        const focusables = [safeBtn, details.querySelector('summary'),
          ...(details.open ? [check, anyway] : [])].filter((n) => !n.disabled);
        const idx = focusables.indexOf(shadow.activeElement);
        e.preventDefault();
        e.stopImmediatePropagation();
        const next = (idx + (e.shiftKey ? -1 : 1) + focusables.length) % focusables.length;
        focusables[next].focus();
      }
    };
    document.addEventListener('keydown', onKey, true);

    safeBtn.addEventListener('click', goSafe);
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) goSafe(); });
    anyway.addEventListener('click', () => {
      if (anyway.disabled || !check.checked) return;
      close();
      if (isPassword) {
        passwordsUnlocked = true;
        action.field?.focus();
      } else if (action.target === '_blank') {
        window.open(action.href, '_blank', 'noopener,noreferrer');
      } else {
        window.location.assign(action.href);
      }
    });

    document.documentElement.appendChild(host);
    safeBtn.focus();
  }

  // ---------------------------------------------------------------- dangerous page
  function showPageBanner(r) {
    if (pageBannerShown) return;
    pageBannerShown = true;
    const host = el('div');
    host.style.cssText = 'all: initial !important;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = el('style');
    style.textContent = `
      .bar {
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483646;
        background: #d40000; color: #fff; padding: 14px 16px;
        font: 20px/1.4 system-ui, sans-serif; display: flex; flex-wrap: wrap;
        gap: 12px; align-items: center; box-shadow: 0 4px 16px rgba(0,0,0,.4);
      }
      .msg { flex: 1 1 320px; }
      b { font-size: 22px; }
      button { font: bold 18px system-ui, sans-serif; padding: 10px 16px; border-radius: 8px; cursor: pointer; border: none; }
      .leave { background: #fff; color: #b00000; }
      .why { background: transparent; color: #fff; border: 2px solid #fff; }
    `;
    shadow.appendChild(style);
    const bar = el('div', { class: 'bar', role: 'alert' });
    const msg = el('div', { class: 'msg' });
    msg.appendChild(el('b', {}, r.impersonates
      ? `⛔ Warning: this website is NOT ${r.impersonates}. `
      : r.ageDays != null && r.reasons.length === 1
        ? `⛔ Careful: this website was created ${D.describeAge(r.ageDays)}. `
        : '⛔ Warning: this website looks like a scam. '));
    msg.appendChild(document.createTextNode('Do not type passwords, codes or card numbers here.'));
    const why = el('button', { class: 'why', type: 'button' }, 'Why?');
    const leave = el('button', { class: 'leave', type: 'button' }, 'Leave this site');
    why.addEventListener('click', () => openWarning(r, { kind: 'password' }));
    leave.addEventListener('click', () => {
      if (history.length > 1) history.back();
      else location.replace('about:blank');
    });
    bar.append(msg, why, leave);
    shadow.appendChild(bar);
    document.documentElement.appendChild(host);
  }

  const SENSITIVE = 'input[type="password"], input[autocomplete^="cc-"], input[autocomplete="one-time-code"], ' +
    'input[name*="card" i], input[name*="cvv" i], input[name*="iban" i], input[name*="pin" i]';

  function guardSensitiveFields(r) {
    window.addEventListener('focusin', (e) => {
      if (passwordsUnlocked) return;
      const field = e.composedPath().find((n) => n instanceof Element && n.matches(SENSITIVE));
      if (!field) return;
      field.blur();
      openWarning(r, { kind: 'password', field });
    }, true);
    // Also stop typing if the field already had focus before we loaded.
    window.addEventListener('keydown', (e) => {
      if (passwordsUnlocked || dialogOpen) return;
      const field = e.composedPath().find((n) => n instanceof Element && n.matches(SENSITIVE));
      if (field) { stop(e); field.blur(); openWarning(r, { kind: 'password', field }); }
    }, true);
  }

  // ---------------------------------------------------------------- start
  async function loadSettings() {
    try {
      const data = await chrome.storage.sync.get({ trusted: [], ageCheck: true, ageDays: 30 });
      trusted = Array.isArray(data.trusted) ? data.trusted : [];
      ageCheck = data.ageCheck !== false;
      ageDays = Number(data.ageDays) > 0 ? Number(data.ageDays) : 30;
    } catch {
      trusted = [];
    }
  }

  // Checks the page we're on (top frame only). Called again when ages arrive.
  function checkPage() {
    if (window.top !== window || pageBannerShown) return;
    pageResult = analyze(location.href, '');
    if (pageResult.verdict === 'danger') {
      showPageBanner(pageResult);
      guardSensitiveFields(pageResult);
    }
  }

  async function start() {
    await loadSettings();
    injectPageStyle();
    checkPage();
    scan(document);

    new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.type === 'attributes') {
          if (m.target.matches?.('a[href], area[href]')) processLink(m.target);
        } else {
          m.addedNodes.forEach(scan);
        }
      }
    }).observe(document.documentElement, {
      childList: true, subtree: true, attributes: true, attributeFilter: ['href'],
    });

    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'sync') return;
      if (changes.trusted) trusted = changes.trusted.newValue || [];
      if (changes.ageCheck) ageCheck = changes.ageCheck.newValue !== false;
      if (changes.ageDays) ageDays = Number(changes.ageDays.newValue) || 30;
      if (changes.trusted || changes.ageCheck || changes.ageDays) rescanAll();
    });
  }

  start();
})();
