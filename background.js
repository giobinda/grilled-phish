/*
 * Grilled Phish - background worker.
 * Looks up when a domain was registered, using RDAP: the official public
 * registration database run by each domain ending's registry (.com ->
 * Verisign, .xyz -> CentralNic...). The IANA bootstrap file says which
 * registry to ask. No third-party middleman sees the query.
 *
 * Also holds the database of well-known websites: data/known-sites.txt, or a
 * newer copy downloaded automatically from the project's GitHub. Downloads are
 * used only if correctly signed (lib/list-verify.js) and newer than the list in use.
 *
 * Message API (from content script / popup):
 *   { type: 'domainAges', domains: ['a.com', ...] }
 *     -> { 'a.com': { created: ISO | null, status: 'ok' | 'unsupported' | 'notfound' | 'error' } }
 *   { type: 'domainInfo', hosts: ['www.a.com', ...] }
 *     -> { 'www.a.com': { known: rank | null, lookalike: { domain, rank, code, strong } | null } }
 *   { type: 'knownSitesStatus' } -> { count, source, serial, from, updatedAt, checkedAt, error, autoUpdate }
 *   { type: 'knownSitesUpdate' } -> same, after checking for a newer list now
 */
'use strict';

// Chrome runs this file as a service worker; Firefox loads detector.js first via manifest.
if (typeof importScripts === 'function' && !globalThis.GrilledPhishDetector) {
  importScripts('lib/detector.js', 'lib/list-verify.js', 'lib/list-public-key.js');
}
const D = globalThis.GrilledPhishDetector;
const L = globalThis.GrilledPhishList;
const LIST_KEYS = globalThis.GRILLED_PHISH_LIST_KEYS;

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const DAY = 86400000;
const BOOTSTRAP_TTL = 7 * DAY;
const OK_TTL = 7 * DAY; // re-check weekly: a dropped domain can be re-registered by a scammer
const FAIL_TTL = 1 * DAY;
const MAX_CACHE = 3000;
const CONCURRENCY = 3;
const TIMEOUT_MS = 8000;

let bootstrapPromise = null;
const inFlight = new Map();
let active = 0;
const waiting = [];

// ---------------------------------------------------------------- storage helpers
async function getLocal(key, fallback) {
  const data = await chrome.storage.local.get({ [key]: fallback });
  return data[key];
}

let cacheWrite = Promise.resolve();
function updateCache(domain, entry) {
  // Serialize writes so parallel lookups don't overwrite each other.
  cacheWrite = cacheWrite.then(async () => {
    const cache = await getLocal('ageCache', {});
    cache[domain] = entry;
    const keys = Object.keys(cache);
    if (keys.length > MAX_CACHE) {
      keys.sort((a, b) => cache[a].checkedAt - cache[b].checkedAt)
        .slice(0, keys.length - MAX_CACHE)
        .forEach((k) => delete cache[k]);
    }
    await chrome.storage.local.set({ ageCache: cache });
  }).catch(() => {});
  return cacheWrite;
}

// ---------------------------------------------------------------- network
async function fetchJson(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      credentials: 'omit',
      headers: { Accept: 'application/rdap+json, application/json' },
    });
    return { status: res.status, body: res.ok ? await res.json() : null };
  } finally {
    clearTimeout(timer);
  }
}

// Map of TLD ("com", "co.uk"...) -> RDAP base URL.
function loadBootstrap() {
  if (!bootstrapPromise) {
    bootstrapPromise = (async () => {
      const stored = await getLocal('rdapBootstrap', null);
      if (stored && Date.now() - stored.fetchedAt < BOOTSTRAP_TTL) return stored.map;
      try {
        const { body } = await fetchJson(BOOTSTRAP_URL);
        const map = {};
        for (const [tlds, urls] of body.services) {
          const base = urls.find((u) => u.startsWith('https://')) || urls[0];
          for (const tld of tlds) map[tld.toLowerCase()] = base.endsWith('/') ? base : base + '/';
        }
        await chrome.storage.local.set({ rdapBootstrap: { fetchedAt: Date.now(), map } });
        return map;
      } catch (e) {
        bootstrapPromise = null; // retry next time
        if (stored) return stored.map; // stale is better than nothing
        throw e;
      }
    })();
  }
  return bootstrapPromise;
}

function rdapBaseFor(domain, map) {
  const labels = domain.split('.');
  // Most specific first: "co.uk" before "uk".
  for (let i = 1; i < labels.length; i++) {
    const tld = labels.slice(i).join('.');
    if (map[tld]) return map[tld];
  }
  return null;
}

function registrationDate(rdap) {
  const events = Array.isArray(rdap?.events) ? rdap.events : [];
  const ev = events.find((e) => e.eventAction === 'registration');
  return ev?.eventDate || null;
}

async function lookup(domain) {
  const map = await loadBootstrap();
  const base = rdapBaseFor(domain, map);
  if (!base) return { created: null, status: 'unsupported' };
  const { status, body } = await fetchJson(`${base}domain/${encodeURIComponent(domain)}`);
  if (status === 404) return { created: null, status: 'notfound' };
  if (!body) return { created: null, status: 'error' };
  const created = registrationDate(body);
  return { created, status: created ? 'ok' : 'unsupported' };
}

// Small concurrency limiter so a page with 50 external links doesn't hammer registries.
function limited(fn) {
  return new Promise((resolve, reject) => {
    const run = async () => {
      active++;
      try { resolve(await fn()); } catch (e) { reject(e); } finally {
        active--;
        waiting.shift()?.();
      }
    };
    if (active < CONCURRENCY) run(); else waiting.push(run);
  });
}

async function domainAge(domain) {
  const cache = await getLocal('ageCache', {});
  const hit = cache[domain];
  if (hit) {
    const ttl = hit.status === 'ok' || hit.status === 'unsupported' ? OK_TTL : FAIL_TTL;
    if (Date.now() - hit.checkedAt < ttl) return { created: hit.created, status: hit.status };
  }
  if (inFlight.has(domain)) return inFlight.get(domain);

  const p = limited(async () => {
    let res;
    try { res = await lookup(domain); } catch { res = { created: null, status: 'error' }; }
    await updateCache(domain, { ...res, checkedAt: Date.now() });
    return res;
  }).finally(() => inFlight.delete(domain));
  inFlight.set(domain, p);
  return p;
}

const DOMAIN_RE = /^(?:[a-z0-9-]+\.)+[a-z0-9-]{2,}$/;

// ---------------------------------------------------------------- well-known sites
// Where signed updates are published (CDN mirror first, GitHub second). Being
// signed, the list is safe to fetch from anywhere: a tampered copy is rejected.
const LIST_URLS = [
  'https://cdn.jsdelivr.net/gh/giobinda/grilled-phish@main/data/known-sites.txt',
  'https://raw.githubusercontent.com/giobinda/grilled-phish/main/data/known-sites.txt',
];
const LIST_CHECK_EVERY = 3 * DAY;
let indexPromise = null;
let updating = null;
let currentList = null; // { domains, serial, source } in use
let listMeta = { count: 0, source: '', serial: 0, from: 'built in', updatedAt: null };

const unsigned = (text) => L.splitSigned(text)?.body ?? text;

async function loadIndex() {
  const bundledText = await (await fetch(chrome.runtime.getURL('data/known-sites.txt'))).text();
  let use = L.parseList(unsigned(bundledText));
  let from = 'built in';
  let updatedAt = null;
  const stored = await getLocal('knownSitesDownload', null);
  // The stored download is re-verified every time: never trust storage blindly.
  if (stored?.text && await L.verifySignedList(stored.text, LIST_KEYS)) {
    try {
      const dl = L.parseList(unsigned(stored.text));
      if (dl.serial > use.serial) { use = dl; from = 'downloaded'; updatedAt = stored.fetchedAt; }
    } catch { /* ignore a broken download */ }
  }
  currentList = use;
  listMeta = { count: use.domains.length, source: use.source, serial: use.serial, from, updatedAt };
  return D.buildKnownIndex(use.domains);
}

function getIndex() {
  if (!indexPromise) {
    indexPromise = loadIndex().catch((e) => { indexPromise = null; listMeta.error = String(e.message || e); return null; });
    maybeUpdateList(false); // fire and forget
  }
  return indexPromise;
}

async function fetchList(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 60000);
  try {
    // 'no-cache' = ask the server whether the file changed (ETag), reuse the copy if not.
    const res = await fetch(url, { signal: ctrl.signal, credentials: 'omit', cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (!res.url.startsWith('https://')) throw new Error('redirected to a non-https address');
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

// Checks for a newer signed list. Returns true if a new list was installed.
function maybeUpdateList(force) {
  if (updating) return updating;
  updating = (async () => {
    const { autoUpdateList = true } = await chrome.storage.sync.get({ autoUpdateList: true });
    if (!autoUpdateList) return false;
    const check = await getLocal('knownSitesCheck', {});
    if (!force && check.checkedAt && Date.now() - check.checkedAt < LIST_CHECK_EVERY) return false;
    await indexPromise; // need the list in use to compare with

    let error = null;
    for (const url of LIST_URLS) {
      try {
        const text = await fetchList(url);
        if (!(await L.verifySignedList(text, LIST_KEYS))) throw new Error('signature check failed, list ignored');
        const next = L.parseList(unsigned(text));
        if (currentList && next.serial <= currentList.serial) { error = null; break; } // already up to date
        const sanity = L.checkListSanity(next, currentList);
        if (!sanity.ok) throw new Error(`list refused: ${sanity.reason}`);
        await chrome.storage.local.set({ knownSitesDownload: { text, url, fetchedAt: Date.now() } });
        await chrome.storage.local.set({ knownSitesCheck: { checkedAt: Date.now(), error: null } });
        indexPromise = null;
        await getIndex();
        return true;
      } catch (e) {
        error = `${new URL(url).hostname}: ${e.message || e}`;
      }
    }
    await chrome.storage.local.set({ knownSitesCheck: { checkedAt: Date.now(), error } });
    return false;
  })().catch(() => false).finally(() => { updating = null; });
  return updating;
}

async function listStatus() {
  await getIndex();
  const check = await getLocal('knownSitesCheck', {});
  const { autoUpdateList = true } = await chrome.storage.sync.get({ autoUpdateList: true });
  return { ...listMeta, checkedAt: check.checkedAt || null, error: check.error || null, autoUpdate: autoUpdateList };
}

// ---------------------------------------------------------------- toolbar badge
// Drawn by the browser itself, so a phishing page can neither fake nor hide it.
const BADGES = {
  danger: { text: '!', color: '#d40000', title: chrome.i18n.getMessage('badgeDanger') },
  trusted: { text: '✓', color: '#1a7f37', title: chrome.i18n.getMessage('badgeTrusted') },
};
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === 'loading') {
    chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
    chrome.action.setTitle({ tabId, title: 'Grilled Phish' }).catch(() => {});
  }
});

const LEARN_URL = chrome.runtime.getURL('learn/learn.html');
let lastLearnOpen = 0;
function openLearn(nextTo) {
  const props = { url: LEARN_URL };
  if (nextTo?.index != null) { props.index = nextTo.index + 1; props.windowId = nextTo.windowId; }
  chrome.tabs.create(props).catch(() => chrome.tabs.create({ url: LEARN_URL }).catch(() => {}));
}

// First install: show the short guide once, so people know what the red boxes mean.
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') openLearn(null);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Settings messages only from our own pages (options/popup), never from content
  // scripts, which run inside web pages.
  const fromExtensionPage = sender.id === chrome.runtime.id &&
    typeof sender.url === 'string' && sender.url.startsWith(chrome.runtime.getURL(''));

  if (msg?.type === 'pageVerdict') {
    const tabId = sender.tab?.id;
    if (tabId == null || sender.frameId !== 0) return false;
    const b = BADGES[msg.verdict] || { text: '', color: '#000000', title: 'Grilled Phish' };
    chrome.action.setBadgeText({ tabId, text: b.text }).catch(() => {});
    chrome.action.setTitle({ tabId, title: b.title }).catch(() => {});
    if (b.text) chrome.action.setBadgeBackgroundColor({ tabId, color: b.color }).catch(() => {});
    return false;
  }
  if (msg?.type === 'openLearn') {
    // From our warning dialog (content script, user click) or our own pages.
    if (sender.id !== chrome.runtime.id) return false;
    const now = Date.now();
    if (now - lastLearnOpen < 2000) return false; // one tab per click, never a flood
    lastLearnOpen = now;
    openLearn(sender.tab);
    return false;
  }
  if (msg?.type === 'domainInfo' && Array.isArray(msg.hosts)) {
    getIndex().then((index) => {
      const out = {};
      for (const h of msg.hosts.slice(0, 500)) {
        const host = String(h).toLowerCase();
        if (DOMAIN_RE.test(host)) out[host] = D.knownSiteInfo(host, index);
      }
      sendResponse(out);
    }).catch(() => sendResponse({}));
    return true;
  }
  if (msg?.type === 'knownSitesStatus' || msg?.type === 'knownSitesUpdate') {
    if (!fromExtensionPage) return false;
    (async () => {
      if (msg.type === 'knownSitesUpdate') await maybeUpdateList(true);
      sendResponse(await listStatus());
    })().catch((e) => sendResponse({ ...listMeta, error: String(e) }));
    return true;
  }
  if (msg?.type !== 'domainAges' || !Array.isArray(msg.domains)) return false;
  const domains = [...new Set(msg.domains)]
    .map((d) => String(d).toLowerCase())
    .filter((d) => DOMAIN_RE.test(d))
    .slice(0, 60);
  Promise.all(domains.map(async (d) => [d, await domainAge(d)]))
    .then((pairs) => sendResponse(Object.fromEntries(pairs)))
    .catch(() => sendResponse({}));
  return true; // async response
});
