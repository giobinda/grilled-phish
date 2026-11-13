/*
 * Grilled Phish - background worker.
 * Looks up when a domain was registered, using RDAP: the official public
 * registration database run by each domain ending's registry (.com ->
 * Verisign, .xyz -> CentralNic...). The IANA bootstrap file says which
 * registry to ask. No third-party middleman sees the query.
 *
 * Also holds the database of well-known websites (data/known-sites.txt, or a
 * newer copy downloaded from the URL set in the options page).
 *
 * Message API (from content script / popup):
 *   { type: 'domainAges', domains: ['a.com', ...] }
 *     -> { 'a.com': { created: ISO | null, status: 'ok' | 'unsupported' | 'notfound' | 'error' } }
 *   { type: 'domainInfo', hosts: ['www.a.com', ...] }
 *     -> { 'www.a.com': { known: rank | null, lookalike: { domain, rank, code, strong } | null } }
 *   { type: 'knownSitesStatus' } -> { count, source, updatedAt, url, error }
 *   { type: 'knownSitesUpdate' } -> same, after trying to download now
 */
'use strict';

// Chrome runs this file as a service worker; Firefox loads detector.js first via manifest.
if (typeof importScripts === 'function' && !globalThis.GrilledPhishDetector) importScripts('lib/detector.js');
const D = globalThis.GrilledPhishDetector;

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
const LIST_UPDATE_EVERY = 7 * DAY;
const LIST_MIN = 1000;
const LIST_MAX = 300000;
let indexPromise = null;
let listMeta = { count: 0, source: '', updatedAt: null, error: null };

function parseList(text) {
  const lines = text.split(/\r?\n/);
  const header = lines.filter((l) => l.startsWith('#'));
  const domains = lines.map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#'));
  if (domains.length < LIST_MIN || domains.length > LIST_MAX) throw new Error(`list has ${domains.length} entries`);
  const bad = domains.find((d) => !DOMAIN_RE.test(d));
  if (bad) throw new Error(`invalid entry "${bad.slice(0, 60)}"`);
  const source = (header.find((h) => /source:/i.test(h)) || '').replace(/^#\s*source:\s*/i, '');
  return { domains, source };
}

async function loadIndex() {
  const stored = await getLocal('knownSitesDownload', null);
  let parsed = null;
  if (stored?.text) {
    try { parsed = parseList(stored.text); listMeta.updatedAt = stored.fetchedAt; } catch { parsed = null; }
  }
  if (!parsed) {
    const text = await (await fetch(chrome.runtime.getURL('data/known-sites.txt'))).text();
    parsed = parseList(text);
    listMeta.updatedAt = null;
  }
  listMeta.count = parsed.domains.length;
  listMeta.source = parsed.source + (stored?.text && listMeta.updatedAt ? ' (downloaded)' : ' (built in)');
  return D.buildKnownIndex(parsed.domains);
}

function getIndex() {
  if (!indexPromise) {
    indexPromise = loadIndex().catch((e) => { indexPromise = null; listMeta.error = String(e.message || e); return null; });
    maybeUpdateList(false); // fire and forget
  }
  return indexPromise;
}

async function maybeUpdateList(force) {
  const { knownSitesUrl = '' } = await chrome.storage.sync.get({ knownSitesUrl: '' });
  if (!/^https:\/\//.test(knownSitesUrl)) return false;
  const stored = await getLocal('knownSitesDownload', null);
  if (!force && stored?.url === knownSitesUrl && Date.now() - stored.fetchedAt < LIST_UPDATE_EVERY) return false;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 60000);
    const res = await fetch(knownSitesUrl, { signal: ctrl.signal, credentials: 'omit', cache: 'no-cache' });
    clearTimeout(t);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (!res.url.startsWith('https://')) throw new Error('redirected to a non-https address');
    const text = await res.text();
    parseList(text); // validate before storing
    await chrome.storage.local.set({ knownSitesDownload: { text, url: knownSitesUrl, fetchedAt: Date.now() } });
    listMeta.error = null;
    indexPromise = null; // rebuild with the new list on next use
    await getIndex();
    return true;
  } catch (e) {
    listMeta.error = `Update failed: ${e.message || e}`;
    return false;
  }
}

// ---------------------------------------------------------------- toolbar badge
// Drawn by the browser itself, so a phishing page can neither fake nor hide it.
const BADGES = {
  danger: { text: '!', color: '#d40000', title: 'Grilled Phish: FAKE or dangerous website' },
  trusted: { text: '✓', color: '#1a7f37', title: 'Grilled Phish: the real website' },
};
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === 'loading') {
    chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
    chrome.action.setTitle({ tabId, title: 'Grilled Phish' }).catch(() => {});
  }
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
      if (msg.type === 'knownSitesUpdate') {
        const { knownSitesUrl = '' } = await chrome.storage.sync.get({ knownSitesUrl: '' });
        if (!knownSitesUrl) await chrome.storage.local.remove('knownSitesDownload'); // back to built-in list
        else await maybeUpdateList(true);
        indexPromise = null;
      }
      await getIndex();
      const { knownSitesUrl = '' } = await chrome.storage.sync.get({ knownSitesUrl: '' });
      sendResponse({ ...listMeta, url: knownSitesUrl });
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
