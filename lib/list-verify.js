/*
 * Grilled Phish - verification of downloaded well-known-sites lists.
 * Runs in the background worker and in Node (tests, CI). No dependencies:
 * uses WebCrypto (ECDSA P-256 + SHA-256), available in all modern browsers and Node 18+.
 *
 * A signed list is the plain list followed by one last line:
 *     #sig:<base64 signature over every byte before that line>
 * Signature = IEEE P1363 (raw r||s), as produced by tools/sign-list.js.
 */
(function (root) {
  'use strict';

  const SIG_PREFIX = '#sig:';
  const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;
  const LIST_MIN = 1000;
  const LIST_MAX = 300000;
  // Sites that will be in any honest top-100k list. A list without them is broken or tampered.
  const MUST_HAVE = ['google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
    'microsoft.com', 'apple.com', 'paypal.com', 'netflix.com', 'linkedin.com'];

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // -> { body, sig } or null. `body` is exactly the signed text.
  function splitSigned(text) {
    const i = text.lastIndexOf('\n' + SIG_PREFIX);
    if (i < 0) return null;
    const sig = text.slice(i + 1 + SIG_PREFIX.length).trim();
    if (!/^[A-Za-z0-9+/]{40,200}={0,2}$/.test(sig)) return null;
    return { body: text.slice(0, i + 1), sig };
  }

  // true only if signed by one of `publicKeys` (base64 SPKI, P-256).
  async function verifySignedList(text, publicKeys) {
    const parts = typeof text === 'string' ? splitSigned(text) : null;
    if (!parts) return false;
    const data = new TextEncoder().encode(parts.body);
    const sig = b64ToBytes(parts.sig);
    for (const k of publicKeys || []) {
      try {
        const key = await crypto.subtle.importKey('spki', b64ToBytes(k),
          { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        if (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data)) return true;
      } catch { /* malformed key or signature: try the next key */ }
    }
    return false;
  }

  // -> { domains, serial, source }. Throws on malformed content.
  function parseList(text) {
    const lines = String(text).split(/\r?\n/);
    const header = lines.filter((l) => l.startsWith('#'));
    const domains = lines.map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#'));
    if (domains.length < LIST_MIN || domains.length > LIST_MAX) throw new Error(`list has ${domains.length} entries`);
    const bad = domains.find((d) => !DOMAIN_RE.test(d));
    if (bad) throw new Error(`invalid entry "${bad.slice(0, 60)}"`);
    if (new Set(domains).size !== domains.length) throw new Error('duplicate entries');
    const serialLine = header.find((h) => /^#\s*Serial:/i.test(h));
    const serial = serialLine ? Number(serialLine.replace(/^#\s*Serial:\s*/i, '')) : 0;
    const source = (header.find((h) => /^#\s*Source:/i.test(h)) || '').replace(/^#\s*Source:\s*/i, '');
    return { domains, serial: Number.isFinite(serial) ? serial : 0, source };
  }

  // Rules a NEW list must pass even when correctly signed, compared with the list in use.
  // -> { ok: true } | { ok: false, reason }
  function checkListSanity(next, current, { maxChurn = 0.4 } = {}) {
    const have = new Set(next.domains);
    const missing = MUST_HAVE.filter((d) => !have.has(d));
    if (missing.length) return { ok: false, reason: `missing essential sites: ${missing.join(', ')}` };
    if (current) {
      if (!(next.serial > current.serial)) {
        return { ok: false, reason: `not newer than the list in use (serial ${next.serial} <= ${current.serial})` };
      }
      const removed = current.domains.filter((d) => !have.has(d)).length;
      const churn = removed / current.domains.length;
      if (churn > maxChurn) {
        return { ok: false, reason: `${Math.round(churn * 100)}% of sites removed at once (limit ${Math.round(maxChurn * 100)}%)` };
      }
    }
    return { ok: true };
  }

  const api = { SIG_PREFIX, MUST_HAVE, splitSigned, verifySignedList, parseList, checkListSanity };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.GrilledPhishList = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
