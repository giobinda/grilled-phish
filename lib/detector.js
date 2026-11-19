/*
 * Grilled Phish - detection engine.
 * Pure logic, no DOM. Runs in the content script, the popup, the options page
 * and in Node (for tests).
 *
 * Main entry point:
 *   analyzeUrl(url, { trusted: ['mybank.com'], linkText: 'www.paypal.com' })
 *     -> { verdict: 'trusted' | 'danger' | 'unknown' | 'ignore',
 *          host, displayHost, registrable, impersonates, realDomains, reasons }
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Brands that phishers copy most often. `domains` are the REAL websites.
  // `typo: false` turns off the "one letter different" check for names that are
  // too close to ordinary words (apple/apply, adobe/abode, steam/stream...).
  // ---------------------------------------------------------------------------
  const BRANDS = [
    { name: 'PayPal', labels: ['paypal'], except: ['paypay'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
    { name: 'Google', labels: ['google', 'gmail', 'youtube'], domains: [
      'google.com', 'gmail.com', 'youtube.com', 'youtu.be', 'googleusercontent.com', 'gstatic.com',
      'googleapis.com', 'google.it', 'google.co.uk', 'google.de', 'google.fr', 'google.es', 'google.ca',
      'google.com.au', 'google.nl', 'google.ch', 'google.at', 'google.be', 'google.pt', 'google.pl',
      'google.ie', 'google.co.in', 'google.com.br', 'google.com.mx', 'google.co.jp', 'goo.gl', 'g.co',
      'googletagservices.com', 'googleadservices.com', 'googlesyndication.com', 'googletagmanager.com',
      'google-analytics.com', 'googlevideo.com', 'ggpht.com', 'withgoogle.com', 'doubleclick.net'] },
    { name: 'Apple', labels: ['apple', 'icloud', 'appleid', 'itunes'], typo: false, except: ['1cloud'], domains: [
      'apple.com', 'icloud.com', 'me.com', 'apple.co', 'itunes.com', 'mzstatic.com', 'applemediaservices.com'] },
    { name: 'Microsoft', labels: ['microsoft', 'outlook', 'hotmail', 'office365', 'onedrive', 'microsoftonline', 'sharepoint'], domains: [
      'microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com', 'office365.com',
      'microsoftonline.com', 'onedrive.com', 'sharepoint.com', 'bing.com', 'msn.com', 'xbox.com',
      'skype.com', 'azure.com', 'windows.com', 'office.net', 'aka.ms', 'sharepointonline.com',
      's-microsoft.com', 'microsoftonline-p.com', 'microsoftonline-p.net', 'microsoftcrmportals.com'] },
    { name: 'Amazon', labels: ['amazon'], domains: [
      'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca',
      'amazon.com.au', 'amazon.co.jp', 'amazon.in', 'amazon.nl', 'amazon.se', 'amazon.pl',
      'amazon.com.br', 'amazon.com.mx', 'amazon.com.be', 'amazon.com.tr', 'amazon.ae', 'amazon.sa',
      'amazon.sg', 'amazon.eg', 'amazonaws.com', 'media-amazon.com', 'ssl-images-amazon.com', 'amzn.to', 'a.co',
      'payments-amazon.com', 'amazonwebservices.com', 'amazonpay.com'] },
    { name: 'Facebook', labels: ['facebook'], domains: ['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com', 'fb.me'] },
    { name: 'Instagram', labels: ['instagram'], domains: ['instagram.com', 'cdninstagram.com'] },
    { name: 'WhatsApp', labels: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
    { name: 'Netflix', labels: ['netflix'], domains: ['netflix.com', 'nflxext.com', 'nflximg.net'] },
    { name: 'eBay', labels: ['ebay'], typo: false, domains: [
      'ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.it', 'ebay.fr', 'ebay.es', 'ebay.ca', 'ebay.com.au', 'ebayimg.com'] },
    { name: 'LinkedIn', labels: ['linkedin'], domains: ['linkedin.com', 'lnkd.in', 'licdn.com'] },
    { name: 'X / Twitter', labels: ['twitter'], except: ['twister'], domains: ['twitter.com', 'x.com', 't.co', 'twimg.com'] },
    { name: 'Bank of America', labels: ['bankofamerica'], domains: ['bankofamerica.com', 'bofa.com'] },
    { name: 'Chase', labels: ['chase'], typo: false, domains: ['chase.com', 'jpmorganchase.com', 'chasepaymentech.com', 'chasepaymentechhostedpay.com', 'chasepaymentechhostedpay-var.com'] },
    { name: 'Wells Fargo', labels: ['wellsfargo'], domains: ['wellsfargo.com'] },
    { name: 'Citibank', labels: ['citibank'], except: ['citicbank'], domains: ['citi.com', 'citibank.com', 'citibankonline.com'] },
    { name: 'Capital One', labels: ['capitalone'], domains: ['capitalone.com'] },
    { name: 'HSBC', labels: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk'] },
    { name: 'Barclays', labels: ['barclays'], domains: ['barclays.co.uk', 'barclays.com'] },
    { name: 'Santander', labels: ['santander'], domains: ['santander.com', 'santander.co.uk', 'santander.it', 'santander.es', 'santander.de', 'santanderbank.com'] },
    { name: 'Revolut', labels: ['revolut'], typo: false, domains: ['revolut.com'] },
    { name: 'Intesa Sanpaolo', labels: ['intesasanpaolo'], domains: ['intesasanpaolo.com'] },
    { name: 'UniCredit', labels: ['unicredit'], domains: ['unicredit.it', 'unicredit.eu', 'unicreditgroup.eu', 'unicreditbank.ru'] },
    { name: 'Poste Italiane', labels: ['posteitaliane', 'poste'], typo: false, domains: ['poste.it', 'posteitaliane.it'] },
    { name: 'DHL', labels: ['dhl'], domains: ['dhl.com', 'dhl.de', 'dhl.it', 'dhl.co.uk', 'dhl.fr', 'dhl.es'] },
    { name: 'FedEx', labels: ['fedex'], typo: false, domains: ['fedex.com'] },
    { name: 'UPS', labels: ['ups'], domains: ['ups.com'] },
    { name: 'USPS', labels: ['usps'], domains: ['usps.com'] },
    { name: 'Royal Mail', labels: ['royalmail'], domains: ['royalmail.com'] },
    { name: 'Coinbase', labels: ['coinbase'], domains: ['coinbase.com'] },
    { name: 'Binance', labels: ['binance'], typo: false, domains: ['binance.com'] },
    { name: 'Steam', labels: ['steampowered', 'steamcommunity'], domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'] },
    { name: 'Dropbox', labels: ['dropbox'], domains: ['dropbox.com', 'dropboxusercontent.com'] },
    { name: 'DocuSign', labels: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Adobe', labels: ['adobe'], typo: false, domains: ['adobe.com', 'adobelogin.com'] },
    { name: 'Spotify', labels: ['spotify'], domains: ['spotify.com', 'scdn.co'] },
    { name: 'Booking.com', labels: ['booking'], typo: false, wordy: true, domains: ['booking.com'] },
    { name: 'Airbnb', labels: ['airbnb'], domains: ['airbnb.com', 'airbnb.it', 'airbnb.co.uk', 'airbnb.de', 'airbnb.fr'] },
    { name: 'Walmart', labels: ['walmart'], domains: ['walmart.com'] },
    { name: 'Venmo', labels: ['venmo'], domains: ['venmo.com'] },
    { name: 'Zelle', labels: ['zellepay'], domains: ['zellepay.com'] },
  ];

  // Two/three-part endings where the owner is one label further left.
  // Includes free hosting platforms: on "paypal-login.netlify.app" the owner is
  // "paypal-login", not Netlify.
  const COUNTRY_SUFFIXES = [
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp',
    'co.in', 'co.za', 'co.kr', 'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg',
    'com.be', 'com.es', 'com.pl', 'com.ua', 'gov.it', 'edu.au',
  ];
  // `wordy: true` = the brand name is also an everyday word ("booking"), so it is
  // only protected against exact look-alikes, not against "word + bait word".
  // Free hosting: anyone can get "<name>.netlify.app" in seconds, so the age of
  // "netlify.app" itself says nothing about the site.
  const HOSTING_SUFFIXES = new Set([
    'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app',
    'firebaseapp.com', 'herokuapp.com', 'azurewebsites.net', 'blogspot.com', 'wixsite.com',
    'weebly.com', 'glitch.me', 'ngrok.io', 'ngrok-free.app', 'r2.dev', 'onrender.com', 'replit.app',
    'repl.co', 'surge.sh', 'framer.app', 'webflow.io', 'carrd.co', 'godaddysites.com',
    'square.site', 'myshopify.com', 'sites.google.com', 'storage.googleapis.com', 's3.amazonaws.com',
    'translate.goog', 'ipfs.dweb.link', 'trycloudflare.com', 'duckdns.org', 'no-ip.org',
    'wordpress.com', '000webhostapp.com', 'appspot.com', 'cloudfront.net', 'amplifyapp.com',
    'azurestaticapps.net', 'fly.dev', 'deno.dev', 'jimdosite.com', 'mystrikingly.com', 'webnode.page',
    'site123.me', 'yolasite.com', 'wcomhost.com', 'codeanyapp.com', 'pythonanywhere.com', 'start.page',
  ]);
  const MULTI_PART_SUFFIXES = new Set([...COUNTRY_SUFFIXES, ...HOSTING_SUFFIXES]);
  // "google.co.id", "google.com.tw", "nhk.or.jp": generic second level under a country ending.
  const GENERIC_SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob', 'mil', 'nic']);

  // Words phishers bolt onto a brand name: "paypal-secure-login.com".
  const BAIT_WORDS = [
    'login', 'logon', 'signin', 'secure', 'security', 'verify', 'verification', 'account', 'accounts',
    'update', 'billing', 'payment', 'confirm', 'unlock', 'recover', 'recovery', 'auth', 'wallet',
    'service', 'services', 'alert', 'suspend', 'suspended', 'refund', 'invoice', 'password', 'reset',
    'validate', 'validation', 'customer', 'official', 'online', 'support', 'help', 'center', 'centre',
    'access', 'id', 'portal', 'web', 'app', 'claim', 'reward', 'gift', 'bonus', 'delivery', 'parcel',
    'tracking', 'track', 'bank', 'banking', 'my', 'team', 'notice', 'locked', 'limited', 'restore',
    // Italian
    'accesso', 'accedi', 'verifica', 'conferma', 'sicurezza', 'sicuro', 'conto', 'pagamento', 'rimborso',
    'spedizione', 'pacco', 'consegna', 'aggiorna', 'aggiornamento', 'sblocca', 'cliente', 'clienti',
    'assistenza', 'area', 'riservata', 'servizi', 'servizio', 'avviso', 'bloccato', 'sospeso', 'premio',
    // Spanish / German / French
    'verificar', 'cuenta', 'seguridad', 'acceso', 'konto', 'sicherheit', 'anmelden', 'bestaetigen',
    'kunden', 'compte', 'securite', 'verifier', 'connexion', 'colis',
  ];

  // Characters from other alphabets that look like Latin letters.
  // (BAIT_SKELETONS is filled in below, once skeleton() exists.)
  let BAIT_SKELETONS;
  const CONFUSABLES = {
    // Cyrillic
    'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l',
    'к': 'k', 'м': 'm', 'н': 'h', 'т': 't', 'ь': 'b', 'п': 'n', 'г': 'r', 'ү': 'y', 'ѵ': 'v',
    'ɡ': 'g', 'ԍ': 'g', 'ѡ': 'w', 'ꙇ': 'i',
    // Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j',
    // Armenian
    'օ': 'o', 'ս': 'u', 'ո': 'n', 'ց': 'g', 'հ': 'h', 'զ': 'q',
    // Latin look-alikes
    'ı': 'i', 'ɩ': 'i', 'ɪ': 'i', 'ɑ': 'a', 'ʟ': 'l', 'ℓ': 'l', 'ɒ': 'a', 'ɔ': 'c', 'ꞁ': 'l',
    'ƅ': 'b', 'ɋ': 'q', 'ʋ': 'u', 'ẏ': 'y', 'ƚ': 'l', 'ɫ': 'l',
  };

  // ---------------------------------------------------------------------------
  // Punycode (RFC 3492) - browsers store "pаypal.com" as "xn--pypal-4ve.com".
  // ---------------------------------------------------------------------------
  function punycodeDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const out = [];
    let n = 128, bias = 72, i = 0;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) out.push(input.charCodeAt(j));
    const adapt = (delta, numPoints, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
    };
    const digitOf = (c) => {
      if (c >= 0x30 && c < 0x3a) return c - 22;
      if (c >= 0x41 && c < 0x5b) return c - 0x41;
      if (c >= 0x61 && c < 0x7b) return c - 0x61;
      return base;
    };
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error('bad punycode');
        const digit = digitOf(input.charCodeAt(idx++));
        if (digit >= base) throw new Error('bad punycode');
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }

  function decodeLabel(label) {
    if (!label.startsWith('xn--')) return label;
    try { return punycodeDecode(label.slice(4)); } catch { return label; }
  }

  const toUnicodeHost = (host) => host.split('.').map(decodeLabel).join('.');

  // ---------------------------------------------------------------------------
  // "Skeleton": what a label looks like to a human eye. Two labels with the
  // same skeleton are visually confusable.
  // ---------------------------------------------------------------------------
  function skeleton(label) {
    let s = label.toLowerCase();
    if (/[^\x00-\x7f]/.test(s)) {
      s = s.normalize('NFKD').replace(/\p{M}/gu, '');
      s = Array.from(s, (ch) => CONFUSABLES[ch] || ch).join('');
    }
    return s
      .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd')
      .replace(/0/g, 'o').replace(/[1i!|]/g, 'l').replace(/-/g, '');
  }

  BAIT_SKELETONS = new Set(BAIT_WORDS.map(skeleton));

  // Damerau-Levenshtein (optimal string alignment) distance.
  function editDistance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[a.length][b.length];
  }

  // ---------------------------------------------------------------------------
  // Domain helpers
  // ---------------------------------------------------------------------------
  function splitHost(host) {
    const labels = host.toLowerCase().replace(/\.$/, '').split('.');
    let suffixLen = 1;
    if (labels.length >= 4 && MULTI_PART_SUFFIXES.has(labels.slice(-3).join('.'))) suffixLen = 3;
    else if (labels.length >= 3 && (MULTI_PART_SUFFIXES.has(labels.slice(-2).join('.')) ||
      (labels.at(-1).length === 2 && GENERIC_SECOND_LEVEL.has(labels.at(-2))))) suffixLen = 2;
    const ownerIdx = Math.max(0, labels.length - suffixLen - 1);
    return {
      labels,
      suffix: labels.slice(-suffixLen).join('.'),
      registrable: labels.slice(ownerIdx).join('.'),
      ownerLabel: labels[ownerIdx],
      subLabels: labels.slice(0, ownerIdx),
    };
  }

  function registrableDomain(hostOrUrl) {
    let host = String(hostOrUrl || '').trim();
    if (!host) return '';
    try {
      host = new URL(host.includes('://') ? host : 'https://' + host).hostname;
    } catch { return ''; }
    return splitHost(host).registrable;
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
  }

  function isPrivateIp(host) {
    if (host.startsWith('[')) return host === '[::1]' || /^\[f[cd]/i.test(host) || /^\[fe80/i.test(host);
    const [a, b] = host.split('.').map(Number);
    return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
  }

  // Build the list of names to protect: built-in brands + user's trusted sites.
  // Cached: pages with thousands of links call analyzeUrl() thousands of times.
  let targetsCache = { key: null, targets: null, official: null };
  function buildTargets(trusted) {
    const key = trusted.join('\n');
    if (targetsCache.key === key) return targetsCache.targets;
    const targets = [];
    for (const b of BRANDS) {
      for (const label of b.labels) {
        targets.push({ name: b.name, label, skel: skeleton(label), domains: b.domains, typo: b.typo !== false, except: b.except || [], wordy: !!b.wordy });
      }
    }
    for (const t of trusted) {
      const { ownerLabel } = splitHost(t);
      if (!ownerLabel || ownerLabel.length < 4) continue;
      targets.push({ name: t, label: ownerLabel, skel: skeleton(ownerLabel), domains: [t], typo: true, except: [], user: true });
    }
    targetsCache = { key, targets, official: new Set(targets.flatMap((t) => t.domains)) };
    return targets;
  }

  const isOfficial = (registrable, domains) => domains.includes(registrable);

  // Domain shown in a link's visible text, e.g. "www.paypal.com/login".
  function domainInText(text) {
    const t = String(text || '').trim();
    const m = t.match(/^(?:https?:\/\/)?((?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,})(?:[/:?#]\S*)?$/iu);
    return m ? m[1].toLowerCase() : null;
  }

  // ---------------------------------------------------------------------------
  // Main analysis
  // ---------------------------------------------------------------------------
  // Translated text from _locales/<lang>/messages.json when running in the
  // browser; the English text given here is used in Node (tests) and must match
  // _locales/en/messages.json (checked by test/i18n.test.js).
  function L(key, subs, en) {
    try {
      const m = root.chrome?.i18n?.getMessage?.(key, (subs || []).map(String));
      if (m) return m;
    } catch { /* not in an extension context */ }
    return (subs || []).reduce((text, s, i) => text.split(`$${i + 1}`).join(String(s)), en);
  }

  function analyzeUrl(url, opts = {}) {
    const trusted = (opts.trusted || []).map((d) => d.toLowerCase());
    let parsed;
    try { parsed = new URL(url); } catch { return { verdict: 'ignore', reasons: [] }; }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return { verdict: 'ignore', reasons: [] };

    const host = parsed.hostname.toLowerCase();
    const result = {
      verdict: 'unknown', host, displayHost: toUnicodeHost(host), registrable: host,
      impersonates: null, realDomains: [], reasons: [], codes: [],
    };
    const flag = (reason, target, code) => {
      result.verdict = 'danger';
      result.reasons.push(reason);
      result.codes.push(code);
      if (target && !result.impersonates) {
        result.impersonates = target.name;
        result.realDomains = target.domains.slice(0, 3);
      }
    };

    if (isIp(host)) {
      if (!isPrivateIp(host)) flag(L('rIp', [], 'The link goes to a bare number address instead of a website name. Real companies do not do this.'), null, 'ip');
      return result;
    }

    const { registrable, ownerLabel, subLabels } = splitHost(host);
    result.registrable = registrable;
    const targets = buildTargets(trusted);
    const allOfficial = targetsCache.official;

    if (trusted.includes(registrable) || allOfficial.has(registrable)) {
      result.verdict = 'trusted';
      const brand = BRANDS.find((b) => b.domains.includes(registrable));
      result.owner = brand ? brand.name : registrable;
      return result;
    }

    const decodedOwner = decodeLabel(ownerLabel);
    const decodedLabels = host.split('.').map(decodeLabel);

    // 1. Letters from several alphabets mixed in one name (Latin + Cyrillic...)
    for (const label of decodedLabels) {
      const scripts = new Set();
      for (const ch of label) {
        if (/\p{Script=Latin}/u.test(ch)) scripts.add(L('scriptLatin', [], 'Latin'));
        else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add(L('scriptCyrillic', [], 'Cyrillic'));
        else if (/\p{Script=Greek}/u.test(ch)) scripts.add(L('scriptGreek', [], 'Greek'));
        else if (/\p{Script=Armenian}/u.test(ch)) scripts.add(L('scriptArmenian', [], 'Armenian'));
      }
      if (scripts.size > 1) {
        flag(L('rScript', [[...scripts].join(' + ')], 'The address mixes letters from different alphabets ($1). This is a classic trick to fake a famous name.'), null, 'script');
        break;
      }
    }

    // 2. Looks identical to a protected name (homoglyphs, rn->m, 1->l, other TLD)
    const ownerSkel = skeleton(decodedOwner);
    const lookAlike = targets.find((t) => t.skel === ownerSkel && !isOfficial(registrable, t.domains) &&
      !t.except.includes(decodedOwner));
    if (lookAlike) {
      if (/[^\x00-\x7f]/.test(decodedOwner)) {
        flag(L('rHomoglyph', [lookAlike.label], 'It uses look-alike letters from another alphabet to imitate "$1".'), lookAlike, 'homoglyph');
      } else if (decodedOwner.replace(/-/g, '') === lookAlike.label) {
        flag(L('rSameLabel', [lookAlike.label, lookAlike.name], 'It uses the name "$1" but it is NOT $2\'s real website.'), lookAlike, 'sameLabel');
      } else {
        flag(L('rSwap', [lookAlike.label], 'It swaps letters to look like "$1" (tricks like "rn" for "m", "1" for "l", "0" for "o").'), lookAlike, 'swap');
      }
    }

    // 3. One letter off (typosquatting): "amazom", "gooogle", "netfilx"
    if (!lookAlike) {
      const plain = ownerSkel;
      const typo = targets.find((t) => t.typo && t.label.length >= 6 && plain !== t.skel && !t.except.includes(decodedOwner) &&
        Math.abs(plain.length - t.skel.length) <= 1 && editDistance(plain, t.skel) === 1);
      if (typo) flag(L('rTypo', [decodedOwner, typo.label], 'The name "$1" is one letter different from "$2".'), typo, 'typo');
    }

    // 4. Brand name hidden in a longer address: paypal.com.verify-now.xyz,
    //    paypal-secure-login.com, amazonrefund.net
    const subTokens = subLabels.map(decodeLabel).flatMap((l) => l.split('-')).map(skeleton);
    const ownerTokens = decodedOwner.split('-').map(skeleton);
    const plainOwner = decodedOwner.replace(/-/g, '');
    for (const t of result.verdict === 'danger' ? [] : targets) {
      if (t.wordy) continue;
      if (subTokens.includes(t.skel)) {
        flag(L('rBrandSub', [t.label, toUnicodeHost(registrable)], '"$1" appears at the start of the address, but the site really belongs to "$2".'), t, 'brandSubdomain');
        break;
      }
      const hasBait = ownerTokens.some((tok) => BAIT_SKELETONS.has(tok));
      const brandToken = ownerTokens.includes(t.skel);
      // Real letters here, not skeletons: "globalcloudteam" must not read as "icloud".
      const glued = t.label.length >= 5 && plainOwner.includes(t.label) &&
        BAIT_WORDS.some((w) => w.length >= 4 && plainOwner.replace(t.label, '').includes(w));
      if ((brandToken && hasBait && ownerTokens.length > 1) || glued) {
        flag(L('rBait', [t.label, t.name], 'It adds words to the name "$1" to look official, but it is not $2\'s website.'), t, 'bait');
        break;
      }
    }

    // 5. The visible text shows a famous site, but the link goes elsewhere.
    const shown = domainInText(opts.linkText);
    if (shown) {
      const shownReg = registrableDomain(shown);
      const shownTarget = targets.find((t) => t.domains.includes(shownReg));
      if (shownTarget && shownReg !== registrable) {
        flag(L('rTextMismatch', [shown, toUnicodeHost(registrable)], 'The text says "$1", but the link secretly goes to "$2".'), shownTarget, 'textMismatch');
      }
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // Domain age (the date itself is fetched by background.js from the registry)
  // ---------------------------------------------------------------------------
  const DAY_MS = 86400000;

  // The domain whose registration date matters, or null when age is meaningless
  // (IP addresses, free hosting subdomains, single-label hosts).
  function ageLookupDomain(url) {
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch { return null; }
    if (!host.includes('.') || isIp(host)) return null;
    const { registrable, suffix } = splitHost(host);
    if (HOSTING_SUFFIXES.has(suffix) || registrable === suffix) return null;
    return registrable;
  }

  function daysSince(createdIso, now = Date.now()) {
    const created = Date.parse(createdIso);
    if (Number.isNaN(created)) return null;
    return Math.max(0, Math.floor((now - created) / DAY_MS));
  }

  function describeAge(days) {
    if (days == null) return null;
    if (days === 0) return L('ageToday', [], 'today');
    if (days === 1) return L('ageYesterday', [], 'yesterday');
    if (days < 60) return L('ageDaysAgo', [days], '$1 days ago');
    if (days < 730) return L('ageMonthsAgo', [Math.floor(days / 30)], '$1 months ago');
    return L('ageYearsAgo', [Math.floor(days / 365)], '$1 years ago');
  }

  // Marks a result as dangerous when the site is younger than `maxDays`.
  // Never touches trusted sites (brands / user's list).
  function applyDomainAge(result, createdIso, { maxDays = 30, now = Date.now() } = {}) {
    if (!result || !createdIso || result.verdict === 'trusted' || result.verdict === 'ignore') return result;
    const days = daysSince(createdIso, now);
    if (days == null || days >= maxDays) return result;
    const when = days <= 1 ? describeAge(days) : L('ageOnlyDaysAgo', [days], 'only $1 days ago');
    return {
      ...result,
      verdict: 'danger',
      ageDays: days,
      codes: [...(result.codes || []), 'age'],
      reasons: [...result.reasons,
        L('rAge', [when], 'This website was created $1. Scam websites are usually brand new and vanish within days; real banks and shops have existed for years.')],
    };
  }

  // ---------------------------------------------------------------------------
  // Database of well-known websites (data/known-sites.txt, built from Tranco).
  // "Known" means POPULAR, not SAFE: it is used to spot copies of these names,
  // never to vouch for a site.
  // ---------------------------------------------------------------------------
  const MIN_DB_LABEL = 5; // shorter names collide by chance too often

  // `domains` must be in popularity order (best first).
  // `base` (optional Set): the list shipped inside the extension. When given,
  // only those domains count as "known" (which skips the look-alike and age
  // checks); domains that only a downloaded update added are still used to
  // spot copies of them, but are checked like any other site. So even a list
  // signed with a stolen key can't make an address skip the checks.
  function buildKnownIndex(domains, { base = null } = {}) {
    const rank = new Map();
    const bySkel = new Map();
    let i = 0;
    const later = [];
    const addSkel = (d) => {
      // The list holds owner-level domains, so the first label is the name.
      const label = decodeLabel(d.split('.')[0]);
      if (label.length < MIN_DB_LABEL) return;
      const k = skeleton(label);
      if (!bySkel.has(k)) bySkel.set(k, d);
    };
    for (const raw of domains) {
      const d = raw.trim().toLowerCase();
      if (!d || d.startsWith('#') || rank.has(d)) continue;
      rank.set(d, ++i);
      // Shipped names claim their look first, so an added copy can't take it over.
      if (base && !base.has(d)) later.push(d); else addSkel(d);
    }
    later.forEach(addSkel);
    return { rank, bySkel, base, size: i, typo: null };
  }

  // ---------------------------------------------------------------------------
  // Typing mistakes ("githhub.com"): addresses one keystroke away from a very
  // popular site. Only used for addresses the person TYPED, as a gentle
  // "did you mean?" question: many honest sites are one letter apart.
  // ---------------------------------------------------------------------------
  const TYPO_TOP = 10000;   // only the most visited sites are worth guarding this way
  const TYPO_MIN_LABEL = 5; // "hulu"/"hula": short names are one letter apart by chance

  // Every way to delete one character (plus the word itself).
  function deletions(word) {
    const out = new Set([word]);
    for (let i = 0; i < word.length; i++) out.add(word.slice(0, i) + word.slice(i + 1));
    return out;
  }

  // Built on first use: ~10,000 sites x ~10 variants.
  function typoIndex(index) {
    if (index.typo) return index.typo;
    const map = new Map();
    for (const [d, r] of index.rank) {
      if (r > TYPO_TOP) continue;
      if (index.base && !index.base.has(d)) continue;
      const dot = d.indexOf('.');
      const label = d.slice(0, dot);
      if (label.length < TYPO_MIN_LABEL || /^xn--/.test(label)) continue;
      const suffix = d.slice(dot + 1);
      for (const v of deletions(label)) {
        const k = v + '|' + suffix;
        if (!map.has(k)) map.set(k, []);
        map.get(k).push(d);
      }
    }
    index.typo = map;
    return map;
  }

  // -> { domain, rank } of the popular site `host` is probably a typo of, or null.
  function typoSuggestion(host, index) {
    if (!index || !host || isIp(host)) return null;
    const { registrable, ownerLabel } = splitHost(host.toLowerCase());
    if (!registrable || index.rank.has(registrable)) return null; // itself well known
    const label = ownerLabel;
    if (label.length < TYPO_MIN_LABEL - 1 || /^xn--/.test(label)) return null;
    const suffix = registrable.slice(label.length + 1);
    const map = typoIndex(index);
    let best = null;
    for (const v of deletions(label)) {
      for (const d of map.get(v + '|' + suffix) || []) {
        const real = d.slice(0, d.indexOf('.'));
        if (real === label || editDistance(real, label) !== 1) continue;
        // Not a typo: only hyphens differ, or only numbers ("site2" vs "site3").
        if (real.replace(/-/g, '') === label.replace(/-/g, '')) continue;
        if (real.replace(/\d/g, '') === label.replace(/\d/g, '')) continue;
        const r = index.rank.get(d);
        if (!best || r < best.rank) best = { domain: d, rank: r };
      }
    }
    return best;
  }

  // -> { known: rank | null, lookalike: { domain, rank, code } | null }
  function knownSiteInfo(host, index) {
    const out = { known: null, lookalike: null };
    if (!index || !host || isIp(host)) return out;
    const { labels, registrable, ownerLabel, subLabels } = splitHost(host.toLowerCase());
    // Try the owner domain and longer forms ("legifrance.gouv.fr" when our simple
    // ending rules stop at "gouv.fr"); never shorter, so "x.github.io" never
    // counts as the well-known "github.io".
    const minLen = registrable.split('.').length;
    for (let n = minLen; n <= labels.length; n++) {
      const d = labels.slice(-n).join('.');
      if (index.rank.has(d) && (!index.base || index.base.has(d))) { out.known = index.rank.get(d); return out; }
    }

    const label = decodeLabel(ownerLabel);
    if (label.length >= MIN_DB_LABEL) {
      const cand = index.bySkel.get(skeleton(label));
      // Same look, different letters. (Same name on another ending is NOT flagged:
      // "delta.com" and "delta.it" are often unrelated.)
      // Hyphens alone don't count: "one-click" and "oneclick" are usually unrelated businesses.
      if (cand && decodeLabel(cand.split('.')[0]).replace(/-/g, '') !== label.replace(/-/g, '')) {
        // Strong: foreign-alphabet letters, or more 0/1 digits than the real name
        // ("0nl1ne" vs "online"). Weak: letter swaps only (i/l, rn/m), which also
        // happen between two honest, unrelated names ("stihl" vs "stihi").
        const candLabel = decodeLabel(cand.split('.')[0]);
        // Only digits hidden inside a word count ("pr0fitel", "g00gle"), not names
        // that simply contain numbers ("1golf", "net10", "11x11").
        const hidden = (x) => (x.match(/(?<=[a-z])[01]+(?=[a-z])/g) || []).join('').length;
        const strong = /[^\x00-\x7f]/.test(label) || hidden(label) > hidden(candLabel);
        out.lookalike = { domain: cand, rank: index.rank.get(cand), code: 'dbLookalike', strong };
        return out;
      }
    }
    // A full well-known address used as a prefix: "mywebsite.com.account-check.xyz"
    for (let i = 0; i < subLabels.length; i++) {
      for (let n = 2; n <= 3 && i + n <= subLabels.length; n++) {
        const d = subLabels.slice(i, i + n).join('.');
        if (index.rank.has(d) && d.split('.')[0].length >= 4) {
          out.lookalike = { domain: d, rank: index.rank.get(d), code: 'dbSubdomain' };
          return out;
        }
      }
    }
    return out;
  }

  // Combines database knowledge with a result from analyzeUrl().
  // info.created (ISO date, optional) decides weak look-alikes: they are only
  // blocked when the site is younger than `weakMaxDays`.
  const WEAK_LOOKALIKE_MAX_DAYS = 365;
  function applyKnownSites(result, info, { now = Date.now(), weakMaxDays = WEAK_LOOKALIKE_MAX_DAYS } = {}) {
    if (!result || !info || result.verdict === 'trusted' || result.verdict === 'ignore') return result;
    const r = { ...result, reasons: [...result.reasons], codes: [...(result.codes || [])] };
    if (info.known) {
      r.known = info.known;
      // A popular site with exactly a brand's name on another ending is almost
      // always the brand's own (google.ru, amazon.co.za). Letter tricks and
      // typos stay flagged even when popular (instragram.com, twiter.com).
      const keep = r.codes.map((c) => c !== 'sameLabel');
      r.reasons = r.reasons.filter((_, i) => keep[i]);
      r.codes = r.codes.filter((_, i) => keep[i]);
      if (!r.reasons.length) { r.verdict = 'unknown'; r.impersonates = null; r.realDomains = []; }
    }
    const la = info.lookalike;
    // A weak look-alike is confirmed when it is young, or not registered at all
    // (a copy of a well-known name that anyone could buy tomorrow).
    const weakConfirmed = la && !la.strong && la.code === 'dbLookalike' &&
      (info.unregistered || (info.created && daysSince(info.created, now) < weakMaxDays));
    if (la && (la.strong || la.code === 'dbSubdomain' || weakConfirmed) && !r.impersonates) {
      const { domain, code } = la;
      r.verdict = 'danger';
      r.impersonates = domain;
      r.realDomains = [domain];
      r.codes.push(code);
      r.reasons.push(code === 'dbSubdomain'
        ? L('rDbSub', [domain, toUnicodeHost(r.registrable)], 'It starts with "$1", a well-known website, but the site really belongs to "$2".')
        : L('rDbLook', [domain], 'It looks almost identical to "$1", a well-known website, but some letters are different.'));
    }
    return r;
  }

  const api = { analyzeUrl, buildKnownIndex, knownSiteInfo, typoSuggestion, applyKnownSites, ageLookupDomain, applyDomainAge, daysSince, describeAge, registrableDomain, toUnicodeHost, skeleton, editDistance, punycodeDecode, BRANDS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.GrilledPhishDetector = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
