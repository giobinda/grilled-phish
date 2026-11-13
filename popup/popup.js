(async () => {
  const D = globalThis.GrilledPhishDetector;
  const $ = (id) => document.getElementById(id);

  $('settings').addEventListener('click', () => chrome.runtime.openOptionsPage());

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const { trusted = [], ageCheck = true, ageDays = 30 } =
    await chrome.storage.sync.get({ trusted: [], ageCheck: true, ageDays: 30 });
  let r = tab?.url ? D.analyzeUrl(tab.url, { trusted }) : { verdict: 'ignore' };

  // Is it a well-known website, or a copy of one? (local database, no network)
  let info = { known: null, lookalike: null };
  if (r.verdict === 'unknown' || r.verdict === 'danger') {
    const host = new URL(tab.url).hostname.toLowerCase();
    try {
      info = (await chrome.runtime.sendMessage({ type: 'domainInfo', hosts: [host] }))?.[host] || info;
    } catch { /* background unavailable */ }
  }

  // How old is this website? (asked from the background worker, usually cached)
  const ageDomain = tab?.url && ageCheck && !info.known ? D.ageLookupDomain(tab.url) : null;
  let created = null;
  if (ageDomain && r.verdict !== 'ignore') {
    try {
      const answers = await chrome.runtime.sendMessage({ type: 'domainAges', domains: [ageDomain] });
      created = answers?.[ageDomain]?.created || null;
      if (created) {
        const days = D.daysSince(created);
        const ageEl = $('age');
        ageEl.hidden = false;
        ageEl.textContent = `Website created ${D.describeAge(days)} (${created.slice(0, 10)})`;
        if (days < ageDays) ageEl.classList.add('young');
      }
    } catch { /* background unavailable: skip */ }
  }
  if (r.verdict === 'unknown' || r.verdict === 'danger') {
    r = D.applyKnownSites(r, { ...info, created });
    if (!info.known) r = D.applyDomainAge(r, created, { maxDays: ageDays });
  }
  if (r.known) {
    $('known').hidden = false;
    $('known').textContent = `⭐ Well-known website (#${r.known.toLocaleString()} most visited in the world)`;
  }

  if (r.verdict === 'ignore') {
    $('icon').textContent = 'ℹ️';
    $('headline').textContent = 'Not a website';
    $('domain').textContent = '—';
    return;
  }

  $('domain').textContent = r.displayHost;
  const status = $('status');

  if (r.verdict === 'trusted') {
    status.classList.add('trusted');
    $('icon').textContent = '✅';
    $('headline').textContent = trusted.includes(r.registrable)
      ? 'One of your trusted sites'
      : `This is the real ${r.owner}`;
    if (trusted.includes(r.registrable)) $('untrust').hidden = false;
  } else if (r.verdict === 'danger') {
    status.classList.add('danger');
    $('icon').textContent = '⛔';
    $('headline').textContent = r.impersonates ? `FAKE — this is NOT ${r.impersonates}` : 'This site looks like a scam';
    for (const reason of r.reasons) {
      const li = document.createElement('li');
      li.textContent = reason;
      $('reasons').appendChild(li);
    }
  } else {
    $('icon').textContent = '❔';
    $('headline').textContent = 'A site you have not marked as trusted';
    $('trust').hidden = false;
  }

  // Two steps: scammers on the phone ask victims to "mark the site as safe".
  let armed = false;
  $('trust').addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      $('trustWarn').hidden = false;
      $('trust').textContent = 'Yes, I have used this site for years';
      return;
    }
    const list = new Set(trusted);
    list.add(r.registrable);
    await chrome.storage.sync.set({ trusted: [...list].sort() });
    window.close();
  });
  $('untrust').addEventListener('click', async () => {
    await chrome.storage.sync.set({ trusted: trusted.filter((d) => d !== r.registrable) });
    window.close();
  });
})();
