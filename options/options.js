(() => {
  const D = globalThis.LinkGuardDetector;
  const list = document.getElementById('list');
  const msg = document.getElementById('msg');
  const input = document.getElementById('site');

  const get = async () => (await chrome.storage.sync.get({ trusted: [] })).trusted;
  const save = (trusted) => chrome.storage.sync.set({ trusted: [...new Set(trusted)].sort() });

  function say(text, isError) {
    msg.textContent = text;
    msg.className = isError ? 'err' : '';
  }

  async function render() {
    const trusted = await get();
    list.replaceChildren();
    document.getElementById('empty').hidden = trusted.length > 0;
    for (const domain of trusted) {
      const li = document.createElement('li');
      const name = document.createElement('span');
      name.textContent = D.toUnicodeHost(domain);
      const remove = document.createElement('button');
      remove.textContent = 'Remove';
      remove.addEventListener('click', async () => {
        await save((await get()).filter((d) => d !== domain));
        say(`Removed ${domain}.`);
      });
      li.append(name, remove);
      list.appendChild(li);
    }
  }

  document.getElementById('add').addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = input.value.trim();
    const domain = D.registrableDomain(raw);
    if (!domain || !domain.includes('.')) {
      say('That does not look like a website address. Try something like "mybank.com".', true);
      return;
    }
    // Refuse to trust something that itself looks like a fake.
    const check = D.analyzeUrl('https://' + domain + '/', { trusted: [] });
    if (check.verdict === 'danger') {
      say(`Careful! "${check.displayHost}" looks like a fake: ${check.reasons[0]}`, true);
      return;
    }
    await save([...(await get()), domain]);
    input.value = '';
    say(`✓ Added ${D.toUnicodeHost(domain)}.`);
  });

  const ageCheck = document.getElementById('ageCheck');
  const ageDays = document.getElementById('ageDays');
  chrome.storage.sync.get({ ageCheck: true, ageDays: 30 }).then((v) => {
    ageCheck.checked = v.ageCheck !== false;
    ageDays.value = String(v.ageDays);
    ageDays.disabled = !ageCheck.checked;
  });
  ageCheck.addEventListener('change', () => {
    ageDays.disabled = !ageCheck.checked;
    chrome.storage.sync.set({ ageCheck: ageCheck.checked });
  });
  ageDays.addEventListener('change', () => chrome.storage.sync.set({ ageDays: Number(ageDays.value) }));

  const listStatus = document.getElementById('listStatus');
  const listUrl = document.getElementById('listUrl');
  function showListStatus(st) {
    if (!st) { listStatus.textContent = 'List unavailable.'; return; }
    const when = st.updatedAt ? `, updated ${new Date(st.updatedAt).toLocaleDateString()}` : '';
    listStatus.textContent = `${(st.count || 0).toLocaleString()} websites — ${st.source || 'unknown source'}${when}.` +
      (st.error ? ` ⚠ ${st.error}` : '');
    listStatus.className = st.error ? 'hint err' : 'hint';
  }
  chrome.runtime.sendMessage({ type: 'knownSitesStatus' }).then((st) => {
    showListStatus(st);
    listUrl.value = st?.url || '';
  }).catch(() => showListStatus(null));
  document.getElementById('listSave').addEventListener('click', async () => {
    const url = listUrl.value.trim();
    if (url && !/^https:\/\//.test(url)) { listStatus.textContent = 'The address must start with https://'; return; }
    await chrome.storage.sync.set({ knownSitesUrl: url });
    listStatus.textContent = url ? 'Downloading…' : 'Switching back to the built-in list…';
    showListStatus(await chrome.runtime.sendMessage({ type: 'knownSitesUpdate' }));
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync' && changes.trusted) render();
  });
  render();
})();
