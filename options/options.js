(() => {
  const D = globalThis.GrilledPhishDetector;
  const T = globalThis.GP_T;
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
      remove.textContent = T('optRemove');
      remove.addEventListener('click', async () => {
        await save((await get()).filter((d) => d !== domain));
        say(T('optRemoved', D.toUnicodeHost(domain)));
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
      say(T('optBadAddr'), true);
      return;
    }
    // Refuse to trust something that itself looks like a fake.
    const check = D.analyzeUrl('https://' + domain + '/', { trusted: [] });
    if (check.verdict === 'danger') {
      say(T('optCareful', check.displayHost, check.reasons[0]), true);
      return;
    }
    await save([...(await get()), domain]);
    input.value = '';
    say(T('optAdded', D.toUnicodeHost(domain)));
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
  const autoUpdate = document.getElementById('autoUpdate');
  const serialDate = (n) => {
    const t = String(n || '');
    return t.length >= 8 ? `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}` : T('optUnknownDate');
  };
  function showListStatus(st) {
    if (!st) { listStatus.textContent = T('optListUnavailable'); return; }
    const from = st.from === 'downloaded' ? T('optFromDownloaded') : T('optFromBuiltIn');
    let text = T('optListStatus', (st.count || 0).toLocaleString(), serialDate(st.serial), from);
    if (st.checkedAt) text += ' ' + T('optLastChecked', new Date(st.checkedAt).toLocaleString());
    if (st.error) text += ' ' + T('optCouldNot', st.error);
    listStatus.textContent = text;
    listStatus.className = st.error ? 'hint err' : 'hint';
    autoUpdate.checked = st.autoUpdate !== false;
  }
  chrome.runtime.sendMessage({ type: 'knownSitesStatus' }).then(showListStatus).catch(() => showListStatus(null));
  autoUpdate.addEventListener('change', () => chrome.storage.sync.set({ autoUpdateList: autoUpdate.checked }));
  document.getElementById('checkNow').addEventListener('click', async () => {
    listStatus.textContent = T('popChecking');
    showListStatus(await chrome.runtime.sendMessage({ type: 'knownSitesUpdate' }));
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync' && changes.trusted) render();
  });
  render();
})();
