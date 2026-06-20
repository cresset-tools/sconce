// Confirm-guarded form submits (any form with a data-confirm message).
for (const form of document.querySelectorAll('form[data-confirm]')) {
  form.addEventListener('submit', (e) => {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
}

// Remember which repo tab you're on via the URL #hash, so it's linkable and
// survives reloads and post-action redirects. Hashes are prefixed `tab-` so they
// don't collide with in-page heading anchors (#tokens, #ci, #health). A package
// search/filter (?q=/?state=/?page=) arrives with no hash and keeps the server's
// Packages pre-selection.
{
  const tabs = ['overview', 'packages', 'approvals', 'upstreams', 'deps',
                'policy', 'tokens', 'ci'];
  const tabFromHash = () => location.hash.replace(/^#tab-/, '');

  // Select the tab named by the current hash. Used on load (deep links and
  // post-action redirects) and on hashchange (back/forward, a hand-edited hash,
  // or a same-document #-nav). Setting `.checked` programmatically doesn't fire
  // `change`, so this never loops with the listener below.
  const applyHash = () => {
    const name = tabFromHash();
    if (!tabs.includes(name)) return;
    const radio = document.getElementById('rt-' + name);
    if (radio) radio.checked = true;
  };
  applyHash();
  window.addEventListener('hashchange', applyHash);

  // Reflect tab changes back into the hash (replaceState → no history spam or
  // scroll jump). Also fires when an in-page label selects a tab.
  for (const name of tabs) {
    const radio = document.getElementById('rt-' + name);
    radio?.addEventListener('change', () => {
      if (radio.checked) history.replaceState(null, '', '#tab-' + name);
    });
  }

  // Carry the active tab through a POST → redirect: the browser keeps the
  // fragment on the form's action URL and reattaches it to the server's
  // fragment-less redirect, so an action returns you to the same tab.
  for (const form of document.querySelectorAll('.tabpanel form')) {
    form.addEventListener('submit', () => {
      const name = tabFromHash();
      if (tabs.includes(name) && !form.action.includes('#')) {
        form.action += '#tab-' + name;
      }
    });
  }
}

// Upstreams add-form: reveal the credential fields only for a private source.
{
  const vis = document.getElementById('upvis');
  if (vis) {
    const credRow = document.getElementById('credrow');
    const addRow = document.getElementById('addrow');
    const sync = () => {
      const isPrivate = vis.value === 'private';
      credRow.style.display = isPrivate ? 'grid' : 'none';
      addRow.style.display = isPrivate ? 'none' : 'grid';
    };
    vis.addEventListener('change', sync);
    sync();
  }
}

// Upstreams add-form: basic auth takes a username + token (two boxes); the other
// credential types take a single token.
{
  const credType = document.getElementById('cred-type');
  const credUser = document.getElementById('cred-user');
  const credToken = document.getElementById('cred-token');
  if (credType && credUser && credToken) {
    const sync = () => {
      const isBasic = credType.value === 'basic';
      credUser.style.display = isBasic ? 'block' : 'none';
      credToken.placeholder = isBasic ? 'password' : 'token';
    };
    credType.addEventListener('change', sync);
    sync();
  }
}

// Upstreams toolbar: live search over the URL text + kind/failing filter chips.
{
  const search = document.getElementById('up-search');
  const chips = document.getElementById('up-chips');
  if (search && chips) {
    const rows = [...document.querySelectorAll('.uptbl .urow')];
    const shown = document.getElementById('up-shown');
    const noMatch = document.getElementById('up-nomatch');
    let filter = 'all';

    const matchesFilter = (row) => {
      if (filter === 'all') return true;
      if (filter === 'failing') return row.dataset.fail === '1';
      return row.dataset.kind === filter;
    };

    const apply = () => {
      const query = search.value.trim().toLowerCase();
      let visible = 0;
      for (const row of rows) {
        const ok = matchesFilter(row) && (query === '' || row.dataset.text.includes(query));
        row.style.display = ok ? 'grid' : 'none';
        if (ok) visible++;
      }
      if (shown) shown.textContent = visible;
      if (noMatch) noMatch.style.display = visible === 0 ? 'block' : 'none';
    };

    search.addEventListener('input', apply);
    for (const chip of chips.querySelectorAll('.chip')) {
      chip.addEventListener('click', () => {
        for (const c of chips.querySelectorAll('.chip')) c.classList.remove('on');
        chip.classList.add('on');
        filter = chip.dataset.filter;
        apply();
      });
    }
  }
}
