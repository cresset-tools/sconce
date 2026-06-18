// Confirm-guarded form submits (any form with a data-confirm message).
for (const form of document.querySelectorAll('form[data-confirm]')) {
  form.addEventListener('submit', (e) => {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
}

// Remember which repo tab you're on (across reloads and post-action redirects).
// A package search/filter in the URL still forces the Packages tab.
{
  const KEY = 'sconceRepoTab';
  const tabs = ['rt-overview', 'rt-packages', 'rt-approvals', 'rt-upstreams',
                'rt-deps', 'rt-policy', 'rt-tokens', 'rt-ci'];

  for (const id of tabs) {
    const radio = document.getElementById(id);
    radio?.addEventListener('change', () => {
      if (radio.checked) {
        try { localStorage.setItem(KEY, id); } catch {}
      }
    });
  }

  if (!/[?&](q|state|page)=/.test(location.search)) {
    let saved = null;
    try { saved = localStorage.getItem(KEY); } catch {}
    if (saved && tabs.includes(saved)) {
      const radio = document.getElementById(saved);
      if (radio) radio.checked = true;
    }
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
