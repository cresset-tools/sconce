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

// Approvals tab: the approval queue — filter chips, package search, per-package
// expand/collapse, and a selection bar that bulk-approves the ticked versions.
{
  const queue = document.getElementById('ap-queue');
  if (queue) {
    const sections = [...queue.querySelectorAll('.apsec')];
    const items = [...queue.querySelectorAll('.apgroup, .apcool, .apheld')];
    const search = document.getElementById('ap-search');
    const filters = document.getElementById('ap-filters');
    let bucket = 'all';

    // Show items matching the active bucket + search; hide now-empty sections.
    const apply = () => {
      const query = (search?.value || '').trim().toLowerCase();
      for (const item of items) {
        const ok = (query === '' || (item.dataset.pkg || '').includes(query));
        item.style.display = ok ? '' : 'none';
      }
      for (const sec of sections) {
        const inBucket = bucket === 'all' || sec.dataset.bucket === bucket;
        const anyVisible = [...sec.querySelectorAll('.apgroup, .apcool, .apheld')]
          .some((el) => el.style.display !== 'none');
        sec.style.display = inBucket && anyVisible ? '' : 'none';
      }
    };

    search?.addEventListener('input', apply);
    if (filters) {
      for (const chip of filters.querySelectorAll('.apchip')) {
        chip.addEventListener('click', () => {
          for (const c of filters.querySelectorAll('.apchip')) c.classList.remove('on');
          chip.classList.add('on');
          bucket = chip.dataset.bucket;
          apply();
        });
      }
    }

    // Expand/collapse a package group (ignore clicks on its inner controls).
    for (const head of queue.querySelectorAll('.apghead')) {
      head.addEventListener('click', (e) => {
        if (e.target.closest('a, .apall, .apgcheck')) return;
        head.parentElement.classList.toggle('open');
      });
    }

    // "Show all N" reveals the rows collapsed past the first few.
    for (const btn of queue.querySelectorAll('.apmore .showall')) {
      btn.addEventListener('click', () => {
        btn.closest('.apgroup').classList.add('showall');
      });
    }

    // Just-synced banner: scroll to the queue, or dismiss for this session.
    const banner = document.getElementById('ap-banner');
    if (banner) {
      const key = 'ap-banner:' + banner.dataset.key;
      if (sessionStorage.getItem(key)) banner.remove();
      document.getElementById('ap-review')?.addEventListener('click', () => {
        queue.querySelector('.apbody')?.scrollIntoView({ behavior: 'smooth' });
      });
      document.getElementById('ap-banner-x')?.addEventListener('click', () => {
        sessionStorage.setItem(key, '1');
        banner.remove();
      });
    }

    // Selection → bulk approve/hold bar.
    const bulk = document.getElementById('ap-bulk');
    const selVals = document.getElementById('ap-selvals');
    const selValsHold = document.getElementById('ap-selvals-hold');
    const selN = document.getElementById('ap-seln');
    const selNBtn = document.getElementById('ap-selnb');
    const selAcross = document.getElementById('ap-across');
    const clear = document.getElementById('ap-clear');
    const boxes = [...queue.querySelectorAll('.apvcheck')];

    const refresh = () => {
      const picked = boxes.filter((b) => b.checked);
      selVals.value = picked.map((b) => b.dataset.val).join('\n');
      if (selValsHold) selValsHold.value = selVals.value;
      selN.textContent = picked.length;
      if (selNBtn) selNBtn.textContent = picked.length;
      if (selAcross) {
        const pkgs = new Set(picked.map((b) => b.dataset.val.split('|')[0]));
        selAcross.textContent =
          pkgs.size > 1 ? `across ${pkgs.size} packages` : '';
      }
      bulk.hidden = picked.length === 0;
      // Reflect each group's row selection in its header checkbox.
      for (const head of queue.querySelectorAll('.apgcheck')) {
        const rows = [...head.closest('.apgroup').querySelectorAll('.apvcheck')];
        const on = rows.filter((b) => b.checked).length;
        head.checked = on > 0 && on === rows.length;
        head.indeterminate = on > 0 && on < rows.length;
      }
    };

    for (const box of boxes) box.addEventListener('change', refresh);
    for (const head of queue.querySelectorAll('.apgcheck')) {
      head.addEventListener('change', () => {
        for (const b of head.closest('.apgroup').querySelectorAll('.apvcheck')) {
          b.checked = head.checked;
        }
        refresh();
      });
    }
    clear?.addEventListener('click', () => {
      for (const b of boxes) b.checked = false;
      refresh();
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
