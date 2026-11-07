(() => {
  'use strict';
  const root = document.getElementById('wvw'), byId = id => document.getElementById('wvw-' + id);
  document.title = 'Varnish Cache';
  let busy = false, snapshot;
  const node = (tag, text) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; return el; };
  function controls() { root.querySelectorAll('button,input,textarea').forEach(el => { el.disabled = busy || el.dataset.unavailable === '1'; }); }
  async function call(action, values = {}) {
    if (busy) return;
    busy = true; controls(); byId('error').hidden = true; byId('notice').hidden = true;
    try {
      const body = new URLSearchParams({token: root.dataset.token, payload: JSON.stringify({action, ...values})});
      const response = await fetch(location.href, {method: 'POST', body, credentials: 'same-origin', headers: {'X-WVW-Request': '1'}});
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || 'The operation failed.');
      if (data.sites) { snapshot = data; render(); }
      if (data.message) { byId('notice').textContent = data.message; byId('notice').hidden = false; }
      return data;
    } catch (error) { byId('error').textContent = error.message; byId('error').hidden = false; }
    finally { busy = false; controls(); }
  }
  function render() {
    byId('status').textContent = !snapshot.installed ? 'Varnish service is not set up.' : snapshot.running ? 'Varnish is running.' : 'Varnish is stopped. Public page requests fall back to Apache.';
    byId('install').hidden = snapshot.installed;
    byId('start').hidden = !snapshot.installed || snapshot.running;
    byId('remove').hidden = !snapshot.installed;
    byId('server').hidden = !snapshot.installed;
    byId('site-settings').hidden = !snapshot.installed;
    byId('memory').value = snapshot.memory_mb;
    byId('usage-result').hidden = true;
    const details = byId('details'); details.replaceChildren();
    const body = byId('sites'); body.replaceChildren();
    for (const site of snapshot.sites) {
      const row = node('tr'), name = node('td'); name.append(node('strong', site.domain), node('small', site.owner));
      if (site.error) name.append(node('small', site.error));
      const enabled = node('input'); enabled.type = 'checkbox'; enabled.checked = site.enabled; enabled.setAttribute('aria-label', 'Enable Varnish for ' + site.domain);
      const enabledCell = node('td'); enabledCell.append(enabled); row.append(name, enabledCell);
      const ttl = node('input'); ttl.type = 'number'; ttl.min = '1'; ttl.max = '2147483647'; ttl.value = site.ttl; ttl.setAttribute('aria-label', 'Maximum cache lifetime for ' + site.domain);
      const ttlCell = node('td'); ttlCell.append(ttl, node('small', 'seconds')); row.append(ttlCell);
      const bypass = node('textarea'); bypass.value = site.bypass.join('\n'); bypass.placeholder = '/private-area/\n/custom-checkout/'; bypass.setAttribute('aria-label', 'Additional bypass paths for ' + site.domain);
      const bypassCell = node('td'); bypassCell.append(bypass, node('small', 'URL prefixes, one per line.')); row.append(bypassCell);
      const cell = node('td'), actions = node('div'); actions.className = 'wvw-actions';
      const save = node('button', 'Save & Apply'); save.type = 'button'; save.className = 'wvw-primary';
      save.addEventListener('click', () => call('configure', {id: site.id, enabled: enabled.checked, ttl: Number(ttl.value), bypass: bypass.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean)}));
      const purge = node('button', 'Clear cache'); purge.type = 'button'; purge.dataset.unavailable = String(!snapshot.installed || !site.enabled ? 1 : 0);
      purge.addEventListener('click', () => call('purge', {id: site.id}));
      actions.append(save, purge); cell.append(actions); row.append(cell); body.append(row);
      for (const el of [enabled, ttl, bypass, save]) el.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      const section = node('details'); section.className = 'wvw-card';
      section.append(node('summary', site.domain));
      const edit = node('button', 'VCL & connection'); edit.type = 'button'; edit.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      edit.addEventListener('click', () => { section.open = true; section.scrollIntoView({behavior: 'smooth', block: 'start'}); }); actions.append(edit);
      const connection = node('button', 'Show connection information & purge key'); connection.type = 'button';
      const connectionBox = node('div'); connectionBox.hidden = true;
      connection.addEventListener('click', async () => {
        if (!connectionBox.hidden) { connectionBox.replaceChildren(); connectionBox.hidden = true; connection.textContent = 'Show connection information & purge key'; return; }
        const data = await call('connection', {id: site.id});
        if (!data) return;
        const info = data.connection;
        const table = node('dl');
        for (const [label, value] of [['Site URL', info.url], ['Aliases', info.names.join(', ')], ['Transport', 'Local Unix socket'], ['Socket', info.socket], ['HTTP method', info.method], ['Authentication header', info.header]]) {
          table.append(node('dt', label), node('dd', value));
        }
        const keyLabel = node('label', 'Site purge key'), key = node('input'); key.id = 'wvw-key-' + site.id; keyLabel.htmlFor = key.id; key.type = 'password'; key.readOnly = true; key.value = info.key; key.autocomplete = 'off'; key.setAttribute('aria-label', 'Site purge key for ' + site.domain); key.className = 'wvw-key';
        const show = node('button', 'Reveal key'); show.type = 'button';
        show.addEventListener('click', () => { key.type = key.type === 'password' ? 'text' : 'password'; show.textContent = key.type === 'password' ? 'Reveal key' : 'Hide key'; });
        const copy = node('button', 'Copy key'); copy.type = 'button';
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(key.value); copy.textContent = 'Copied'; }
          catch (_) { key.type = 'text'; show.textContent = 'Hide key'; key.select(); }
        });
        const keyActions = node('div'); keyActions.className = 'wvw-actions'; keyActions.append(show, copy);
        connectionBox.replaceChildren(table, keyLabel, key, keyActions, node('p', 'This key clears only this site and its aliases. It does not provide panel access. The WordPress connector reads it automatically; install the connector ZIP in WordPress to use its Clear cache button. Remote TCP purges are not enabled.'));
        connectionBox.hidden = false; connection.textContent = 'Hide connection information & purge key';
      });
      section.addEventListener('toggle', () => { if (!section.open) { connectionBox.replaceChildren(); connectionBox.hidden = true; connection.textContent = 'Show connection information & purge key'; } });
      section.append(node('p', 'Use site-local VCL rules to add cache exclusions or adjust public response caching.'), connection, connectionBox);
      const requestLabel = node('label', 'Request VCL (vcl_recv)'), recv = node('textarea'); recv.value = site.recv_vcl; recv.className = 'wvw-vcl'; recv.setAttribute('aria-label', 'Request VCL for ' + site.domain); recv.placeholder = 'if (req.url ~ "^/members/") { return (pass); }';
      const backendLabel = node('label', 'Response VCL (vcl_backend_response)'), backend = node('textarea'); backend.value = site.backend_vcl; backend.className = 'wvw-vcl'; backend.setAttribute('aria-label', 'Response VCL for ' + site.domain); backend.placeholder = 'if (bereq.url ~ "^/news/") { set beresp.ttl = 60s; }';
      recv.id = 'wvw-recv-' + site.id; requestLabel.htmlFor = recv.id; backend.id = 'wvw-backend-' + site.id; backendLabel.htmlFor = backend.id;
      const vclSave = node('button', 'Validate & Apply VCL'); vclSave.type = 'button'; vclSave.className = 'wvw-primary';
      vclSave.addEventListener('click', () => call('vcl', {id: site.id, recv_vcl: recv.value, backend_vcl: backend.value}));
      for (const el of [connection, recv, backend, vclSave]) el.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      section.append(requestLabel, recv, backendLabel, backend, node('p', 'Rules apply only to this site. Supported: if/else, return (pass) in requests, X-User-* headers, response ttl/grace/keep, and regsub/regsuball. Cookie, login, private-response and site isolation protections remain in effect. The site maximum lifetime still applies.'), vclSave);
      details.append(section);
    }
    if (!snapshot.sites.length) { const row = node('tr'), cell = node('td', 'No hosting domains found.'); cell.colSpan = 5; row.append(cell); body.append(row); }
  }
  byId('install').addEventListener('click', () => call('install'));
  byId('start').addEventListener('click', () => call('start'));
  byId('remove').addEventListener('click', () => {
    if (window.confirm('Disable Varnish for all sites and remove its service setup? Sites will return to their normal Webuzo routing.')) call('remove');
  });
  byId('refresh').addEventListener('click', () => call(snapshot && snapshot.installed ? 'reconcile' : 'status'));
  byId('resize').addEventListener('click', () => {
    const memory = Number(byId('memory').value);
    if (!Number.isSafeInteger(memory) || memory < 1) { byId('error').textContent = 'Cache size must be a positive whole number of MiB.'; byId('error').hidden = false; return; }
    if (memory !== snapshot.memory_mb && !window.confirm('Restart Varnish with a ' + memory + ' MiB cache? This clears cached pages for all enabled sites.')) return;
    call('resize', {memory_mb: memory});
  });
  byId('usage').addEventListener('click', async () => {
    const data = await call('usage'); if (!data) return;
    const usage = data.usage, mib = value => (value / 1048576).toLocaleString(undefined, {maximumFractionDigits: 2}) + ' MiB';
    const box = byId('usage-result'); box.replaceChildren();
    box.append(node('p', 'Cache: ' + mib(usage.used_bytes) + ' used · ' + mib(usage.free_bytes) + ' free · ' + usage.budget_mb + ' MiB configured'));
    if (usage.process_bytes !== null) box.append(node('p', 'Total service memory: ' + mib(usage.process_bytes)));
    const counters = [['Hits', usage.hits], ['Misses', usage.misses], ['Passes', usage.passes]].filter(([, value]) => value !== null).map(([label, value]) => label + ': ' + value.toLocaleString());
    if (counters.length) box.append(node('p', counters.join(' · ')));
    box.append(node('small', 'Snapshot taken at ' + new Date().toLocaleTimeString() + '. Counters are for this Varnish service since its last restart.')); box.hidden = false;
  });
  call('status');
})();
