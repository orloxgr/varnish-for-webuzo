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
    }
    if (!snapshot.sites.length) { const row = node('tr'), cell = node('td', 'No hosting domains found.'); cell.colSpan = 5; row.append(cell); body.append(row); }
  }
  byId('install').addEventListener('click', () => call('install'));
  byId('start').addEventListener('click', () => call('start'));
  byId('remove').addEventListener('click', () => {
    if (window.confirm('Disable Varnish for all sites and remove its service setup? Sites will return to their normal Webuzo routing.')) call('remove');
  });
  byId('refresh').addEventListener('click', () => call(snapshot && snapshot.installed ? 'reconcile' : 'status'));
  call('status');
})();
