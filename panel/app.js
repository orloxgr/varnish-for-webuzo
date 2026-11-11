(() => {
  'use strict';
  const root = document.getElementById('wvw'), byId = id => document.getElementById('wvw-' + id);
  document.title = 'Varnish Cache';
  let busy = false, snapshot, editingProfile = 'basic', defaultBrowserEditor;
  const node = (tag, text) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; return el; };
  function controls() { root.querySelectorAll('button,input,textarea,select').forEach(el => { el.disabled = busy || el.dataset.unavailable === '1'; }); }
  function options(select, value) {
    select.replaceChildren();
    for (const profile of snapshot.profiles) { const option = node('option', profile.label); option.value = profile.name; select.append(option); }
    select.value = value;
  }
  function profileEditor() {
    const profile = snapshot.profiles.find(p => p.name === editingProfile);
    byId('profile-description').textContent = profile.description;
    byId('profile-source').textContent = profile.source;
    byId('profile-recv').value = profile.recv_vcl;
    byId('profile-backend').value = profile.backend_vcl;
    const count = snapshot.sites.filter(s => s.enabled && s.profile === editingProfile).length;
    byId('profile-targets').textContent = 'Applying these central rules clears cache for ' + count + ' enabled site(s) using ' + profile.label + '.';
  }
  function browserEditor(parent, value, scope, site = false) {
    const fields = node('div'), inputs = [], inherited = node('input');
    inherited.type = 'checkbox'; inherited.checked = site && value === null;
    inherited.setAttribute('aria-label', 'Use central browser cache settings for ' + scope);
    if (site) { const label = node('label'); label.append(inherited, document.createTextNode(' Use central browser cache settings')); parent.append(label); }
    const selected = value || snapshot.browser_cache;
    const enabled = node('input'); enabled.type = 'checkbox'; enabled.checked = selected.enabled;
    enabled.setAttribute('aria-label', 'Enable browser cache headers for ' + scope);
    const enabledLabel = node('label'); enabledLabel.append(enabled, document.createTextNode(' Enable browser cache headers')); fields.append(enabledLabel); inputs.push(enabled);
    const seconds = (label, initial) => {
      const input = node('input'), caption = node('label', label + ' (seconds)'); input.type = 'number'; input.min = '0'; input.max = '2147483647'; input.step = '1'; input.value = initial;
      input.setAttribute('aria-label', label + ' for ' + scope); caption.append(input); fields.append(caption); inputs.push(input); return input;
    };
    const ordinary = seconds('Ordinary static files', selected.static_seconds), versioned = seconds('Versioned static files', selected.versioned_seconds);
    const paths = node('textarea'); paths.value = selected.versioned_paths.join('\n'); paths.placeholder = '/assets/app-{hash}.js\n/assets/styles-{hash}.css'; paths.setAttribute('aria-label', 'Versioned asset URL patterns for ' + scope);
    const pathsLabel = node('label', 'Versioned asset URL patterns — one per line'); pathsLabel.append(paths); fields.append(pathsLabel); inputs.push(paths);
    fields.append(node('p', 'Declare only files whose URL changes when their content changes. {hash} matches 16–128 hexadecimal characters; * matches within one path segment. Query strings such as ?ver= are not classified automatically. Versioned files receive immutable; zero seconds requires revalidation.'));
    const update = () => { fields.hidden = site && inherited.checked; for (const input of inputs) input.dataset.unavailable = String(!snapshot.installed || (site && inherited.checked) ? 1 : 0); controls(); };
    const automatic = node('p'); automatic.hidden = true;
    inherited.addEventListener('change', update); parent.append(fields, automatic); update();
    return {
      value: () => site && inherited.checked ? null : {enabled: enabled.checked, static_seconds: Number(ordinary.value), versioned_seconds: Number(versioned.value), versioned_paths: paths.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean)},
      profile: name => {
        const patterns = snapshot.browser_cache_profiles[name] || [];
        automatic.textContent = 'Automatic versioned asset patterns from the selected VCL profile: ' + patterns.join(', ') + '. These use the effective versioned lifetime and apply when browser cache headers are enabled. Custom patterns above are preserved. Save & Apply commits a profile change.';
        automatic.hidden = patterns.length === 0;
      }
    };
  }
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
    byId('profiles').hidden = !snapshot.installed;
    byId('browser').hidden = !snapshot.installed;
    byId('browser-fields').replaceChildren();
    defaultBrowserEditor = browserEditor(byId('browser-fields'), snapshot.browser_cache, 'central defaults');
    byId('memory').value = snapshot.memory_mb;
    byId('control-port').value = snapshot.control_port || 82;
    const allowances = snapshot.proxy_timeouts;
    byId('timeouts').textContent = allowances
      ? 'Webuzo proxy allowances: connection ' + allowances.connect / 1000 + 's, read inactivity ' + allowances.read / 1000 + 's, send inactivity ' + allowances.send / 1000 + 's. Refresh sites reapplies changes from the hosting configuration.'
      : 'Refresh sites to apply the hosting configuration\'s request timeouts.';
    byId('usage-result').hidden = true;
    options(byId('default-profile'), snapshot.default_profile);
    options(byId('edit-profile'), editingProfile); profileEditor();
    const body = byId('sites'); body.replaceChildren();
    for (const site of snapshot.sites) {
      const row = node('tr'), name = node('td'); name.append(node('strong', site.domain), node('small', site.owner));
      row.dataset.site = site.id;
      if (site.error) name.append(node('small', site.error));
      row.append(name);
      const profile = node('select'); options(profile, site.profile); profile.setAttribute('aria-label', 'VCL profile for ' + site.domain);
      const profileCell = node('td'); profileCell.append(profile); row.append(profileCell);
      const enabled = node('input'); enabled.type = 'checkbox'; enabled.checked = site.enabled; enabled.setAttribute('aria-label', 'Enable Varnish for ' + site.domain);
      const enabledCell = node('td'); enabledCell.append(enabled); row.append(enabledCell);
      const originTtl = node('input'); originTtl.type = 'checkbox'; originTtl.checked = site.ttl === 0;
      const originLabel = node('label', 'Use origin cache policy'); originLabel.prepend(originTtl);
      const ttl = node('input'); ttl.type = 'number'; ttl.min = '1'; ttl.max = '2147483647'; ttl.value = site.ttl || 300; ttl.setAttribute('aria-label', 'Maximum cache lifetime for ' + site.domain);
      const ttlLimit = node('div'); ttlLimit.append(ttl, node('small', 'Maximum seconds; shorter origin lifetimes still apply.'));
      const ttlHint = node('small', 'Uses the site’s response cache lifetime without an additional panel cap. Private/no-store responses remain excluded.');
      function ttlMode() { ttlLimit.hidden = originTtl.checked; ttlHint.hidden = !originTtl.checked; }
      originTtl.addEventListener('change', ttlMode); ttlMode();
      const ttlCell = node('td'); ttlCell.append(originLabel, ttlHint, ttlLimit); row.append(ttlCell);
      const bypass = node('textarea'); bypass.value = site.bypass.join('\n'); bypass.placeholder = '/private-area/\n/custom-checkout/'; bypass.setAttribute('aria-label', 'Additional bypass paths for ' + site.domain);
      const bypassCell = node('td'); bypassCell.append(bypass, node('small', 'URL prefixes, one per line.')); row.append(bypassCell);
      const cell = node('td'), actions = node('div'); actions.className = 'wvw-actions';
      const save = node('button', 'Save & Apply'); save.type = 'button'; save.className = 'wvw-primary';
      save.addEventListener('click', () => call('configure', {id: site.id, profile: profile.value, enabled: enabled.checked, ttl: originTtl.checked ? 0 : Number(ttl.value), bypass: bypass.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean), recv_vcl: recv.value, backend_vcl: backend.value}));
      const purge = node('button', 'Clear cache'); purge.type = 'button'; purge.dataset.unavailable = String(!snapshot.installed || !site.enabled ? 1 : 0);
      purge.addEventListener('click', () => call('purge', {id: site.id}));
      actions.append(save, purge); cell.append(actions); row.append(cell); body.append(row);
      for (const el of [profile, enabled, originTtl, ttl, bypass, save]) el.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      const detailRow = node('tr'); detailRow.hidden = true; detailRow.dataset.detailsFor = site.id;
      const detailCell = node('td'); detailCell.colSpan = 6;
      const section = node('div'); section.className = 'wvw-site-details'; detailCell.append(section); detailRow.append(detailCell); body.append(detailRow);
      const browserBox = node('details'); browserBox.append(node('summary', 'Browser cache for ' + site.domain));
      const siteBrowserEditor = browserEditor(browserBox, site.browser_cache, site.domain, true);
      const saveBrowser = node('button', 'Save site browser cache'); saveBrowser.type = 'button'; saveBrowser.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      saveBrowser.addEventListener('click', () => call('browser_site', {id: site.id, settings: siteBrowserEditor.value()})); browserBox.append(saveBrowser);
      section.append(browserBox);
      const browserButton = node('button', 'Browser cache'); browserButton.type = 'button'; browserButton.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      browserButton.addEventListener('click', () => { detailRow.hidden = false; browserBox.open = !browserBox.open; edit.setAttribute('aria-expanded', 'true'); }); actions.append(browserButton);
      const edit = node('button', 'VCL & connection'); edit.type = 'button'; edit.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      edit.setAttribute('aria-expanded', 'false'); actions.append(edit);
      const connection = node('button', 'Show connection information'); connection.type = 'button';
      const connectionBox = node('div'); connectionBox.hidden = true;
      connection.addEventListener('click', async () => {
        if (!connectionBox.hidden) { connectionBox.replaceChildren(); connectionBox.hidden = true; connection.textContent = 'Show connection information'; return; }
        const data = await call('connection', {id: site.id});
        if (!data) return;
        const info = data.connection;
        const heading = node('h4', 'HTTP cache connection'), fields = node('div');
        for (const [label, value] of [['Connection type', info.mode], ['HTTP endpoint', info.endpoint], ['Host', info.host], ['Port', info.port || 'Not configured'], ['Site / Host header', info.domain], ['Authentication header', info.header]]) {
          const field = node('input'), caption = node('label', label); field.type = 'text'; field.readOnly = true; field.value = value; field.className = 'wvw-key'; field.setAttribute('aria-label', label + ' for ' + site.domain);
          fields.append(caption, field);
          if (label === 'HTTP endpoint' && value) {
            const copyEndpoint = node('button', 'Copy endpoint'); copyEndpoint.type = 'button';
            copyEndpoint.addEventListener('click', async () => { try { await navigator.clipboard.writeText(field.value); copyEndpoint.textContent = 'Copied'; } catch (_) { field.select(); } }); fields.append(copyEndpoint);
          }
        }
        const keyLabel = node('label', 'Site purge token'), key = node('input'); key.id = 'wvw-key-' + site.id; keyLabel.htmlFor = key.id; key.type = 'password'; key.readOnly = true; key.value = info.key; key.autocomplete = 'off'; key.setAttribute('aria-label', 'Site purge token for ' + site.domain); key.className = 'wvw-key';
        const show = node('button', 'Reveal key'); show.type = 'button';
        show.addEventListener('click', () => { key.type = key.type === 'password' ? 'text' : 'password'; show.textContent = key.type === 'password' ? 'Reveal key' : 'Hide key'; });
        const copy = node('button', 'Copy key'); copy.type = 'button';
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(key.value); copy.textContent = 'Copied'; }
          catch (_) { key.type = 'text'; show.textContent = 'Hide key'; key.select(); }
        });
        const keyActions = node('div'); keyActions.className = 'wvw-actions'; keyActions.append(show, copy);
        const notice = !info.ready ? 'Start Varnish if it is stopped, then set up the local HTTP connection using Save connection port above, or click Refresh sites.' : !info.enabled ? 'Enable Varnish for this site and click Save & Apply before using its connection.' : 'Use these server connection values in your application. Requests must send the Site / Host header and the site purge token in the Authentication header shown below.';
        connectionBox.replaceChildren(heading, node('p', notice), fields, keyLabel, key, keyActions, node('p', 'Available operations: exact URL PURGE, scoped URL/group/HTML/site BAN and soft purge. Prewarm uses normal GET requests to the public site URLs.'), node('p', 'The endpoint is local to this server. This token authorizes cache invalidation only for this site and its aliases. It does not grant Varnish administration access.'));
        connectionBox.hidden = false; connection.textContent = 'Hide connection information';
      });
      edit.addEventListener('click', () => {
        detailRow.hidden = !detailRow.hidden; edit.setAttribute('aria-expanded', String(!detailRow.hidden));
        if (detailRow.hidden) { connectionBox.replaceChildren(); connectionBox.hidden = true; connection.textContent = 'Show connection information'; }
      });
      const description = node('p'), builtIn = node('details'), source = node('pre'); builtIn.append(node('summary', 'View selected profile VCL'), source);
      function selectedProfile() { const selected = snapshot.profiles.find(p => p.name === profile.value); description.textContent = selected.description; source.textContent = selected.source; siteBrowserEditor.profile(profile.value); }
      profile.addEventListener('change', selectedProfile); selectedProfile();
      section.append(description, builtIn, connection, connectionBox);
      const requestLabel = node('label', 'Additional site request VCL (vcl_recv)'), recv = node('textarea'); recv.value = site.recv_vcl; recv.className = 'wvw-vcl'; recv.setAttribute('aria-label', 'Request VCL for ' + site.domain); recv.placeholder = 'if (req.url ~ "^/members/") { return (pass); }';
      const backendLabel = node('label', 'Additional site response VCL (vcl_backend_response)'), backend = node('textarea'); backend.value = site.backend_vcl; backend.className = 'wvw-vcl'; backend.setAttribute('aria-label', 'Response VCL for ' + site.domain); backend.placeholder = 'if (bereq.url ~ "^/news/") { set beresp.ttl = 60s; }';
      recv.id = 'wvw-recv-' + site.id; requestLabel.htmlFor = recv.id; backend.id = 'wvw-backend-' + site.id; backendLabel.htmlFor = backend.id;
      for (const el of [connection, recv, backend]) el.dataset.unavailable = String(!snapshot.installed || !!site.error ? 1 : 0);
      section.append(requestLabel, recv, backendLabel, backend, node('p', 'Save & Apply validates and saves this site\'s profile, settings and additional VCL. Additions support if/else, request return (pass), X-User-* headers, response ttl/grace/keep and regsub/regsuball. Private-response and site-isolation protections remain in effect.'));
    }
    if (!snapshot.sites.length) { const row = node('tr'), cell = node('td', 'No hosting domains found.'); cell.colSpan = 6; row.append(cell); body.append(row); }
  }
  byId('install').addEventListener('click', () => call('install'));
  byId('start').addEventListener('click', () => call('start'));
  byId('remove').addEventListener('click', () => {
    if (window.confirm('Disable Varnish for all sites and remove its service setup? Sites will return to their normal Webuzo routing.')) call('remove');
  });
  byId('refresh').addEventListener('click', () => call(snapshot && snapshot.installed ? 'reconcile' : 'status'));
  byId('save-connection').addEventListener('click', () => call('connection_setup', {port: Number(byId('control-port').value)}));
  byId('edit-profile').addEventListener('change', () => { editingProfile = byId('edit-profile').value; profileEditor(); });
  byId('save-default').addEventListener('click', () => call('defaults', {profile: byId('default-profile').value}));
  byId('save-browser').addEventListener('click', () => call('browser_defaults', {settings: defaultBrowserEditor.value()}));
  byId('restore-browser').addEventListener('click', () => call('browser_restore'));
  byId('save-profile').addEventListener('click', () => call('profile_rules', {profile: editingProfile, recv_vcl: byId('profile-recv').value, backend_vcl: byId('profile-backend').value}));
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
