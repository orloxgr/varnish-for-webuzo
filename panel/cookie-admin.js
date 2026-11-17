(() => {
  'use strict';
  const ACTIONS = {
    automatic: ['Automatic', 'Use the existing cookie policy. At site scope, this explicitly cancels a matching central override.'],
    shared: ['Shared HTML', 'Ignore this cookie when selecting shared HTML. Preserve it in the browser and origin request; origin privacy and login protection still apply.'],
    variant: ['Public variant', 'Use this cookie value to select a separate public cache variant. Cookie values are never displayed in this table.'],
    private: ['Private', 'Requests carrying this cookie use private processing instead of shared public HTML.']
  };
  const element = (tag, text) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; return el; };
  const clone = value => JSON.parse(JSON.stringify(value));
  const nameOf = match => match.value + (match.kind === 'prefix' ? '*' : '');
  function parseName(value) { const prefix = value.endsWith('*'); return {kind: prefix ? 'prefix' : 'exact', value: prefix ? value.slice(0, -1) : value}; }
  function parsePaste(text) {
    const rows = []; let row = [], field = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (char === '"' && (quoted || field === '')) {
        if (quoted && text[i + 1] === '"') { field += '"'; i++; }
        else quoted = !quoted;
      } else if (!quoted && (char === '\t' || char === '\n' || char === '\r')) {
        row.push(field); field = '';
        if (char !== '\t') { if (row.some(value => value.trim())) rows.push(row); row = []; if (char === '\r' && text[i + 1] === '\n') i++; }
      } else field += char;
    }
    if (quoted) throw new Error('The pasted rows contain an unclosed quoted cell.');
    row.push(field); if (row.some(value => value.trim())) rows.push(row);
    return rows;
  }
  function mount(root, request, options = {}) {
    if (!root) return;
    let model, rows = [], drafts = new Map(), selected = new Set(), dirty = false, busy = false, page = 1;
    const message = element('p'); message.setAttribute('role', 'status');
    const error = element('p'); error.setAttribute('role', 'alert'); error.className = 'wvw-policy-error';
    const toolbar = element('div'); toolbar.className = 'wvw-toolbar';
    const scope = element('select'); scope.setAttribute('aria-label', 'Cookie policy scope'); scope.title = 'Choose central rules or a site. Each site keeps its own overrides.';
    const refresh = element('button', 'Refresh cookie policies'); refresh.type = 'button'; refresh.title = 'Read local recognition data and saved rules for this scope. This does not scan traffic or change cache.';
    toolbar.append(scope, refresh);
    const notice = element('p', 'Shared HTML preserves cookies. Login, checkout, application private/no-store responses and private fragments keep their existing protection.');
    const precedence = element('ul');
    const integrationBox = element('fieldset'), integrationLegend = element('legend','UltraCache connection'); integrationBox.append(integrationLegend);
    const syncLabel=element('label'), syncEnabled=element('input'); syncEnabled.type='checkbox'; syncEnabled.setAttribute('aria-label','Sync cookie policies to UltraCache'); syncLabel.append(syncEnabled,document.createTextNode(' Sync cookie policies to UltraCache'));
    syncEnabled.title='Apply this site’s cookie choices to UltraCache as well as Varnish. Disabled until you explicitly connect it.';
    const endpoint=element('input'); endpoint.type='url'; endpoint.setAttribute('aria-label','UltraCache cookie policy endpoint'); endpoint.style.width='100%';
    endpoint.title='The fixed cookie-policy endpoint on this site or one of its hosting aliases. Redirects and other hosts are refused.';
    const testConnection=element('button','Test UltraCache connection'); testConnection.type='button';
    const connectionResult=element('p'); connectionResult.setAttribute('role','status');
    integrationBox.append(syncLabel,element('p','Configure the matching site token in UltraCache’s Varnish settings, then enable this connection. No password or server administration key is used. Disabling a saved connection restores the application’s baseline policy before disconnecting.'),endpoint,testConnection,connectionResult);
    const filters = element('div'); filters.className = 'wvw-toolbar';
    const search = element('input'); search.type = 'search'; search.placeholder = 'Search cookies, descriptions or providers'; search.setAttribute('aria-label', 'Search cookie policies');
    const actionFilter = element('select'); actionFilter.setAttribute('aria-label', 'Filter cookie action');
    actionFilter.append(new Option('All actions', ''));
    for (const [value, [label]] of Object.entries(ACTIONS)) actionFilter.append(new Option(label, value));
    const sourceFilter = element('select'); sourceFilter.setAttribute('aria-label', 'Filter cookie policy source');
    for (const [value, label] of [['','All rows'],['overrides','Explicit overrides in this scope'],['custom','Custom rows'],['reviewed','Reviewed recommendations'],['recognition','Recognition database']]) sourceFilter.append(new Option(label, value));
    const size = element('select'); size.setAttribute('aria-label', 'Cookie policies per page');
    for (const value of ['20','50','100','500','all']) size.append(new Option(value === 'all' ? 'All' : value, value));
    filters.append(search, actionFilter, sourceFilter, element('span', 'Show per page'), size);
    const bulk = element('div'); bulk.className = 'wvw-toolbar';
    const bulkAction = element('select'); bulkAction.setAttribute('aria-label', 'Action for selected cookies');
    for (const [value, [label]] of Object.entries(ACTIONS)) bulkAction.append(new Option(label, value));
    const apply = element('button', 'Set selected action'), reset = element('button', 'Reset selected to inherited proposal');
    apply.type = reset.type = 'button'; apply.title = 'Edit all selected rows in this scope; Save & Apply activates the changes.';
    reset.title = 'Remove explicit choices in this scope. Site rules inherit central choices; central rules return to the recommendation.';
    const count = element('span'); bulk.append(bulkAction, apply, reset, count);
    const scroll = element('div'); scroll.className = 'wvw-scroll';
    const table = element('table'), head = element('thead'), header = element('tr');
    const selectPage = element('input'); selectPage.type = 'checkbox'; selectPage.setAttribute('aria-label', 'Select this page of cookies');
    const first = element('th'); first.append(selectPage); header.append(first);
    for (const title of ['ID','Cookie','Description','Cache action','Source / details']) header.append(element('th', title));
    head.append(header); const body = element('tbody'); table.append(head, body); scroll.append(table);
    const navigation = element('div'); navigation.className = 'wvw-toolbar';
    const previous = element('button', 'Previous'), next = element('button', 'Next'), pageInfo = element('span');
    previous.type = next.type = 'button'; navigation.append(previous, pageInfo, next);
    const add = element('button', 'Add cookie'), download = element('button', 'Download CSV'); add.type = download.type = 'button';
    const paste = element('textarea'); paste.rows = 4; paste.placeholder = 'Cookie\tDescription\tAction\nsite_currency\tCurrency selected by the visitor\tvariant'; paste.setAttribute('aria-label', 'Paste cookie policy rows from Excel');
    const pasteHelp = element('p', 'Paste Cookie, Description, Action columns, or ID, Cookie, Description, Action. Use a trailing * for a prefix. Actions: automatic, shared, variant, private.');
    const append = element('button', 'Append pasted rows'); append.type = 'button'; append.title = 'Add rows to the draft for this scope. Existing rows and saved rules are preserved.';
    const save = element('button', 'Save & Apply cookie policies'); save.type = 'button'; save.className = 'wvw-primary'; save.title = 'Validate and activate this scope through native Varnish. Invalid rules leave the previous working policy active.';
    const bottom = element('div'); bottom.className = 'wvw-toolbar'; bottom.append(add, download, save);
    root.append(toolbar, notice, precedence, message, error, integrationBox, filters, bulk, scroll, navigation, pasteHelp, paste, append, bottom);
    integrationBox.hidden=true;
    function controls(value) { busy = value; root.querySelectorAll('button,input,select,textarea').forEach(el => { el.disabled = value; el.dataset.unavailable = value ? '1' : '0'; }); }
    function effective(row) {
      const draft = drafts.get(row.id);
      if (draft) return {...row, ...draft, name: nameOf(draft.match), override: true, scope: model.scope,rule_id:row.id};
      const fallback = row.inherited;
      return fallback ? {...row, ...fallback, name: nameOf(fallback.match)} : row;
    }
    function filtered() {
      const term = search.value.toLowerCase();
      return rows.map(effective).filter(row => {
        const source = sourceFilter.value;
        if (source === 'overrides' && !drafts.has(row.id)) return false;
        if (source === 'custom' && !row.id.startsWith('custom:')) return false;
        if (source === 'reviewed' && row.confidence !== 'reviewed' && !row.id.startsWith('policy:')) return false;
        if (source === 'recognition' && !row.id.startsWith('ocd:')) return false;
        return (!actionFilter.value || row.action === actionFilter.value) && (!term || [row.id, row.name, row.description, row.provider, row.category].join(' ').toLowerCase().includes(term));
      });
    }
    function pagination() { const all = filtered(), amount = size.value === 'all' ? Math.max(all.length, 1) : Number(size.value); const pages = Math.max(1, Math.ceil(all.length / amount)); page = Math.min(page, pages); return {all, pages, visible: all.slice((page - 1) * amount, page * amount)}; }
    function changed() { dirty = true; message.textContent = 'Unsaved cookie policy changes.'; }
    function edit(row, patch) {
      const old = effective(row);
      drafts.set(row.id, {id:row.id, match:clone(old.match), description:old.description || '', action:old.action || 'automatic', ...patch}); changed();
    }
    function resetRow(id) {
      drafts.delete(id);
      const row = rows.find(value => value.id === id);
      if (row && !row.inherited && id.startsWith('custom:')) rows = rows.filter(value => value.id !== id);
      selected.delete(id); changed();
    }
    function render() {
      if (!model) return;
      const {all, pages, visible} = pagination(); body.replaceChildren();
      for (const row of visible) {
        const tr = element('tr'), checkCell = element('td'), check = element('input'); check.type = 'checkbox'; check.checked = selected.has(row.id); check.setAttribute('aria-label', 'Select cookie ' + row.name);
        check.addEventListener('change', () => { check.checked ? selected.add(row.id) : selected.delete(row.id); renderCount(); }); checkCell.append(check); tr.append(checkCell);
        const id = element('td'); id.append(element('small', row.id)); tr.append(id);
        const cookieCell = element('td'), cookie = element('input'); cookie.type = 'text'; cookie.value = nameOf(row.match); cookie.setAttribute('aria-label', 'Cookie match ' + row.id); cookie.title = 'An exact cookie name, or a literal prefix ending in *. No regular expressions.';
        cookie.addEventListener('input', () => { edit(row, {match:parseName(cookie.value.trim())}); }); cookieCell.append(cookie); tr.append(cookieCell);
        const descriptionCell = element('td'), description = element('textarea'); description.rows = 2; description.value = row.description || ''; description.setAttribute('aria-label', 'Description ' + row.id); description.addEventListener('input', () => edit(row, {description:description.value})); descriptionCell.append(description); tr.append(descriptionCell);
        const actionCell = element('td'), choice = element('select'); choice.setAttribute('aria-label', 'Cache action ' + row.id);
        for (const [value, [label, explanation]] of Object.entries(ACTIONS)) { const option = new Option(label, value); option.title = explanation; choice.append(option); }
        choice.value = row.action || 'automatic'; choice.title = ACTIONS[choice.value][1]; choice.addEventListener('change', () => { edit(row, {action:choice.value}); choice.title = ACTIONS[choice.value][1]; renderCount(); }); actionCell.append(choice);
        actionCell.append(element('small', 'Proposal: ' + (ACTIONS[row.proposal] || [row.proposal || 'Automatic'])[0])); tr.append(actionCell);
        if (row.effective_action && row.effective_action !== row.action) actionCell.append(element('small', 'Effective: ' + (row.effective_action === 'application-contract' ? 'Depends on the application ESI contract' : (ACTIONS[row.effective_action] || [row.effective_action])[0]) + '. ' + row.core_precedence));
        const meta = element('td'); meta.append(element('strong', drafts.has(row.id) ? 'Override in this scope' : row.override ? 'Matched '+row.scope+' rule' : row.confidence === 'reviewed' ? 'Reviewed recommendation' : 'Recognition assessment'));
        const details = element('details'); details.append(element('summary', 'Cookie details'));
        for (const [label, value] of [['Applied rule',row.rule_id],['Provider', row.provider],['Category',row.category],['HTML effect',row.htmlEffect],['Confidence',row.confidence],['Reason',row.reason],['Precedence',row.core_precedence]]) if (value) details.append(element('p', label + ': ' + value));
        if (row.valid_match === false) details.append(element('p', 'This upstream pattern is recognition metadata. Edit it to a literal cookie name or trailing-star prefix before saving an explicit rule.'));
        for (const source of row.sources || []) { const text = typeof source === 'string' ? source : JSON.stringify(source); if (/^https?:\/\//i.test(text)) { const link = element('a', text); link.href = text; link.target = '_blank'; link.rel = 'noopener noreferrer'; details.append(link); } else details.append(element('p', text)); }
        const resetOne = element('button', 'Reset'); resetOne.type = 'button'; resetOne.title = reset.title; resetOne.addEventListener('click', () => { resetRow(row.id); render(); }); details.append(resetOne); meta.append(details); tr.append(meta); body.append(tr);
      }
      pageInfo.textContent = `${all.length} rows · Page ${page}/${pages}`;
      previous.disabled = page === 1; next.disabled = page === pages;
      previous.dataset.unavailable = page === 1 ? '1' : '0'; next.dataset.unavailable = page === pages ? '1' : '0';
      selectPage.checked = visible.length > 0 && visible.every(row => selected.has(row.id)); renderCount();
    }
    function renderCount() { count.textContent = selected.size + ' selected'; const visible = pagination().visible; selectPage.checked = visible.length > 0 && visible.every(row => selected.has(row.id)); }
    async function load(id, saving = false) {
      if (busy) return;
      controls(true); error.textContent = '';
      try {
        const values=saving ? {id, settings:{schemaVersion:1, rules:[...drafts.values()]}} : {id};
        if(saving && model.id) values.integration={enabled:syncEnabled.checked,url:endpoint.value};
        const response = await request(saving ? 'cookie_policies_save' : 'cookie_policies_status', values);
        if (!response || !response.cookie_policies) throw new Error('Cookie policies are unavailable.');
        model = response.cookie_policies; rows = model.rows; drafts = new Map(model.settings.rules.map(rule => [rule.id, clone(rule)])); selected.clear(); dirty = false;
        scope.replaceChildren(); if (model.administrator) scope.append(new Option('Central cookie policies', ''));
        for (const site of model.sites) scope.append(new Option(site.domain + (model.administrator ? ' / ' + site.owner : ''), site.id)); scope.value = model.id || '';
        integrationBox.hidden=!model.id;
        if(model.integration){syncEnabled.checked=model.integration.enabled;endpoint.value=model.integration.url;}
        connectionResult.textContent=model.integration_error || 'Connection status is checked only when requested.';
        precedence.replaceChildren(...(model.precedence_notes || []).map(text=>element('li',text)));
        message.textContent = response.message || (model.enabled ? 'Policies apply to this scope. ' : model.integration?.enabled ? 'Varnish is disabled for this scope; the UltraCache connection is configured. Save & Apply synchronizes its cookie policies. ' : 'Varnish is disabled for this scope; saved choices apply when enabled. ') + (model.scope === 'central' ? 'Sites inherit these choices unless they have matching overrides.' : model.profile === 'ultracache' ? 'Additional personal fragments require the existing UltraCache integration on this site.' : 'Basic uses the shared public/private cookie policy independently of WordPress.');
      } catch (failure) { error.textContent = failure.message; }
      finally { controls(false); render(); if (model && !model.administrator && !model.id) { controls(true); refresh.disabled = false; refresh.dataset.unavailable = '0'; busy = false; message.textContent = 'No sites are available for this Webuzo account.'; } }
    }
    scope.addEventListener('change', () => { if (dirty && !window.confirm('Discard unsaved cookie policy changes for this scope?')) { scope.value = model.id || ''; return; } load(scope.value || null); });
    refresh.addEventListener('click', () => { if (!dirty || window.confirm('Discard unsaved cookie policy changes and reload this scope?')) load(model ? model.id : null); });
    save.addEventListener('click', () => { if (model) load(model.id, true); });
    syncEnabled.addEventListener('change',changed); endpoint.addEventListener('input',changed);
    testConnection.addEventListener('click',async()=>{
      if(busy || !model?.id)return;
      controls(true);error.textContent='';connectionResult.textContent='Checking UltraCache connection…';
      try{
        const response=await request('cookie_integration_status',{id:model.id,integration:{enabled:syncEnabled.checked,url:endpoint.value}});
        if(!response?.cookie_integration)throw new Error('UltraCache connection could not be checked.');
        const data=response.cookie_integration;
        connectionResult.textContent='Authenticated UltraCache connection. Capabilities: '+JSON.stringify(data.capabilities || {});
      }catch(failure){error.textContent=failure.message;connectionResult.textContent='Connection check failed; saved settings are unchanged.';}
      finally{controls(false);render();}
    });
    for (const input of [search, actionFilter, sourceFilter, size]) input.addEventListener(input === search ? 'input' : 'change', () => { page = 1; render(); });
    previous.addEventListener('click', () => { page--; render(); }); next.addEventListener('click', () => { page++; render(); });
    selectPage.addEventListener('change', () => { for (const row of pagination().visible) selectPage.checked ? selected.add(row.id) : selected.delete(row.id); renderCount(); });
    apply.addEventListener('click', () => { for (const row of rows) if (selected.has(row.id)) edit(row, {action:bulkAction.value}); render(); });
    reset.addEventListener('click', () => { for (const id of [...selected]) resetRow(id); render(); });
    function appendRule(name = '', description = '', action = 'automatic', id = null) {
      id = id || 'custom:' + crypto.randomUUID(); const match = parseName(name);
      const rule = {id, match, description, action}; const existing = rows.find(row => row.id === id);
      if (!existing) rows.unshift({...rule, name, proposal:'automatic', scope:model.scope, inherited:null, reason:'Local cookie policy.'});
      drafts.set(id, rule); changed(); return id;
    }
    add.addEventListener('click', () => { if (!model) return; const id = appendRule(); search.value = ''; sourceFilter.value = ''; actionFilter.value = ''; page = 1; render(); body.querySelector('input[type=text]')?.focus(); });
    append.addEventListener('click', () => {
      if (!model) return; error.textContent = '';
      try {
        const values = parsePaste(paste.value); if (values.length && /^(?:id|cookie)$/i.test(values[0][0].trim())) values.shift();
        const parsed = values.map((cells, index) => {
          if (cells.length !== 3 && cells.length !== 4) throw new Error('Pasted row ' + (index + 1) + ' needs three or four columns.');
          const offset = cells.length === 4 ? 1 : 0, name = cells[offset].trim(), action = cells[offset + 2].trim().toLowerCase();
          if (!name || !ACTIONS[action]) throw new Error('Pasted row ' + (index + 1) + ' needs a cookie name and one of the four actions.');
          const id = offset && rows.some(row => row.id === cells[0]) ? cells[0] : null;
          return [name, cells[offset + 1], action, id];
        });
        for (const row of parsed) appendRule(...row); paste.value = ''; search.value = ''; sourceFilter.value = ''; actionFilter.value = ''; page = 1; render();
      } catch (failure) { error.textContent = failure.message; }
    });
    download.addEventListener('click', () => {
      const escape = value => { let text = String(value ?? ''); if (/^[=+@\-\t\r]/.test(text)) text = "'" + text; return '"' + text.replaceAll('"','""') + '"'; };
      const lines = [['ID','Cookie','Description','Cache action','Proposal','Source'], ...filtered().map(row => [row.id,nameOf(row.match),row.description,row.action,row.proposal,row.scope])];
      const url = URL.createObjectURL(new Blob(['\uFEFF' + lines.map(row => row.map(escape).join(',')).join('\r\n')], {type:'text/csv;charset=utf-8'}));
      const anchor = element('a'); anchor.href = url; anchor.download = 'cookie-policies.csv'; anchor.click(); URL.revokeObjectURL(url);
    });
    if (options.lazy) options.lazy.addEventListener('toggle', () => { if (options.lazy.open && !model && !busy) load(null); });
    else load(null);
    return {reload: () => load(model ? model.id : null)};
  }
  window.WebuzoCookiePolicies = {mount};
})();
