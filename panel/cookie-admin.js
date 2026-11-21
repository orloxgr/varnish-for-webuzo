(() => {
  'use strict';
  const ACTIONS = {
    shared: ['Shared HTML', 'Ignore this cookie when selecting shared HTML. Preserve it in the browser and origin request; recognized login/cart protection and this site\'s cache mode still apply.'],
    variant: ['Public variant', 'Use this cookie value to select a separate public cache variant. Cookie values are never displayed in this table.'],
    private: ['Private', 'Requests carrying this cookie use private processing instead of shared public HTML.']
  };
  const PROFILES=['basic','ultracache'], PROFILE_LABEL={basic:'Basic',ultracache:'UltraCache'};
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
    let model, rows = [], drafts = new Map(), selected = new Set(), expanded = new Set(), dirty = false, busy = false, page = 1, draftIndex=null;
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
    syncEnabled.title='Apply this site’s active profile column to UltraCache as well as Varnish. The other column remains independent. Disabled until you explicitly connect it.';
    const endpoint=element('input'); endpoint.type='url'; endpoint.setAttribute('aria-label','UltraCache cookie policy endpoint'); endpoint.style.width='100%';
    endpoint.title='The fixed cookie-policy endpoint on this site or one of its hosting aliases. Redirects and other hosts are refused.';
    const testConnection=element('button','Test UltraCache connection'); testConnection.type='button';
    const connectionResult=element('p'); connectionResult.setAttribute('role','status');
    integrationBox.append(syncLabel,element('p','Configure the matching site token in UltraCache’s Varnish settings, then enable this connection. No password or server administration key is used. Disabling a saved connection restores the application’s baseline policy before disconnecting.'),endpoint,testConnection,connectionResult);
    const filters = element('div'); filters.className = 'wvw-toolbar';
    const search = element('input'); search.type = 'search'; search.placeholder = 'Search cookies, descriptions or providers'; search.setAttribute('aria-label', 'Search cookie policies');
    const actionFilters = {};
    filters.append(search);
    for (const profile of PROFILES) {
      const label = element('label', PROFILE_LABEL[profile] + ' '), select = element('select');
      select.setAttribute('aria-label', 'Filter ' + PROFILE_LABEL[profile] + ' cookie action');
      select.title = 'Match only the ' + PROFILE_LABEL[profile] + ' column. Both profile filters apply when selected.';
      select.append(new Option('All actions', ''));
      for (const [value, [caption]] of Object.entries(ACTIONS)) select.append(new Option(caption, value));
      actionFilters[profile] = select; label.append(select); filters.append(label);
    }
    const sourceFilter = element('select'); sourceFilter.setAttribute('aria-label', 'Filter cookie policy source');
    for (const [value, label] of [['','All rows'],['overrides','Overrides in this scope'],['bundled','Bundled defaults'],['central','Central choices'],['custom','Custom rows'],['proposals','New recognition proposals'],['recognition','Recognition database']]) sourceFilter.append(new Option(label, value));
    const size = element('select'); size.setAttribute('aria-label', 'Cookie policies per page');
    for (const value of ['20','50','100','500','all']) size.append(new Option(value === 'all' ? 'All' : value, value));
    filters.append(sourceFilter, element('span', 'Show per page'), size);
    const bulk = element('div'); bulk.className = 'wvw-toolbar';
    const bulkAction = element('select'); bulkAction.setAttribute('aria-label', 'Action for selected cookies');
    for (const [value, [label]] of Object.entries(ACTIONS)) bulkAction.append(new Option(label, value));
    const apply=element('button','Apply to Basic'),applyUC=element('button','Apply to UltraCache'),reset=element('button','Reset Basic'),resetUC=element('button','Reset UltraCache');
    applyUC.type=resetUC.type='button';applyUC.title='Change only the UltraCache column.';resetUC.title='Remove only UltraCache overrides; Basic remains unchanged.';
    apply.type = reset.type = 'button'; apply.title = 'Edit all selected rows in this scope; Save & Apply activates the changes.';
    reset.title = 'Remove choices in this scope. Sites inherit central rules; central rules return to the bundled defaults.';
    const count = element('span'); bulk.append(bulkAction, apply, applyUC, reset, resetUC, count);
    const scroll = element('div'); scroll.className = 'wvw-scroll';
    const table = element('table'), head = element('thead'), header = element('tr'); table.className = 'wvw-cookie-sheet';
    const selectPage = element('input'); selectPage.type = 'checkbox'; selectPage.setAttribute('aria-label', 'Select this page of cookies');
    const first = element('th'); first.append(selectPage); header.append(first);
    for (const title of ['Cookie','Description','Basic','UltraCache','Source / explanation']) header.append(element('th', title));
    head.append(header); const body = element('tbody'); table.append(head, body); scroll.append(table);
    const navigation = element('div'); navigation.className = 'wvw-toolbar';
    const previous = element('button', 'Previous'), next = element('button', 'Next'), pageInfo = element('span');
    previous.type = next.type = 'button'; navigation.append(previous, pageInfo, next);
    const add = element('button', 'Add cookie'), download = element('button', 'Download CSV'); add.type = download.type = 'button';
    const paste = element('textarea'); paste.rows = 4; paste.placeholder = 'Cookie\tDescription\tBasic\tUltraCache\nsite_currency\tCurrency selected by the visitor\tvariant\tvariant'; paste.setAttribute('aria-label', 'Paste cookie policy rows from Excel');
    const pasteHelp = element('p', 'Paste Cookie, Description, Basic, UltraCache columns. Legacy three-column rows copy their action to both profiles. Use a trailing * for a prefix. Actions: shared, variant, private.');
    const append = element('button', 'Append pasted rows'); append.type = 'button'; append.title = 'Add rows to the draft for this scope. Existing rows and saved rules are preserved.';
    const save = element('button', 'Save & Apply cookie policies'); save.type = 'button'; save.className = 'wvw-primary'; save.title = 'Validate and activate this scope through native Varnish. Invalid rules leave the previous working policy active.';
    const bottom = element('div'); bottom.className = 'wvw-toolbar'; bottom.append(add, download, save);
    root.append(toolbar, notice, precedence, message, error, integrationBox, filters, bulk, scroll, navigation, pasteHelp, paste, append, bottom);
    integrationBox.hidden=true;
    function controls(value) { busy = value; root.querySelectorAll('button,input,select,textarea').forEach(el => { el.disabled = value; el.dataset.unavailable = value ? '1' : '0'; }); }
    function localRule(row,profile) {
      const target=drafts.get(row.id)?.match ?? row.match;
      if(!draftIndex){draftIndex={};for(const p of PROFILES)draftIndex[p]=[...drafts.values()].filter(r=>r.actions[p]!==null).sort((a,b)=>(a.match.kind!=='exact')-(b.match.kind!=='exact')||new TextEncoder().encode(b.match.value).length-new TextEncoder().encode(a.match.value).length||a.id.localeCompare(b.id));}
      return draftIndex[profile].find(r=>r.match.kind===target.kind&&r.match.value===target.value||r.match.kind==='prefix'&&target.value.startsWith(r.match.value));
    }
    function effective(row) {
      const own=drafts.get(row.id), values={},states={};
      for(const profile of PROFILES){
        const base=row.profile_actions?.[profile] ?? {action:'variant',inherited_action:'variant',proposal:'variant',inherited_scope:'recognition',active_rule:false};
        const winner=localRule(row,profile);
        const inherited={...base,...base.reset_metadata,action:base.mode_default_action??base.inherited_action??base.action,scope:base.inherited_scope,override:false};
        const state=winner?{...base,action:winner.actions[profile],effective_action:winner.actions[profile],override:true,active_rule:true,scope:model.scope,rule_id:winner.id,pending_behavior:dirty}:inherited;
        states[profile]=state;values[profile]=state.action;
      }
      const profile=model.profile||'basic';
      return {...row,...states[profile],...(own?{match:clone(own.match),description:own.description}:{}),id:row.id,name:nameOf(own?.match??row.match),actions:values,profile_actions:states};
    }
    function filtered() {
      const term = search.value.toLowerCase();
      return rows.map(effective).filter(row => {
        const source = sourceFilter.value;
        if (source === 'overrides' && !PROFILES.some(p=>row.profile_actions[p].override&&row.profile_actions[p].scope===model.scope)) return false;
        if (source === 'bundled' && !PROFILES.some(p=>row.profile_actions[p].scope==='bundled')) return false;
        if (source === 'central' && !PROFILES.some(p=>row.profile_actions[p].scope==='central')) return false;
        if (source === 'proposals' && row.active_rule !== false && !row.from_proposal) return false;
        if (source === 'custom' && !row.id.startsWith('custom:')) return false;
        if (source === 'recognition' && !row.id.startsWith('ocd:')) return false;
        return PROFILES.every(p => !actionFilters[p].value || row.actions[p] === actionFilters[p].value) && (!term || [row.id, row.name, row.description, row.provider, row.category].join(' ').toLowerCase().includes(term));
      });
    }
    function pagination() { const all = filtered(), amount = size.value === 'all' ? Math.max(all.length, 1) : Number(size.value); const pages = Math.max(1, Math.ceil(all.length / amount)); page = Math.min(page, pages); return {all, pages, visible: all.slice((page - 1) * amount, page * amount)}; }
    function changed() { draftIndex=null;dirty = true; message.textContent = 'Unsaved cookie policy changes.'; }
    function edit(row,patch,profile=model.profile||'basic') {
      const old=effective(row),existing=drafts.get(row.id)??[...drafts.values()].find(r=>nameOf(r.match)===nameOf(old.match));
      const id=existing?.id??row.id,rule=existing?clone(existing):{id,match:clone(old.match),description:old.description||'',actions:{basic:null,ultracache:null}};
      if(Object.hasOwn(patch,'action'))rule.actions[profile]=patch.action;
      else {Object.assign(rule,patch);if(PROFILES.every(p=>rule.actions[p]===null))rule.actions[profile]=old.actions[profile];}
      drafts.set(id,rule);changed();
    }
    function resetRow(id,profile=model.profile||'basic') {
      const row=rows.find(r=>r.id===id);if(!row)return;
      const winner=localRule(row,profile);if(!winner)return;
      const next=clone(winner);next.actions[profile]=null;
      if(PROFILES.every(p=>next.actions[p]===null))drafts.delete(winner.id);else drafts.set(winner.id,next);
      rows=rows.filter(r=>!r.unsaved_new||drafts.has(r.id));changed();
    }
    function render() {
      if (!model) return;
      const {all, pages, visible} = pagination(); body.replaceChildren();
      for (const row of visible) {
        const tr = element('tr'), checkCell = element('td'), check = element('input'); check.type = 'checkbox'; check.checked = selected.has(row.id); check.setAttribute('aria-label', 'Select cookie ' + row.name);
        check.addEventListener('change', () => { check.checked ? selected.add(row.id) : selected.delete(row.id); renderCount(); }); checkCell.append(check); tr.append(checkCell);
        const cookieCell = element('td'), cookie = element('input'); cookie.type = 'text'; cookie.value = nameOf(row.match); cookie.title = 'An exact cookie name, or a literal prefix ending in *. No regular expressions.';
        cookie.className = 'wvw-cookie-field'; cookie.setAttribute('aria-label', 'Cookie name');
        cookie.addEventListener('input', () => { edit(row, {match:parseName(cookie.value.trim())}); refreshExplanation(effective(rows.find(value => value.id === row.id))); });
        cookieCell.append(cookie); tr.append(cookieCell);
        const descriptionCell = element('td'), description = element('textarea'); description.rows = 1; description.className = 'wvw-cookie-field'; description.value = row.description || ''; description.setAttribute('aria-label', 'Description for ' + row.name); description.addEventListener('input', () => edit(row, {description:description.value})); descriptionCell.append(description); tr.append(descriptionCell);
        let choice,actionCell;
        for(const profile of PROFILES){
          const cell=element('td'),select=element('select'),state=row.profile_actions[profile];
          for(const [value,[label,explanation]] of Object.entries(ACTIONS)){const option=new Option(label,value);option.title=explanation;select.append(option);}
          select.className='wvw-cookie-field';select.setAttribute('aria-label',PROFILE_LABEL[profile]+' action for '+row.name);select.value=row.actions[profile];select.title='Change only '+PROFILE_LABEL[profile]+'.';
          select.addEventListener('change',()=>{edit(row,{action:select.value},profile);render();});
          const resetColumn=element('button','Reset '+PROFILE_LABEL[profile]);resetColumn.type='button';resetColumn.title='Remove this matching override only for '+PROFILE_LABEL[profile]+'. The other profile is unchanged.';resetColumn.disabled=!localRule(row,profile);resetColumn.addEventListener('click',()=>{resetRow(row.id,profile);render();});
          cell.append(select,element('small',sourceName(state)),resetColumn);tr.append(cell);
          if(profile===(model.profile||'basic')){choice=select;actionCell=cell;}
        }
        const statusLabel=element('small');actionCell.append(statusLabel);
        const meta = element('td'), sourceLabel = element('strong'); meta.append(sourceLabel);
        const why = element('button', 'Why / precedence'); why.type = 'button'; why.className = 'wvw-cookie-why';
        const activate = element('button', 'Use this proposal'); activate.type = 'button'; activate.title = 'Add this rule to the draft, then use Save & Apply to activate it.';
        activate.addEventListener('click', () => { edit(row,{action:row.action}); render(); });
        const detailRow = element('tr'); detailRow.className = 'wvw-cookie-detail-row'; detailRow.hidden = !expanded.has(row.id);
        const detailsCell = element('td'); detailsCell.colSpan = 6;
        const details = element('div'); details.className = 'wvw-cookie-explanation'; details.id = 'wvw-cookie-explanation-' + rows.findIndex(value => value.id === row.id);
        why.setAttribute('aria-controls', details.id); why.setAttribute('aria-expanded', String(!detailRow.hidden));
        why.addEventListener('click', () => { refreshExplanation(effective(rows.find(value => value.id === row.id))); detailRow.hidden = !detailRow.hidden; detailRow.hidden ? expanded.delete(row.id) : expanded.add(row.id); why.setAttribute('aria-expanded', String(!detailRow.hidden)); });
        function refreshExplanation(current) {
          sourceLabel.textContent = sourceName(current);
          activate.hidden = current.active_rule !== false;
          why.setAttribute('aria-label', 'Why / precedence for ' + current.name);
          choice.setAttribute('aria-label',PROFILE_LABEL[model.profile||'basic']+' action for '+current.name);
          check.setAttribute('aria-label', 'Select cookie ' + current.name);
          statusLabel.textContent = current.pending_behavior ? 'Unsaved choice' : current.active_rule === false ? 'Proposal · save to activate' : current.effective_action && current.effective_action !== current.action ? 'Effective: ' + actionName(current.effective_action) : '';
          statusLabel.hidden = !statusLabel.textContent;
          details.replaceChildren(element('strong',current.name));
          for(const p of PROFILES)details.append(element('p',PROFILE_LABEL[p]+': '+actionName(current.actions[p])+' · '+sourceName(current.profile_actions[p])+' · Proposal: '+actionName(current.profile_actions[p].proposal)));
          if (current.pending_behavior || current.active_rule === false || !current.policy_behavior || current.effective_action && current.effective_action !== current.action)
            details.append(element('p', (current.active_rule === false ? 'Proposed behavior: ' : 'Selected behavior: ') + (ACTIONS[current.action]?.[1] || current.policy_behavior || '')));
          if (current.pending_behavior) details.append(element('p', 'This choice is not active yet. Save & Apply resolves its matching protections and applies it.'));
          else if (current.active_rule === false) details.append(element('p', 'No table rule is active for this new recognition entry. Existing application and cache handling continues. Use this proposal or choose an action, then Save & Apply to activate a rule.'));
          else if (current.policy_behavior) details.append(element('p', 'Applied behavior: ' + current.policy_behavior));
          for (const [label, value] of [['Source',sourceName(current)],['Effective behavior',!current.pending_behavior && current.effective_action !== current.action ? actionName(current.effective_action) : null],['Provider', current.provider],['Category',current.category],['HTML effect',current.htmlEffect],['Assessment',current.confidence],[current.active_rule === false ? 'Proposal rationale' : 'Reason',current.reason],['Precedence',current.core_precedence],['Default policy version',current.default_version]]) if (value) details.append(element('p', label + ': ' + value));
          if (current.valid_match === false) details.append(element('p', 'This upstream pattern is recognition metadata. Edit it to a literal cookie name or trailing-star prefix before saving an explicit rule.'));
          for (const source of current.sources || []) { const text = typeof source === 'string' ? source : JSON.stringify(source); if (/^https?:\/\//i.test(text)) { const link = element('a', text); link.href = text; link.target = '_blank'; link.rel = 'noopener noreferrer'; details.append(link); } else details.append(element('p', text)); }
          for(const p of PROFILES){const button=element('button','Reset '+PROFILE_LABEL[p]);button.type='button';button.title='Remove only this profile override.';button.addEventListener('click',()=>{resetRow(row.id,p);render();});details.append(button);}
        }
        refreshExplanation(row);
        meta.append(why,activate); tr.append(meta); detailsCell.append(details); detailRow.append(detailsCell); body.append(tr, detailRow);
      }
      pageInfo.textContent = `${all.length} rows · Page ${page}/${pages}`;
      previous.disabled = page === 1; next.disabled = page === pages;
      previous.dataset.unavailable = page === 1 ? '1' : '0'; next.dataset.unavailable = page === pages ? '1' : '0';
      selectPage.checked = visible.length > 0 && visible.every(row => selected.has(row.id)); renderCount();
    }
    function actionName(action) { return action === 'application-contract' ? 'Public HTML with verified private fragments; otherwise PASS' : action === 'existing-policy' ? 'Existing handling; no active table rule' : ACTIONS[action]?.[0] || action || ''; }
    function sourceName(row) { return row.active_rule === false ? 'Recognition only · proposal' : row.mode_default_action && !row.override ? 'Aggressive mode · anonymous session default' : row.scope === 'bundled' ? 'Bundled default' : row.scope === 'central' ? 'Central choice' : row.scope === 'site' ? 'Site choice' : row.override ? 'Saved override' : 'Bundled default'; }
    function renderCount() { count.textContent = selected.size + ' selected'; const visible = pagination().visible; selectPage.checked = visible.length > 0 && visible.every(row => selected.has(row.id)); }
    async function load(id, saving = false) {
      if (busy) return;
      controls(true); error.textContent = '';
      try {
        const values=saving ? {id, settings:{schemaVersion:2, rules:[...drafts.values()]}} : {id};
        if(saving && model.id) values.integration={enabled:syncEnabled.checked,url:endpoint.value};
        const response = await request(saving ? 'cookie_policies_save' : 'cookie_policies_status', values);
        if (!response || !response.cookie_policies) throw new Error('Cookie policies are unavailable.');
        model = response.cookie_policies; rows = model.rows; drafts = new Map(model.settings.rules.map(rule => [rule.id, clone(rule)])); draftIndex=null; selected.clear(); expanded.clear(); dirty = false;
        notice.textContent=model.aggressive ? 'Aggressive caching overrides generic origin no-cache/no-store for anonymous public HTML. Known authentication, private routes, cart contracts and explicit Private choices still take precedence.' : 'Shared HTML preserves cookies. Login, checkout, application private/no-store responses and private fragments keep their existing protection.';
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
    for (const input of [search, ...Object.values(actionFilters), sourceFilter, size]) input.addEventListener(input === search ? 'input' : 'change', () => { page = 1; render(); });
    previous.addEventListener('click', () => { page--; render(); }); next.addEventListener('click', () => { page++; render(); });
    selectPage.addEventListener('change', () => { for (const row of pagination().visible) selectPage.checked ? selected.add(row.id) : selected.delete(row.id); renderCount(); });
    apply.addEventListener('click', () => { for (const row of rows) if (selected.has(row.id)) edit(row,{action:bulkAction.value},'basic'); render(); });
    applyUC.addEventListener('click',()=>{for(const row of rows)if(selected.has(row.id))edit(row,{action:bulkAction.value},'ultracache');render();});
    reset.addEventListener('click', () => { for (const id of [...selected]) resetRow(id,'basic'); render(); });
    resetUC.addEventListener('click',()=>{for(const id of [...selected])resetRow(id,'ultracache');render();});
    function appendRule(name='',description='',basic='variant',ultracache=basic,id=null) {
      const match = parseName(name);
      const existingChoice = [...drafts.values()].find(value => nameOf(value.match) === nameOf(match));
      const known = name ? rows.find(value => nameOf(value.match) === nameOf(match)) : null;
      id = id || existingChoice?.id || known?.id || 'custom:' + crypto.randomUUID();
      const rule={id,match,description,actions:{basic,ultracache}}; const existing = rows.find(row => row.id === id);
      if (!existing) rows.unshift({...rule, name, proposal:'variant', scope:model.scope, inherited:null, unsaved_new:true, reason:'Custom cookie policy.', policy_behavior:ACTIONS[basic][1],profile_actions:Object.fromEntries(PROFILES.map(p=>[p,{action:'variant',inherited_action:'variant',proposal:'variant',inherited_scope:'recognition'}]))});
      drafts.set(id, rule); changed(); return id;
    }
    add.addEventListener('click', () => { if (!model) return; const id = appendRule(); search.value = ''; sourceFilter.value = ''; for (const filter of Object.values(actionFilters)) filter.value = ''; page = 1; render(); body.querySelector('input[type=text]')?.focus(); });
    append.addEventListener('click', () => {
      if (!model) return; error.textContent = '';
      try {
        const values = parsePaste(paste.value); if (values.length && /^(?:id|cookie)$/i.test(values[0][0].trim())) values.shift();
        const parsed=values.map((cells,index)=>{
          if(cells.length<3||cells.length>5)throw new Error('Each row needs Cookie, Description, Basic and UltraCache.');
          const offset=cells.length===5?1:0,name=cells[offset].trim(),basic=cells[offset+2].trim().toLowerCase(),ultra=(cells[offset+3]??basic).trim().toLowerCase();
          if(!name||!ACTIONS[basic]||!ACTIONS[ultra])throw new Error('Use shared, variant or private in both profile columns.');
          return [name,cells[offset+1],basic,ultra,offset&&rows.some(r=>r.id===cells[0])?cells[0]:null];
        });
        for (const row of parsed) appendRule(...row); paste.value = ''; search.value = ''; sourceFilter.value = ''; for (const filter of Object.values(actionFilters)) filter.value = ''; page = 1; render();
      } catch (failure) { error.textContent = failure.message; }
    });
    download.addEventListener('click', () => {
      const escape = value => { let text = String(value ?? ''); if (/^[=+@\-\t\r]/.test(text)) text = "'" + text; return '"' + text.replaceAll('"','""') + '"'; };
      const lines = [['Cookie','Description','Basic','UltraCache'],...filtered().map(row=>[nameOf(row.match),row.description,row.actions.basic,row.actions.ultracache])];
      const url = URL.createObjectURL(new Blob(['\uFEFF' + lines.map(row => row.map(escape).join(',')).join('\r\n')], {type:'text/csv;charset=utf-8'}));
      const anchor = element('a'); anchor.href = url; anchor.download = 'cookie-policies.csv'; anchor.click(); URL.revokeObjectURL(url);
    });
    if (options.lazy) options.lazy.addEventListener('toggle', () => { if (options.lazy.open && !model && !busy) load(null); });
    else load(null);
    return {reload: () => load(model ? model.id : null)};
  }
  window.WebuzoCookiePolicies = {mount};
})();
