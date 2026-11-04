(function () {
  'use strict';
  var msg = document.getElementById('cx-msg'), list = document.getElementById('cx-list');
  var form = document.getElementById('cx-form'), inventoryStatus = document.getElementById('cx-inventory-status');
  var currentByName = {}, editing = null, context = null, inventoryReady = false, accessLost = false;
  var canManage = form.dataset.canManage === 'true';
  var busy = false, uncertain = false, conflict = false, unknownBinding = false, loadSerial = 0;
  function el(tag, cls, text) { var node = document.createElement(tag); node.className = cls || ''; if (text != null) node.textContent = text; return node; }
  function say(text, error) { window.mvStatus(msg, text || '', {error: !!error}); msg.style.color = error ? 'var(--danger)' : 'var(--muted)'; }
  function controls() {
    form.querySelectorAll('button').forEach(function (button) { button.disabled = !canManage || !inventoryReady || busy || uncertain || conflict || unknownBinding || accessLost; });
    list.querySelectorAll('button').forEach(function (button) { button.disabled = (!canManage && !button.dataset.connectionImpact) || !inventoryReady || busy || uncertain || accessLost; });
    form.setAttribute('aria-busy', String(busy));
  }
  function clearSecrets() { ['cx-token','cx-aws-access','cx-aws-secret','cx-aws-region','cx-aws-session'].forEach(function (id) { document.getElementById(id).value = ''; }); }
  function clearAccess() {
    accessLost = true; loadSerial++; inventoryReady = false; currentByName = {}; editing = null;
    list.replaceChildren(); form.reset(); clearSecrets();
    document.getElementById('cx-conflict').hidden = true;
    document.getElementById('cx-conflict-draft').textContent = '';
    document.getElementById('cx-conflict-current').textContent = '';
    document.getElementById('cx-empty').hidden = true;
    form.querySelectorAll('input,select,button').forEach(function (node) { node.disabled = true; });
    inventoryStatus.textContent = 'Connection access changed. Sign in again, select your workspace, and reload this page.';
    controls();
  }
  document.addEventListener('lightwork:connection-access-lost', clearAccess);
  document.addEventListener('lightwork:workspace-changed', clearAccess);
  document.addEventListener('lightwork:connection-saved', function () { if (!accessLost) load(); });
  window.addEventListener('pagehide', clearAccess);
  async function request(url, options) {
    var denied = 'Connection access is unavailable. Refresh the page and try again.';
    var opts = Object.assign({cache: 'no-store', timeout: 25000, accessStatuses: [401], onAccess: clearAccess, messages: {401: denied, 403: denied}}, options || {});
    opts.headers = Object.assign({'Content-Type': 'application/json'}, options && options.headers);
    try { return await window.mvFetchJSON(url, opts, 'complete this connection action'); }
    catch (error) {
      if (error.status === 403) {
        clearAccess();
        if (error.detail && error.detail.code === 'connections_disabled') inventoryStatus.textContent = 'Connections are turned off. An administrator can enable them in Settings.';
      }
      throw error;
    }
  }
  var PRESETS = [
    { id: 'slack',      label: 'Slack',       connector: 'slack',      base: 'https://slack.com/api', keyHelp: 'https://api.slack.com/apps' },
    { id: 'github',     label: 'GitHub',      connector: 'github',     base: 'https://api.github.com', keyHelp: 'https://github.com/settings/tokens' },
    { id: 'notion',     label: 'Notion',      connector: 'notion',     base: 'https://api.notion.com', keyHelp: 'https://www.notion.so/my-integrations' },
    { id: 'hubspot',    label: 'HubSpot',     connector: 'hubspot',    base: 'https://api.hubapi.com', keyHelp: 'https://knowledge.hubspot.com/integrations/how-do-i-get-my-hubspot-api-key' },
    { id: 'stripe',     label: 'Stripe',      connector: 'stripe',     base: 'https://api.stripe.com', keyHelp: 'https://dashboard.stripe.com/apikeys' },
    { id: 'salesforce', label: 'Salesforce',  connector: 'salesforce', base: '', hint: 'https://your-company.my.salesforce.com', baseLabel: 'Your Salesforce address' },
    { id: 'zendesk',    label: 'Zendesk',     connector: 'zendesk',    base: '', hint: 'https://your-company.zendesk.com', baseLabel: 'Your Zendesk address' },
    { id: 'jira',       label: 'Jira',        connector: 'jira',       base: '', hint: 'https://your-team.atlassian.net', baseLabel: 'Your Jira address', keyHelp: 'https://id.atlassian.com/manage-profile/security/api-tokens' },
    { id: 'aws_s3', label: 'Amazon S3 storage', connector: 'aws_s3', base: '', hint: 'https://your-bucket.s3.your-region.amazonaws.com', baseLabel: 'Your storage address', discovery: true, help: 'Fill in the Amazon Web Services sign-in below. Choose how this account is used separately in Privacy scanning or Independent history protection. History protection needs your own account for the same bucket and region configured in Compliance.' },
    { id: 'azure_blob', label: 'Privacy scanning: Azure storage', connector: 'azure_blob', base: '', hint: 'https://your-account.blob.core.windows.net', baseLabel: 'Your Azure storage address', discovery: true, help: 'Paste an access token from Azure that can read this storage. Shared access links and account keys are not supported.' },
    { id: 'google_cloud_storage', label: 'Privacy scanning: Google Cloud Storage', connector: 'google_cloud_storage', base: 'https://storage.googleapis.com', discovery: true, help: 'Paste an access token from Google Cloud that can read this storage.' },
    { id: 'snowflake_metadata', label: 'Privacy scanning: Snowflake', connector: 'snowflake_metadata', base: '', hint: 'https://your-account.snowflakecomputing.com', baseLabel: 'Your Snowflake address', discovery: true, help: 'Paste an access token from Snowflake. Scanning only reads the names and types of your data, not the data itself.' },
    { id: 'servicenow_cmdb', label: 'Privacy scanning: ServiceNow', connector: 'servicenow_cmdb', base: '', hint: 'https://your-company.service-now.com', baseLabel: 'Your ServiceNow address', discovery: true, help: 'Paste an access token from ServiceNow that can read your list of systems.' },
    { id: 'entra_assets', label: 'Privacy scanning: Microsoft Entra', connector: 'entra_assets', base: 'https://graph.microsoft.com', discovery: true, help: 'Paste a Microsoft access token that can read your devices and apps.' },
    { id: 'aws_security_hub', label: 'Evidence: AWS Security Hub', connector: 'aws_security_hub', evidence: true, aws: true, help: 'Enter the AWS sign-in below. Choose the account and security controls separately in Continuous evidence.' },
    { id: 'aws_config', label: 'Evidence: AWS Config', connector: 'aws_config', evidence: true, aws: true, help: 'Enter the AWS sign-in below. Choose the account and configuration rules separately in Continuous evidence.' },
    { id: 'azure_defender', label: 'Evidence: Microsoft Defender for Cloud', connector: 'azure_defender', base: 'https://management.azure.com', evidence: true, help: 'Paste a Microsoft access token for Azure management that can read the selected subscription. Storage tokens are a separate kind of access.' },
    { id: 'azure_policy', label: 'Evidence: Azure Policy', connector: 'azure_policy', base: 'https://management.azure.com', evidence: true, help: 'Paste a Microsoft access token for Azure management that can read policy results in the selected subscription.' },
    { id: 'gcp_security_command_center', label: 'Evidence: Google Cloud Security Command Center', connector: 'gcp_security_command_center', base: 'https://securitycenter.googleapis.com', evidence: true, help: 'Paste a Google access token that can read Security Command Center findings in your chosen organization, folder or project.' },
    { id: 'github_security', label: 'Evidence: GitHub security alerts', connector: 'github_security', base: 'https://api.github.com', evidence: true, help: 'Paste a GitHub token that can read the security alerts you choose. Repository access alone may not grant security-alert access.' },
    { id: 'okta_posture', label: 'Evidence: Okta policies', connector: 'okta_posture', base: '', hint: 'https://your-company.okta.com', evidence: true, help: 'Paste an Okta API token and your company’s exact HTTPS Okta address. Choose the policy type separately in Continuous evidence.' },
  ];

  var preset = document.getElementById('cx-preset'), nameEl = document.getElementById('cx-name');
  var connEl = document.getElementById('cx-connector'), baseEl = document.getElementById('cx-base');
  var advanced = document.getElementById('cx-advanced'), catalog = {};
  function slugName(value) { return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^[-_]+|[-_]+$/g, '').slice(0,64); }
  function peopleBoxes() { return Array.from(document.querySelectorAll('#cx-principals input[type="checkbox"]')); }
  function discoveryPreset(value) { return PRESETS.find(function (p) { return p.connector === value && p.discovery; }); }
  function evidencePreset(value) { return PRESETS.find(function (p) { return p.connector === value && p.evidence; }); }
  function evidenceOrigin() {
    var selected = evidencePreset(connEl.value), region = document.getElementById('cx-aws-region').value.trim();
    if (selected && selected.aws && /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) {
      baseEl.value = 'https://' + (selected.id === 'aws_security_hub' ? 'securityhub' : 'config') + '.' + region + '.amazonaws.com';
    }
  }
  function credentialFields(value) {
    var p = PRESETS.find(function (item) { return item.connector === value; });
    var aws = value === 'aws_s3' || Boolean(p && p.aws);
    document.getElementById('cx-aws').hidden = !aws;
    document.getElementById('cx-token').closest('.cx__fld').hidden = aws;
    document.getElementById('cx-token').required = Boolean(!editing && catalog[value] && catalog[value].reference_data);
    document.getElementById('cx-save-test').hidden = Boolean(discoveryPreset(value) || evidencePreset(value));
    document.getElementById('cx-credential-help').textContent = p && p.help ? p.help : catalog[value] ? catalog[value].auth_method + '. ' + catalog[value].prerequisites : 'Existing tool binding preserved. Unknown adapters require administrator review before migration.';
    document.getElementById('cx-key-help').hidden = !(p && p.keyHelp);
    if (p && p.keyHelp) document.getElementById('cx-key-help').href = p.keyHelp;
  }
  function addOption(value, label) {
    if (!Array.from(connEl.options).some(function (o) { return o.value === value; })) connEl.appendChild(new Option(label, value));
    if (!Array.from(preset.options).some(function (o) { return o.value === value; })) preset.insertBefore(new Option(label, value), preset.querySelector('[value="custom"]'));
  }
  PRESETS.forEach(function (p) { addOption(p.connector, p.label); });
  preset.addEventListener('change', function () {
    if (editing) return;
    var p = PRESETS.find(function (item) { return item.id === preset.value; });
    connEl.value = preset.value === 'custom' ? '' : preset.value;
    document.getElementById('cx-connector-field').hidden = preset.value !== 'custom';
    if (p) { baseEl.value = p.base || ''; baseEl.placeholder = p.hint || 'https://'; }
    else { baseEl.value = catalog[preset.value] && catalog[preset.value].default_base_url || ''; baseEl.placeholder = 'https://'; }
    baseEl.readOnly = Boolean(catalog[preset.value] && catalog[preset.value].reference_data);
    if (!nameEl.value.trim()) nameEl.value = p ? p.label : catalog[preset.value] ? catalog[preset.value].label : '';
    advanced.open = true; clearSecrets(); credentialFields(connEl.value);
  });
  connEl.addEventListener('change', function () { clearSecrets(); credentialFields(connEl.value); });
  document.getElementById('cx-aws-region').addEventListener('input', evidenceOrigin);
  document.getElementById('cx-catalog-search').addEventListener('input', function (event) {
    var q = event.target.value.trim().toLowerCase();
    Array.from(preset.options).forEach(function (o) { o.hidden = Boolean(o.value && o.value !== 'custom' && !o.textContent.toLowerCase().includes(q)); });
  });
  nameEl.addEventListener('input', function () { document.getElementById('cx-name-as').textContent = slugName(nameEl.value) !== nameEl.value.trim() ? 'Saved name: ' + slugName(nameEl.value) : ''; });
  function readiness(record) {
    if (evidencePreset(record.connector)) return 'Check the chosen security source in Continuous evidence.';
    if (discoveryPreset(record.connector)) return 'Check exact source access in Privacy scanning.';
    var t = record.last_test;
    if (!t) return 'Access not checked. A saved key does not prove task access.';
    if (!t.revision || t.revision !== record.revision) return 'Earlier credential check; test the current saved credential.';
    var labels = {authenticated:'Authentication verified at check time',access_unverified:'Reachable; access not verified',sign_in_refused:'Sign-in refused',blocked_by_policy:'Blocked by connection policy',unreachable:'Service unreachable',address_missing:'Service address needed'};
    var checked = Number(t.tested_at) * 1000, stale = !Number.isFinite(checked) || Date.now() - checked > 86400000;
    return (stale ? 'Previous check (stale): ' : '') + (labels[t.outcome] || 'Access not verified') +
      (Number.isFinite(checked) ? ' · ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(checked) : new Date(checked).toLocaleString()) : '') + '. ' +
      (t.capability || 'Service address only; task permissions still need checking.');
  }
  function editRecord(record) {
    editing = JSON.parse(JSON.stringify(record)); conflict = false;
    unknownBinding = !catalog[record.connector] && !PRESETS.some(function (item) { return item.connector === record.connector; });
    nameEl.value = record.name; nameEl.readOnly = true;
    addOption(record.connector, catalog[record.connector] ? catalog[record.connector].label : record.connector + ' (existing binding)');
    connEl.value = record.connector; preset.value = record.connector;
    // Metadata edits never migrate a credential to a different adapter. Reconnect explicitly.
    connEl.disabled = true; preset.disabled = true; baseEl.readOnly = Boolean(record.oauth || catalog[record.connector] && catalog[record.connector].reference_data);
    baseEl.value = record.base_url || '';
    document.getElementById('cx-tenant-access').checked = record.access === 'tenant';
    peopleBoxes().forEach(function (box) { box.checked = (record.allowed_principals || []).includes(box.value); });
    clearSecrets(); credentialFields(record.connector); advanced.open = true;
    document.getElementById('cx-connector-field').hidden = false;
    say(unknownBinding ? 'This adapter is unknown or retired. The saved record is read-only; create and review a supported replacement before migration.' : 'Changing ' + record.name + '. Blank credential fields keep the saved credential. Provider changes require a separate reviewed connection.'); controls();
  }
  function publicSummary(value) {
    return JSON.stringify({name:value.name, service:value.connector, address:value.base_url, sharing:value.access, people:value.allowed_principals || []}, null, 2);
  }
  function showConflict(body) {
    conflict = true; document.getElementById('cx-conflict').hidden = false;
    document.getElementById('cx-conflict-draft').textContent = 'Your draft:\n' + publicSummary(body);
    document.getElementById('cx-conflict-current').textContent = 'Current record: refresh to review.';
    clearSecrets(); say('This connection changed. Review the current record before saving again. Your draft has kept its original revision.', true);
  }
  document.getElementById('cx-reload-edit').addEventListener('click', async function () {
    if (busy || accessLost) return;
    var name = editing ? editing.name : slugName(nameEl.value);
    await load();
    if (inventoryReady && currentByName[name]) { editRecord(currentByName[name]); document.getElementById('cx-conflict').hidden = true; nameEl.focus(); }
  });
  async function load(knownInventory) {
    if (accessLost) return;
    var serial = ++loadSerial; inventoryReady = false; document.getElementById('cx-empty').hidden = true; controls();
    inventoryStatus.textContent = 'Checking saved connections.';
    try {
      var data = knownInventory || await request('/api/v1/connections');
      if (serial !== loadSerial || accessLost) return;
      if (!Array.isArray(data.connections) || data.connections.some(function (c) { return !c || typeof c.name !== 'string' || typeof c.revision !== 'string'; }) || typeof data.context !== 'string') throw new Error('Unreadable inventory.');
      if (context && context !== data.context) { clearAccess(); return; }
      context = data.context; currentByName = {}; list.replaceChildren();
      data.connections.forEach(function (record) {
        currentByName[record.name] = record;
        var li = el('li','cx__row'); li.id='connection-'+record.name; li.appendChild(el('span','name',record.name));
        li.appendChild(el('div','meta',(catalog[record.connector] ? catalog[record.connector].label : record.connector) + ' · ' + (record.access === 'tenant' ? 'Everyone in this workspace' : 'Owner and selected people') + ' · ' + readiness(record)));
        li.appendChild(el('span','badge',record.has_token ? 'Credential saved' : 'No credential saved'));
        var change = el('button','btn btn--ghost','Change'); change.type='button'; change.addEventListener('click',function () { if (inventoryReady && !busy) editRecord(record); });
        var test = el('button','btn btn--ghost',discoveryPreset(record.connector) || evidencePreset(record.connector) ? 'Check source access' : 'Check service access'); test.type='button';
        test.addEventListener('click',function () {
          if (evidencePreset(record.connector)) { location.href='/compliance/continuous-evidence'; return; }
          if (discoveryPreset(record.connector)) { location.href='/privacy/data-discovery'; return; }
          mutate('test', record);
        });
        var remove=el('button','btn btn--danger','Remove'); remove.type='button'; remove.addEventListener('click',function () { mutate('remove',record); });
        var impactButton=el('button','btn btn--ghost','Used by and repair'); impactButton.type='button'; impactButton.dataset.connectionImpact=record.name; impactButton.dataset.connectionRevision=record.revision;
        li.append(change,test,remove,impactButton); list.appendChild(li); if(location.hash==='#'+encodeURIComponent(li.id)){li.tabIndex=-1;li.focus();}
      });
      inventoryReady = true;
      inventoryStatus.textContent = 'Connections checked at ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(Date.now()) : new Date().toLocaleTimeString()) + '.';
      document.getElementById('cx-empty').hidden = data.connections.length > 0;
      if (conflict && editing && currentByName[editing.name]) document.getElementById('cx-conflict-current').textContent = 'Current saved record:\n' + publicSummary(currentByName[editing.name]);
    } catch (error) {
      if (serial !== loadSerial || accessLost) return;
      inventoryStatus.textContent = 'Connections are unavailable. Any rows below are from an earlier check; changes are disabled. Refresh to try again.';
    } finally { if (serial === loadSerial) controls(); }
  }
  function readBody() {
    if (editing && unknownBinding) throw new Error('This saved adapter is read-only until a supported migration is reviewed.');
    var name = slugName(nameEl.value), body = {name:name, connector:editing ? editing.connector : connEl.value, base_url:baseEl.value.trim(), access:document.getElementById('cx-tenant-access').checked ? 'tenant' : 'owner', allowed_principals:peopleBoxes().filter(function (b) { return b.checked; }).map(function (b) { return b.value; })};
    var token = document.getElementById('cx-token').value;
    if (!editing && currentByName[name]) throw new Error('That name is already saved. Choose Change on its current row before editing.');
    if (!editing && catalog[body.connector] && !catalog[body.connector].key_setup_supported) throw new Error(catalog[body.connector].prerequisites);
    if (!body.connector) throw new Error('Choose the service that will use this connection.');
    var securitySource = evidencePreset(body.connector);
    if (body.connector === 'aws_s3' || (securitySource && securitySource.aws)) {
      var access=document.getElementById('cx-aws-access').value.trim(), secret=document.getElementById('cx-aws-secret').value, region=document.getElementById('cx-aws-region').value.trim(), session=document.getElementById('cx-aws-session').value;
      if (access || secret || region || session) {
        if (!access || !secret || !/^[a-z]{2}(-[a-z]+)+-[0-9]+$/.test(region)) throw new Error('Enter the access key, secret key, and a valid AWS region together.');
        var credential = {access_key_id:access,secret_access_key:secret};
        if (!securitySource) credential.region = region;
        else { evidenceOrigin(); body.base_url = baseEl.value.trim(); }
        token=JSON.stringify(Object.assign(credential,session ? {session_token:session} : {}));
      }
      else if (!editing && securitySource) throw new Error('Enter the AWS access key, secret key, and region before saving this account.');
    }
    if (token || !editing) body.token=token;
    if (editing) body.expected_revision=editing.revision;
    return body;
  }
  async function mutate(action, record, thenTest) {
    if (!canManage || busy || uncertain || !inventoryReady || accessLost || (action === 'save' && conflict)) return;
    var body;
    if (action === 'save') { try { body=readBody(); } catch (error) { say(error.message,true); return; } if (!form.reportValidity()) return; }
    busy=true; controls();
    var sent=false, followUpFailed=false;
    try {
      var impactVersion=null;
      if (action === 'remove' || (action === 'save' && editing)) {
        if (!window.lightworkConnectionImpact) throw new Error('Connection impact review is unavailable. Reload before changing this record.');
        impactVersion=await window.lightworkConnectionImpact.review(action === 'remove' ? record.name : editing.name, action === 'remove' ? record.revision : editing.revision, action, context);
        if (!impactVersion) return;
        if (action === 'save') { body.impact_version=impactVersion; body.context=context; }
      }
      if (accessLost) return;
      var url='/api/v1/connections' + (action === 'save' ? '' : '/' + encodeURIComponent(record.name) + (action === 'test' ? '/test' : '?' + new URLSearchParams({expected_revision:record.revision,impact_version:impactVersion,context:context})));
      say(action === 'test' ? 'Checking service access.' : 'Saving your change.');
      sent=true;
      var result=await request(url,{method:action === 'remove' ? 'DELETE' : 'POST',body:action === 'save' ? JSON.stringify(body) : undefined});
      if (accessLost) return;
      if (action === 'save' && (!result || result.name !== body.name || typeof result.revision !== 'string')) throw new Error('Save receipt is unreadable.');
      if (action === 'remove' && result.deleted !== record.name) throw new Error('Removal receipt is unreadable.');
      if (action === 'test' && typeof result.reachable !== 'boolean') throw new Error('Test receipt is unreadable.');
      if (action === 'save') {
        clearSecrets(); editing=null; unknownBinding=false; nameEl.readOnly=false; preset.disabled=false; connEl.disabled=false;
        baseEl.readOnly=Boolean(catalog[connEl.value] && catalog[connEl.value].reference_data); credentialFields(connEl.value);
        if (thenTest && !discoveryPreset(body.connector) && !evidencePreset(body.connector)) {
          // The save is already recorded; a failing follow-up check is its own result, not an unconfirmed save.
          try { await request('/api/v1/connections/'+encodeURIComponent(body.name)+'/test',{method:'POST'}); } catch (testError) { if (accessLost) return; followUpFailed=true; }
        }
      }
      say(action === 'remove' ? 'Local connection removed. Provider authorization has not been revoked.' : action === 'test' ? 'Check recorded. Review its scope and time on the connection row.' : followUpFailed ? 'Connection saved, but the follow-up service check could not be completed. Run the check from the connection row.' : 'Connection saved. Review the separate service or source check before running work.');
      await load();
    } catch (error) {
      if (accessLost) return;
      if (error.status === 409 && action === 'save') { showConflict(body); await load(); }
      else if (error.status && error.status < 500) say(window.mvErrorText ? mvErrorText(error,'complete this connection action') : 'The action was refused. Refresh and review the current record.',true);
      else if (!sent) { say(error.message || 'Nothing was sent. Your entered values are kept.', true); }
      else { uncertain=true; clearSecrets(); say('Result not confirmed. Refresh connections and review the saved record before making another change. No request will be replayed.',true); }
    } finally { busy=false; controls(); }
  }
  document.getElementById('cx-retry').addEventListener('click', async function () { if (busy || accessLost) return; await load(); if (inventoryReady) { uncertain=false; controls(); say('Current inventory loaded. Review the saved record before another change.'); } });
  form.addEventListener('submit',function (event) { event.preventDefault(); mutate('save',null,false); });
  document.getElementById('cx-save-test').addEventListener('click',function () { mutate('save',null,true); });
  request('/api/v1/connections/catalog').then(function (data) {
    if (accessLost || !Array.isArray(data.connectors)) return;
    data.connectors.forEach(function (item) { catalog[item.name]=item; addOption(item.name,item.label + (item.key_setup_supported ? '' : ' (dedicated setup)')); });
    if (editing && catalog[editing.connector]) { unknownBinding=false; controls(); }
  }).catch(function () { if (!accessLost) say('The full service catalog is unavailable. Refresh before setting up a new service.',true); });
  window.LightworkConnections = {openReview: async function (expectedContext, isCurrent) {
    if (typeof isCurrent !== 'function' || !isCurrent()) return false;
    if (!canManage || !inventoryReady || accessLost || busy || uncertain || conflict || unknownBinding ||
        !/^[a-f0-9]{64}$/.test(String(expectedContext || '')) || context !== expectedContext) {
      say('Finish the current connection review before opening setup. Your entered work is kept.', true); return false;
    }
    var serial = loadSerial;
    try {
      var responses = await Promise.all([request('/api/v1/connections/catalog'), request('/api/v1/connections')]);
      if (!isCurrent() || accessLost || serial !== loadSerial || busy || uncertain || conflict || unknownBinding || context !== expectedContext) return false;
      if (!responses[1] || responses[1].context !== expectedContext) { clearAccess(); return false; }
      if (!Array.isArray(responses[0].connectors)) throw new Error('The service choices could not be read.');
      responses[0].connectors.forEach(function (item) { catalog[item.name]=item; addOption(item.name,item.label + (item.key_setup_supported ? '' : ' (dedicated setup)')); });
      await load(responses[1]);
      if (!isCurrent() || !inventoryReady || accessLost || busy || uncertain || conflict || unknownBinding || context !== expectedContext) return false;
      document.getElementById('cx-catalog-search').focus();
      say('Choose a service to connect. Your entered connection and account sign-in work is kept.'); return true;
    } catch (error) { if (isCurrent() && !accessLost) say(error.message || 'Connection setup could not be opened. Your entered work is kept.', true); return false; }
  }};
  var requestedEvidence = new URLSearchParams(location.search).get('evidence');
  if (evidencePreset(requestedEvidence)) {
    preset.value = requestedEvidence; preset.dispatchEvent(new Event('change'));
    var returnLink = el('a','btn btn--ghost','Return to Continuous evidence');
    returnLink.href = '/compliance/continuous-evidence'; form.insertBefore(returnLink, form.firstChild);
  }
  load();
})();
