/* Registered native controls: fresh source -> reviewed input -> explicit confirmation. */
(function () {
  'use strict';
  var panel = document.getElementById('mv-copilot'), host = document.getElementById('mv-product-operations');
  var status = document.getElementById('mv-product-operation-status'), buttons = document.getElementById('mv-product-operation-buttons');
  var formHost = document.getElementById('mv-product-operation-form');
  var search = document.getElementById('mv-product-operation-search'), noMatches = document.getElementById('mv-product-operation-empty');
  if (!panel || !host || !status || !buttons || !formHost) return;
  var root = '/api/v1/copilot/product-operations', generation = 0, busy = false, catalog = null, selected = null;
  var uncertainty = '', overrideSelection = null, pendingRequests = new Set();
  // Loaded after the page (lightwork-ui.js): start from a selection the page made meanwhile.
  var early = window.LightworkCopilotEarlySelection;
  if (early && early.selection) overrideSelection = early.selection;
  function cancelRequests() { pendingRequests.forEach(function (controller) { controller.abort(); }); pendingRequests.clear(); }
  function node(tag, text, parent) { var element = document.createElement(tag); if (text !== undefined) element.textContent = String(text); if (parent) parent.appendChild(element); return element; }
  function clear(element) { element.replaceChildren(); }
  // Without an access digest on either side, assume the account changed.
  function accessChanged(before, after) { return !before.access || !after.access || before.access !== after.access; }
  function filterControls() {
    var query = search ? search.value.trim().toLocaleLowerCase() : '', found = 0;
    buttons.querySelectorAll('button').forEach(function (control) {
      control.hidden = !control.textContent.toLocaleLowerCase().includes(query);
      if (!control.hidden) found += 1;
    });
    if (noMatches) noMatches.hidden = !query || found > 0;
  }
  if (search) search.addEventListener('input', filterControls);
  function button(text, parent, handler) { var control = node('button', text, parent); control.type = 'button'; control.disabled = busy; control.className = 'btn btn--ghost'; control.addEventListener('click', handler); return control; }
  function protectedControls(parent, label, href, open) {
    var started = generation, selection = JSON.stringify(context());
    if (typeof open !== 'function') { var link = node('a', label, parent); link.href = href; link.className = 'btn btn--ghost'; return; }
    button(label, parent, async function (event) {
      var isCurrent = function () { return active(started) && JSON.stringify(context()) === selection; };
      if (!isCurrent() || busy) return;
      lock(true);
      try {
        var opened = await open(isCurrent);
        if (!isCurrent()) return;
        status.textContent = opened ? 'The complete controls are open; your entered choices were kept.' : 'The selection or your access changed. Review the current controls.';
        if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
      } catch (_) { if (isCurrent()) status.textContent = 'The controls could not be opened. Your current work is kept.'; }
      finally { lock(false); }
    });
  }
  function context() {
    if (overrideSelection) return overrideSelection;
    var approval = window.location.hash.match(/^#approval-([1-9]\d*)$/);
    if (approval && ['/approvals', '/oversight'].includes(window.location.pathname) && Number.isSafeInteger(Number(approval[1]))) return {kind: 'approval', id: Number(approval[1])};
    var goal = window.location.pathname.match(/^\/(?:chat\/goal|tasks)\/(\d+)(?:\/|$)/);
    if (goal) return {kind: 'goal', id: Number(goal[1]), goal_id: Number(goal[1])};
    var dsar = window.location.pathname.match(/^\/privacy\/dsar\/(DSAR-[0-9a-f]{10})$/);
    if (dsar) return {kind: 'dsar', id: dsar[1]};
    var run = window.location.pathname.match(/^\/flows\/([^/]+)\/runs\/([^/]+)$/);
    if (run) {
      try { return {kind: 'flow_run', id: decodeURIComponent(run[2]), flow_id: decodeURIComponent(run[1])}; }
      catch (_) { return {}; }
    }
    var flow = window.location.pathname.match(/^\/flows\/designer\/([^/]+)$/) ||
      window.location.pathname.match(/^\/flows\/([^/]+)\/teach$/);
    if (flow) {
      try { return {kind: 'flow', id: decodeURIComponent(flow[1])}; } catch (_) { return {}; }
    }
    var query = new URLSearchParams(window.location.search);
    var specialist = query.get('name');
    if (window.location.pathname === '/agents' && specialist && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(specialist)) return {name: specialist};
    var learningPass = query.get('learning_pass');
    var learningTransfer = query.get('learning_transfer');
    if (window.location.pathname === '/learned' && learningTransfer && /^[a-f0-9]{32}$/.test(learningTransfer))
      return {kind: 'learning_transfer', operation: learningTransfer};
    if (window.location.pathname === '/learned' && learningPass && /^[a-f0-9]{32}$/.test(learningPass))
      return {kind: 'learning_pass', operation: learningPass};
    // The workflow builder's Steps mode is the flow designer's editor for ?flow=<id>.
    var builderFlow = query.get('flow');
    if (window.location.pathname === '/workflow-builder' && query.get('mode') === 'steps' &&
        builderFlow && /^[A-Za-z0-9_-]{1,120}$/.test(builderFlow)) return {kind: 'flow', id: builderFlow};
    var selectedGoal = query.get('goal_id');
    if (window.location.pathname === '/budget' && selectedGoal && /^[1-9]\d*$/.test(selectedGoal)) return {goal_id: Number(selectedGoal)};
    var thread = query.get('thread');
    if (window.location.pathname === '/preferences' && thread && /^\d+$/.test(thread)) return {kind: 'preferences', thread: Number(thread)};
    return {};
  }
  function payload() { return {page: window.location.pathname, selection: context()}; }
  function active(started) { return generation === started && !panel.hidden; }
  function lock(value) {
    busy = value;
    buttons.querySelectorAll('button').forEach(function (element) { element.disabled = value || element.dataset.available !== 'true'; });
    formHost.querySelectorAll('input,select,textarea,button').forEach(function (element) { element.disabled = value || Boolean(element._lightworkConsent && !element._lightworkConsent.checked); });
  }
  function errorMessage(result, fallback) {
    var detail = result && result.detail;
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail.message === 'string') return detail.message;
    return fallback;
  }
  async function request(route, body, fullLocalCheck) {
    var controller = new AbortController(); pendingRequests.add(controller);
    var timeout = setTimeout(function () { controller.abort(); }, fullLocalCheck === true && route === '/execute' ? 150000 : fullLocalCheck === true && route === '/prepare' ? 90000 : route === '/propose' ? 45000 : 30000);
    try {
      var response = await fetch(root + route, {method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: JSON.stringify(body)});
      var value = null; try { value = await response.json(); } catch (_) { /* No raw server responses. */ }
      if (!response.ok) { var error = new Error(errorMessage(value, 'The current control is unavailable. Open its native page to check status.')); error.status = response.status; throw error; }
      if (!value || typeof value !== 'object') throw new Error('The response was unreadable. Check native status before another attempt.');
      return value;
    } catch (error) {
      if (controller.signal.aborted) throw new Error(route === '/execute'
        ? 'The wait ended before the result was confirmed. Check native status before another attempt.'
        : 'This check timed out or was cancelled. Reopen the control to read current status.');
      if (error && error.status) throw error;
      throw new Error(route === '/execute'
        ? 'The result could not be confirmed. Check native status before another attempt.'
        : 'This check could not be completed. Reopen the control to read current status.');
    } finally { clearTimeout(timeout); pendingRequests.delete(controller); }
  }
  function renderData(parent, value, options) {
    var complete = true, fullReview = !!(options && options.complete), remaining = fullReview ? 8192 : 160;
    var maximumEntries = fullReview ? 2048 : 35, maximumDepth = fullReview ? 12 : 6;
    function omitted(target) { complete = false; node('p', 'The complete details are available in the full controls.', target); }
    function changeRow(item) {
      return fullReview && item && typeof item === 'object' && !Array.isArray(item) && typeof item.label === 'string' &&
        Object.keys(item).every(function (key) { return ['label', 'before', 'after'].includes(key); }) &&
        (Object.prototype.hasOwnProperty.call(item, 'before') || Object.prototype.hasOwnProperty.call(item, 'after'));
    }
    function append(target, item, depth) {
      if (--remaining < 0 || depth > maximumDepth) { omitted(target); return; }
      if (item === null || item === undefined) { node('span', 'Not specified', target); return; }
      if (typeof item !== 'object') {
        var text = node('span', typeof item === 'boolean' ? (item ? 'Yes' : 'No') : item, target);
        text.style.whiteSpace = 'pre-wrap'; text.style.overflowWrap = 'anywhere'; return;
      }
      if (typeof item.href === 'string' && typeof item.label === 'string' && safeLocalHref(item.href) &&
          (!fullReview || Object.keys(item).sort().join(',') === 'href,label')) {
        var local = node('a', item.label, target); local.href = item.href; local.className = 'btn btn--ghost'; return;
      }
      if (Array.isArray(item)) {
        var named = item.every(changeRow), ordered = node(named ? 'div' : 'ol', undefined, target);
        item.slice(0, maximumEntries).forEach(function (entry) { append(node(named ? 'section' : 'li', undefined, ordered), entry, depth + 1); });
        if (item.length > maximumEntries) omitted(target);
        return;
      }
      if (changeRow(item)) {
        var heading = node('h4', undefined, target);
        append(heading, item.label, depth + 1);
        heading.style.whiteSpace = 'pre-wrap'; heading.style.overflowWrap = 'anywhere';
        if (Object.prototype.hasOwnProperty.call(item, 'before') && Object.prototype.hasOwnProperty.call(item, 'after')) {
          var values = node('dl', undefined, target);
          ['before', 'after'].forEach(function (key) {
            node('dt', key === 'before' ? 'Current' : 'Proposed', values);
            append(node('dd', undefined, values), item[key], depth + 1);
          });
        } else append(node('div', undefined, target), Object.prototype.hasOwnProperty.call(item, 'after') ? item.after : item.before, depth + 1);
        return;
      }
      var list = node('dl', undefined, target);
      var entries = Object.entries(item);
      if (entries.length > maximumEntries) omitted(target);
      entries.slice(0, maximumEntries).forEach(function (entry) {
        if (entry[0] === 'specialist_draft_author') {
          var specialistAuthor = entry[1];
          if (!specialistAuthor || Array.isArray(specialistAuthor) || Object.keys(specialistAuthor).sort().join(',') !== 'binding,context,name' ||
              !/^[a-f0-9]{64}$/.test(specialistAuthor.context || '') || !/^[a-f0-9]{64}$/.test(specialistAuthor.binding || '') ||
              !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(specialistAuthor.name || '')) return;
          var specialistControl = window.LWSpecialistDrafts;
          protectedControls(node('dd', undefined, list), 'Open complete specialist draft controls',
            '/agents?name=' + encodeURIComponent(specialistAuthor.name) + '#specialist-drafts',
            specialistControl && typeof specialistControl.openAuthor === 'function'
              ? function (isCurrent) { return specialistControl.openAuthor(specialistAuthor, {isCurrent: isCurrent}); } : null);
          return;
        }
        if (entry[0] === 'outcome_pilot_form') {
          var pilotForm = entry[1];
          if (!pilotForm || Array.isArray(pilotForm) || Object.keys(pilotForm).sort().join(',') !== 'action,case,context,pilot' ||
              typeof pilotForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(pilotForm.context) ||
              !['plan','prepare','observe','review','costs','value','history'].includes(pilotForm.action) ||
              typeof pilotForm.pilot !== 'string' || !/^(?:OPL-[a-f0-9]{48})?$/.test(pilotForm.pilot) ||
              typeof pilotForm.case !== 'string' || !/^(?:[1-9]\d?|100)?$/.test(pilotForm.case)) return;
          var pilotControl = window.LightworkOutcomePilots;
          protectedControls(node('dd', undefined, list), 'Open complete pilot controls',
            '/outcome-pilots' + (pilotForm.pilot ? '?pilot=' + encodeURIComponent(pilotForm.pilot) : ''),
            pilotControl && typeof pilotControl.open === 'function' ? function (isCurrent) { return pilotControl.open(pilotForm, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'chat_message_action') {
          var chatForm = entry[1];
          if (!chatForm || Array.isArray(chatForm) || Object.keys(chatForm).sort().join(',') !== 'action,context,goal,source' ||
              typeof chatForm.context !== 'string' || typeof chatForm.source !== 'string' ||
              !/^[a-f0-9]{64}$/.test(chatForm.context || '') || !/^[a-f0-9]{64}$/.test(chatForm.source || '') ||
              !Number.isSafeInteger(chatForm.goal) || chatForm.goal < 1 || !['retry','edit','branch'].includes(chatForm.action)) return;
          var chatControl = window.LightworkChatMessageActions;
          var chatLabel = {retry:'Try another answer', edit:'Edit and resend your message', branch:'Branch from a saved answer'}[chatForm.action];
          protectedControls(node('dd', undefined, list), chatLabel, '/chat/goal/' + chatForm.goal,
            chatControl && typeof chatControl.open === 'function' ? function (isCurrent) {
              return chatControl.open(chatForm.context, chatForm.goal, chatForm.action, chatForm.source, isCurrent);
            } : null);
          return;
        }
        if (entry[0] === 'decision_evidence_author') {
          var decisionForm = entry[1];
          if (!decisionForm || Array.isArray(decisionForm) || Object.keys(decisionForm).sort().join(',') !== 'binding,context,review' ||
              typeof decisionForm.context !== 'string' || typeof decisionForm.binding !== 'string' ||
              !/^[a-f0-9]{64}$/.test(decisionForm.context || '') || !/^[a-f0-9]{64}$/.test(decisionForm.binding || '') ||
              typeof decisionForm.review !== 'string' || !/^(?:SDE-[a-f0-9]{32})?$/.test(decisionForm.review)) return;
          var decisionControl = window.LWDecisionEvidence;
          protectedControls(node('dd', undefined, list), 'Open the complete decision form',
            '/decision-evidence' + (decisionForm.review ? '?review=' + encodeURIComponent(decisionForm.review) : '') + '#sde-editor',
            decisionControl && typeof decisionControl.openAuthor === 'function' ? function (isCurrent) {
              return decisionControl.openAuthor(decisionForm, {isCurrent:isCurrent});
            } : null);
          return;
        }
        if (entry[0] === 'privacy_discovery_review') {
          var discoveryReview = entry[1], discoveryControls = window.LightworkPrivacyDiscovery;
          if (!discoveryReview || Array.isArray(discoveryReview) ||
              Object.keys(discoveryReview).join(',') !== 'scope' || discoveryReview.scope !== 'current_page') return;
          protectedControls(node('dd', undefined, list), 'Open the protected scan controls',
            '/privacy/data-discovery#pdd-jobs',
            discoveryControls && typeof discoveryControls.openReview === 'function'
              ? function (isCurrent) { return discoveryControls.openReview({}, {isCurrent: isCurrent}); } : null);
          return;
        }
        if (entry[0] === 'chat_code_review') {
          var codeReview = entry[1], codeControls = window.LightworkChatCodeActions;
          var codeContext = catalog && catalog.context;
          if (!codeReview || Array.isArray(codeReview) ||
              Object.keys(codeReview).join(',') !== 'scope' || codeReview.scope !== 'current_page' ||
              typeof codeContext !== 'string' || !/^[a-f0-9]{64}$/.test(codeContext)) return;
          protectedControls(node('dd', undefined, list), 'Open the snippet copy controls',
            window.location.pathname,
            codeControls && typeof codeControls.openReview === 'function'
              ? function (isCurrent) { return codeControls.openReview({}, {isCurrent: isCurrent, context: codeContext}); } : null);
          return;
        }
        if (entry[0] === 'continuous_evidence_review') {
          var evidenceReview = entry[1], evidenceControls = window.LightworkContinuousEvidence;
          var evidenceContext = catalog && catalog.context;
          if (!evidenceReview || Array.isArray(evidenceReview) ||
              Object.keys(evidenceReview).join(',') !== 'scope' || evidenceReview.scope !== 'current_page' ||
              typeof evidenceContext !== 'string' || !/^[a-f0-9]{64}$/.test(evidenceContext)) return;
          protectedControls(node('dd', undefined, list), 'Open complete evidence controls',
            '/compliance/continuous-evidence#trc-root',
            evidenceControls && typeof evidenceControls.openReview === 'function'
              ? function (isCurrent) { return evidenceControls.openReview({}, {isCurrent: isCurrent, context: evidenceContext}); } : null);
          return;
        }
        if (entry[0] === 'policy_exception_review') {
          var exceptionReview = entry[1], exceptionControls = window.LightworkPolicyExceptions;
          var exceptionContext = catalog && catalog.context;
          if (!exceptionReview || Array.isArray(exceptionReview) ||
              Object.keys(exceptionReview).join(',') !== 'scope' || exceptionReview.scope !== 'current_page' ||
              typeof exceptionContext !== 'string' || !/^[a-f0-9]{64}$/.test(exceptionContext)) return;
          protectedControls(node('dd', undefined, list), 'Review AI-use exceptions and safeguards',
            '/security/assurance#ai-policy-exception-request',
            exceptionControls && typeof exceptionControls.openReview === 'function'
              ? function (isCurrent) { return exceptionControls.openReview({}, {isCurrent: isCurrent, context: exceptionContext}); } : null);
          return;
        }
        if (entry[0] === 'learning_question_check_form') {
          var questionCheckReview = entry[1], questionCheckControls = window.LightworkLearningQuestionChecks;
          if (!questionCheckReview || Array.isArray(questionCheckReview) ||
              Object.keys(questionCheckReview).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(questionCheckReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review the complete question check',
            '/learned#learning-question-checks',
            questionCheckControls && typeof questionCheckControls.open === 'function'
              ? function (isCurrent) { return questionCheckControls.open(questionCheckReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'action_center_form') {
          var attentionReview = entry[1], attentionControls = window.LightworkActionCenter;
          if (!attentionReview || Array.isArray(attentionReview) ||
              Object.keys(attentionReview).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(attentionReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open current decisions needing attention',
            '/action-center#ac-items',
            attentionControls && typeof attentionControls.open === 'function'
              ? function (isCurrent) { return attentionControls.open(attentionReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'privacy_data_use_bridge_form') {
          var discoveryUseReview = entry[1], discoveryUseControls = window.LightworkDiscoveryDataUse;
          if (!discoveryUseReview || Array.isArray(discoveryUseReview) ||
              Object.keys(discoveryUseReview).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(discoveryUseReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review findings for a saved dataset',
            '/privacy/data-discovery#pddb-root',
            discoveryUseControls && typeof discoveryUseControls.openReview === 'function'
              ? function (isCurrent) { return discoveryUseControls.openReview(discoveryUseReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'third_party_alert_setup_form') {
          var vendorAlertReview = entry[1], vendorAlertControls = window.LightworkThirdPartyAlerts;
          if (!vendorAlertReview || Array.isArray(vendorAlertReview) ||
              Object.keys(vendorAlertReview).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(vendorAlertReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open vendor-alert recipient setup',
            '/third-party/intelligence#tpi-recipient-setup',
            vendorAlertControls && typeof vendorAlertControls.openReview === 'function'
              ? function (isCurrent) { return vendorAlertControls.openReview(vendorAlertReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'consent_delivery_review') {
          var consentDeliveryReview = entry[1], consentDeliveryControls = window.LightworkConsentDelivery;
          if (!consentDeliveryReview || Array.isArray(consentDeliveryReview) ||
              Object.keys(consentDeliveryReview).sort().join(',') !== 'context,scope' ||
              consentDeliveryReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(consentDeliveryReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open complete consent delivery controls',
            '/consent/delivery#cd-managed',
            consentDeliveryControls && typeof consentDeliveryControls.openReview === 'function'
              ? function (isCurrent) { return consentDeliveryControls.openReview({}, {isCurrent: isCurrent, context: consentDeliveryReview.context}); } : null);
          return;
        }
        if (entry[0] === 'research_execution_review') {
          var researchExecutionReview = entry[1], researchExecutionControls = window.LightworkResearchExecution;
          if (!researchExecutionReview || Array.isArray(researchExecutionReview) ||
              Object.keys(researchExecutionReview).sort().join(',') !== 'context,scope' ||
              researchExecutionReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(researchExecutionReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open complete research run controls',
            '/research#research-run-form',
            researchExecutionControls && typeof researchExecutionControls.openReview === 'function'
              ? function (isCurrent) { return researchExecutionControls.openReview({}, {isCurrent: isCurrent, context: researchExecutionReview.context}); } : null);
          return;
        }
        if (entry[0] === 'audit_checkpoint_custody_form') {
          var checkpointCustodyForm = entry[1], checkpointCustodyControls = window.LightworkAuditCheckpointCustody;
          if (!checkpointCustodyForm || Array.isArray(checkpointCustodyForm) ||
              Object.keys(checkpointCustodyForm).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(checkpointCustodyForm.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review independent history protection',
            '/audit#independent-checkpoint-custody',
            checkpointCustodyControls && typeof checkpointCustodyControls.openReview === 'function'
              ? function (isCurrent) { return checkpointCustodyControls.openReview(checkpointCustodyForm.context, {isCurrent: isCurrent}); } : null);
          return;
        }
        if (entry[0] === 'personal_push_setup') {
          var privatePushSetup = entry[1], privatePushControls = window.LightworkPersonalPush;
          if (!privatePushSetup || Array.isArray(privatePushSetup) ||
              Object.keys(privatePushSetup).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(privatePushSetup.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open private notification setup',
            '/notifications#private-device-setup',
            privatePushControls && typeof privatePushControls.openReview === 'function'
              ? function (isCurrent) { return privatePushControls.openReview(privatePushSetup.context, {isCurrent: isCurrent}); } : null);
          return;
        }
        if (entry[0] === 'instruction_suggestion_form') {
          var instructionSuggestionForm = entry[1], instructionSuggestionControls = window.LightworkLearningInstructions;
          if (!instructionSuggestionForm || Array.isArray(instructionSuggestionForm) ||
              Object.keys(instructionSuggestionForm).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(instructionSuggestionForm.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open the instruction suggestion form',
            '/learned#llp-propose-box',
            instructionSuggestionControls && typeof instructionSuggestionControls.openSuggestion === 'function'
              ? function (isCurrent) { return instructionSuggestionControls.openSuggestion(instructionSuggestionForm.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'learning_case_import_form') {
          var caseImportForm = entry[1], caseImportControls = window.LightworkLearnedCaseImport;
          if (!caseImportForm || Array.isArray(caseImportForm) ||
              Object.keys(caseImportForm).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(caseImportForm.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open the question import form',
            '/learned#learning-case-import',
            caseImportControls && typeof caseImportControls.open === 'function'
              ? function (isCurrent) { return caseImportControls.open(caseImportForm.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'learning_code_practice_form') {
          var codePracticeForm = entry[1], codePracticeControls = window.LightworkLearningOps;
          if (!codePracticeForm || Array.isArray(codePracticeForm) ||
              Object.keys(codePracticeForm).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(codePracticeForm.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open code practice',
            '/learning#lo-sm-form',
            codePracticeControls && typeof codePracticeControls.openCodePractice === 'function'
              ? function (isCurrent) { return codePracticeControls.openCodePractice(codePracticeForm.context, isCurrent); } : null);
          return;
        }
        if (['ekko_recording_review', 'ekko_discovery_review', 'ekko_planning_review'].includes(entry[0])) {
          var ekkoPlanning = entry[0] === 'ekko_planning_review';
          var ekkoDiscovery = entry[0] === 'ekko_discovery_review';
          var ekkoOpenMethod = ekkoPlanning ? 'openPlanning' : ekkoDiscovery ? 'openDiscovery' : 'openReview';
          var ekkoRecordingReview = entry[1], ekkoRecordingControls = window.LightworkEkkoRecording;
          if (!ekkoRecordingReview || Array.isArray(ekkoRecordingReview) ||
              Object.keys(ekkoRecordingReview).sort().join(',') !== 'context,scope' ||
              ekkoRecordingReview.scope !== 'current_page' ||
              !/^[a-f0-9]{64}$/.test(ekkoRecordingReview.context || '')) return;
          protectedControls(node('dd', undefined, list), ekkoPlanning ? 'Open private opportunity plans' : ekkoDiscovery ? 'Review repeated work' : 'Review activity recording permissions',
            ekkoPlanning ? '/ekko#ekko-planning' : ekkoDiscovery ? '/ekko#ekko-opportunities-heading' : '/ekko#ekko-recording',
            ekkoRecordingControls && typeof ekkoRecordingControls[ekkoOpenMethod] === 'function'
              ? function (isCurrent) { return ekkoRecordingControls[ekkoOpenMethod]({}, {context: ekkoRecordingReview.context, isCurrent: isCurrent}); } : null);
          return;
        }
        if (entry[0] === 'agent_activity_form') {
          var agentActivityForm = entry[1], agentActivityControls = window.LightworkAgentActivity;
          if (!agentActivityForm || Array.isArray(agentActivityForm) ||
              Object.keys(agentActivityForm).sort().join(',') !== 'context,name,revision' ||
              !/^[a-f0-9]{64}$/.test(agentActivityForm.context || '') ||
              !/^[a-f0-9]{64}$/.test(agentActivityForm.revision || '') ||
              !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(agentActivityForm.name || '')) return;
          protectedControls(node('dd', undefined, list), 'Open this specialist’s recent work',
            '/agents?name=' + encodeURIComponent(agentActivityForm.name) + '#agent-recent-work',
            agentActivityControls && typeof agentActivityControls.open === 'function'
              ? function (isCurrent) { return agentActivityControls.open(agentActivityForm.context, agentActivityForm.name, agentActivityForm.revision, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'work_record_details_review') {
          var workDetailsReview = entry[1], workDetailsControls = window.LightworkWorkRecordDetails;
          if (!workDetailsReview || Array.isArray(workDetailsReview) ||
              Object.keys(workDetailsReview).sort().join(',') !== 'context,scope' ||
              workDetailsReview.scope !== 'current_page' ||
              !/^[a-f0-9]{64}$/.test(workDetailsReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Open business fields and stages',
            '/work-details',
            workDetailsControls && typeof workDetailsControls.openReview === 'function'
              ? function (isCurrent) { return workDetailsControls.openReview({}, {isCurrent: isCurrent, context: workDetailsReview.context}); } : null);
          return;
        }
        if (entry[0] === 'report_schedule_form') {
          var reportScheduleForm = entry[1], reportScheduleControls = window.LightworkExecutiveReportSchedules;
          if (!reportScheduleForm || Array.isArray(reportScheduleForm) ||
              Object.keys(reportScheduleForm).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(reportScheduleForm.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review recurring report setup',
            '/third-party/executive-reports#tper-schedules',
            reportScheduleControls && typeof reportScheduleControls.open === 'function'
              ? function (isCurrent) { return reportScheduleControls.open(reportScheduleForm.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'report_starting_point') {
          var reportStartingPoint = entry[1], reportStartingControls = window.LightworkExecutiveReports;
          if (!reportStartingPoint || Array.isArray(reportStartingPoint) ||
              Object.keys(reportStartingPoint).sort().join(',') !== 'context,report,revision' ||
              !/^[a-f0-9]{64}$/.test(reportStartingPoint.context || '') ||
              !/^[a-f0-9]{64}$/.test(reportStartingPoint.revision || '') ||
              !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(reportStartingPoint.report || '')) return;
          protectedControls(node('dd', undefined, list), 'Review saved report choices',
            '/third-party/executive-reports#tper-editor',
            reportStartingControls && typeof reportStartingControls.openStartingPoint === 'function'
              ? function (isCurrent) { return reportStartingControls.openStartingPoint(reportStartingPoint.context, reportStartingPoint.report, reportStartingPoint.revision, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'product_tour_review') {
          var productTourReview = entry[1], productTourControls = window.LightworkProductTour;
          if (!productTourReview || Array.isArray(productTourReview) ||
              Object.keys(productTourReview).sort().join(',') !== 'context,scope' ||
              productTourReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(productTourReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Take a quick tour of this page',
            '/start#product-tour',
            productTourControls && typeof productTourControls.openReview === 'function'
              ? function (isCurrent) { return productTourControls.openReview({}, {isCurrent: isCurrent, context: productTourReview.context}); } : null);
          return;
        }
        if (entry[0] === 'runtime_enforcement_form') {
          var safeguardReview = entry[1], safeguardControls = window.LightworkRuntimeEnforcement;
          if (!safeguardReview || Array.isArray(safeguardReview) ||
              Object.keys(safeguardReview).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(safeguardReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Read actual safeguard activity',
            '/security/governance#runtime-enforcement',
            safeguardControls && typeof safeguardControls.open === 'function'
              ? function (isCurrent) { return safeguardControls.open(safeguardReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'dsar_handling_review') {
          var privacyHandlingReview = entry[1], privacyHandlingControls = window.LightworkDSARHandling;
          if (!privacyHandlingReview || Array.isArray(privacyHandlingReview) ||
              Object.keys(privacyHandlingReview).sort().join(',') !== 'context,scope' ||
              privacyHandlingReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(privacyHandlingReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review the complete action and response',
            window.location.pathname + '#dsar-status',
            privacyHandlingControls && typeof privacyHandlingControls.openReview === 'function'
              ? function (isCurrent) { return privacyHandlingControls.openReview({}, {isCurrent: isCurrent, context: privacyHandlingReview.context}); } : null);
          return;
        }
        if (entry[0] === 'learning_task_question_review') {
          var taskQuestionReview = entry[1], taskQuestionControls = window.LightworkLearningQuestions;
          if (!taskQuestionReview || Array.isArray(taskQuestionReview) ||
              Object.keys(taskQuestionReview).sort().join(',') !== 'context,scope' ||
              taskQuestionReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(taskQuestionReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review a question from your completed work',
            '/learned#learning-test-questions',
            taskQuestionControls && typeof taskQuestionControls.openTaskReview === 'function'
              ? function (isCurrent) { return taskQuestionControls.openTaskReview(taskQuestionReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'connections_key_review') {
          var keyReview = entry[1], keyControls = window.LightworkConnections;
          if (!keyReview || Array.isArray(keyReview) ||
              Object.keys(keyReview).sort().join(',') !== 'context,scope' ||
              keyReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(keyReview.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Choose a service and review its key setup',
            '/connections#cx-form',
            keyControls && typeof keyControls.openReview === 'function'
              ? function (isCurrent) { return keyControls.openReview(keyReview.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'mail_connection_review') {
          var mailReview = entry[1], mailControls = window.LightworkConnectionSetup;
          if (!mailReview || Array.isArray(mailReview) ||
              Object.keys(mailReview).sort().join(',') !== 'scope,workspace_context' ||
              mailReview.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(mailReview.workspace_context || '')) return;
          protectedControls(node('dd', undefined, list), 'Review Microsoft 365 account setup',
            '/connections#connection-setup',
            mailControls && typeof mailControls.openReview === 'function'
              ? function (isCurrent) { return mailControls.openReview({profile: 'microsoft-mail'}, {isCurrent: isCurrent, context: mailReview.workspace_context}); } : null);
          return;
        }
        if (entry[0] === 'schedule_creation_original') {
          var scheduleOriginal = entry[1], scheduleOriginalControls = window.LightworkScheduleCreation;
          if (!scheduleOriginal || Array.isArray(scheduleOriginal) ||
              Object.keys(scheduleOriginal).sort().join(',') !== 'context,scope' ||
              scheduleOriginal.scope !== 'current_page' || !/^[a-f0-9]{64}$/.test(scheduleOriginal.context || '')) return;
          protectedControls(node('dd', undefined, list), 'Check the original schedule result',
            '/automations#auto-create-original',
            scheduleOriginalControls && typeof scheduleOriginalControls.openOriginal === 'function'
              ? function (isCurrent) { return scheduleOriginalControls.openOriginal(scheduleOriginal.context, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'schedule_creation_review') {
          var scheduleReview = entry[1], scheduleControls = window.LightworkScheduleSetup;
          var scheduleContext = catalog && catalog.context;
          if (!scheduleReview || Array.isArray(scheduleReview) ||
              Object.keys(scheduleReview).join(',') !== 'scope' || scheduleReview.scope !== 'current_page' ||
              typeof scheduleContext !== 'string' || !/^[a-f0-9]{64}$/.test(scheduleContext)) return;
          protectedControls(node('dd', undefined, list), 'Choose work and review its schedule',
            '/automations#auto-new-sched',
            scheduleControls && typeof scheduleControls.openReview === 'function'
              ? function (isCurrent) { return scheduleControls.openReview({}, {isCurrent: isCurrent, context: scheduleContext}); } : null);
          return;
        }
        if (entry[0] === 'factory_guidance_author') {
          var factoryAuthor = entry[1], factoryControls = window.LWFactoryGuidance;
          var factoryContext = catalog && catalog.context;
          if (!factoryAuthor || Array.isArray(factoryAuthor) ||
              Object.keys(factoryAuthor).join(',') !== 'scope' || factoryAuthor.scope !== 'current_page' ||
              typeof factoryContext !== 'string' || !/^[a-f0-9]{64}$/.test(factoryContext)) return;
          protectedControls(node('dd', undefined, list), 'Review how new agents are built',
            '/learning#lo-factory',
            factoryControls && typeof factoryControls.openAuthor === 'function'
              ? function (isCurrent) { return factoryControls.openAuthor({}, {isCurrent: isCurrent, context: factoryContext}); } : null);
          return;
        }
        if (entry[0] === 'calibration_review') {
          var calibrationReview = entry[1], calibrationControls = window.LightworkLearningCalibration;
          var calibrationContext = catalog && catalog.context;
          if (!calibrationReview || Array.isArray(calibrationReview) ||
              Object.keys(calibrationReview).join(',') !== 'scope' || calibrationReview.scope !== 'current_page' ||
              typeof calibrationContext !== 'string' || !/^[a-f0-9]{64}$/.test(calibrationContext)) return;
          protectedControls(node('dd', undefined, list), 'Review answer checking',
            '/learned#learning-calibration',
            calibrationControls && typeof calibrationControls.openReview === 'function'
              ? function (isCurrent) { return calibrationControls.openReview({}, {isCurrent: isCurrent, context: calibrationContext}); } : null);
          return;
        }
        if (entry[0] === 'learning_transfer_form') {
          var transferForm = entry[1], transferControls = window.LightworkLearningTransfers;
          if (!transferForm || Array.isArray(transferForm) ||
              Object.keys(transferForm).sort().join(',') !== 'context,original' ||
              !/^[a-f0-9]{64}$/.test(transferForm.context || '') ||
              typeof transferForm.original !== 'boolean') return;
          var transferSelection = context();
          if (transferForm.original && (transferSelection.kind !== 'learning_transfer' ||
              !/^[a-f0-9]{32}$/.test(transferSelection.operation || ''))) return;
          var transferHref = '/learned' + (transferForm.original ? '?learning_transfer=' +
            encodeURIComponent(transferSelection.operation) : '') + '#learning-transfers';
          protectedControls(node('dd', undefined, list),
            transferForm.original ? 'Read this original lesson test' : 'Review a lesson test', transferHref,
            transferControls && typeof transferControls.open === 'function'
              ? function (isCurrent) { return transferControls.open(transferForm.context, transferForm.original, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'continuous_evidence_source_review') {
          var sourceReview = entry[1], sourceControls = window.LightworkContinuousEvidence;
          var sourceContext = catalog && catalog.context;
          if (!sourceReview || Array.isArray(sourceReview) ||
              Object.keys(sourceReview).join(',') !== 'scope' || sourceReview.scope !== 'current_page' ||
              typeof sourceContext !== 'string' || !/^[a-f0-9]{64}$/.test(sourceContext)) return;
          protectedControls(node('dd', undefined, list), 'Open evidence source setup',
            '/compliance/continuous-evidence#trc-source-form',
            sourceControls && typeof sourceControls.openSourceReview === 'function'
              ? function (isCurrent) { return sourceControls.openSourceReview({}, {isCurrent: isCurrent, context: sourceContext}); } : null);
          return;
        }
        if (entry[0] === 'webhook_subscription_review') {
          var webhookReview = entry[1], webhookControls = window.LightworkWebhookSubscriptions;
          var webhookContext = catalog && catalog.context;
          if (!webhookReview || Array.isArray(webhookReview) ||
              Object.keys(webhookReview).join(',') !== 'scope' || webhookReview.scope !== 'current_page' ||
              typeof webhookContext !== 'string' || !/^[a-f0-9]{64}$/.test(webhookContext)) return;
          protectedControls(node('dd', undefined, list), 'Open the complete update controls',
            '/settings/webhooks/manage#wh-form',
            webhookControls && typeof webhookControls.openReview === 'function'
              ? function (isCurrent) { return webhookControls.openReview({}, {isCurrent: isCurrent, context: webhookContext}); } : null);
          return;
        }
        if (entry[0] === 'channels_people') {
          var channelPeople = entry[1], channelStarted = generation, channelSelection = JSON.stringify(context());
          if (!channelPeople || Array.isArray(channelPeople) || Object.keys(channelPeople).sort().join(',') !== 'channel,context' ||
              typeof channelPeople.context !== 'string' || !/^[a-f0-9]{64}$/.test(channelPeople.context) ||
              !['telegram','discord','slack','whatsapp_cloud','sms','email','mattermost','teams'].includes(channelPeople.channel)) return;
          var channelDestination = node('dd', undefined, list), channelForm = window.LightworkChannelPeople;
          if (channelForm && typeof channelForm.open === 'function') button('Review who may message Lightwork', channelDestination, async function (event) {
            var isCurrent = function () { return active(channelStarted) && JSON.stringify(context()) === channelSelection; };
            if (!isCurrent() || busy) return;
            var channelButton = event.currentTarget; channelButton.disabled = true;
            try {
              var opened = await channelForm.open(channelPeople.context, channelPeople.channel, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected current and replacement lists are open.' : 'The current form or access changed. Review Channels before saving.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The access controls could not be opened. Check the current list in Channels.'; }
            finally { if (isCurrent() && channelButton.isConnected) channelButton.disabled = false; }
          });
          else {
            var channelLink = node('a', 'Review who may message Lightwork', channelDestination);
            channelLink.href = '/channels#channel-' + channelPeople.channel;
            channelLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'commitment_capability_author') {
          var capabilityAuthor = entry[1], capabilityStarted = generation, capabilitySelection = JSON.stringify(context());
          if (!capabilityAuthor || Array.isArray(capabilityAuthor) || Object.keys(capabilityAuthor).sort().join(',') !== 'context,parent,parent_binding' ||
              !/^[a-f0-9]{64}$/.test(capabilityAuthor.context || '') || !/^[a-f0-9]{64}$/.test(capabilityAuthor.parent_binding || '') ||
              !/^CMV-[a-f0-9]{48}$/.test(capabilityAuthor.parent || '')) return;
          var capabilityDestination = node('dd', undefined, list), capabilityForm = window.LWCommitmentCapability;
          if (capabilityForm && typeof capabilityForm.openAuthor === 'function') button('Open the complete additional-work form', capabilityDestination, async function (event) {
            var isCurrent = function () { return active(capabilityStarted) && JSON.stringify(context()) === capabilitySelection; };
            if (!isCurrent() || busy) return;
            var capabilityButton = event.currentTarget; capabilityButton.disabled = true;
            try {
              var opened = await capabilityForm.openAuthor(capabilityAuthor, {isCurrent:isCurrent});
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete additional-work form is open; your entered choices were kept.' : 'The selected work or current form changed. Review Promise reviews before continuing.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The additional-work form could not be opened. Check current Promise reviews.'; }
            finally { if (isCurrent() && capabilityButton.isConnected) capabilityButton.disabled = false; }
          });
          else {
            var capabilityLink = node('a', 'Open the complete additional-work form', capabilityDestination);
            capabilityLink.href = '/commitment-reviews?review=' + encodeURIComponent(capabilityAuthor.parent) + '#ccl-author';
            capabilityLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'portable_rule_form' || entry[0] === 'work_grouping_form') {
          var localForm = entry[1], localStarted = generation, localSelection = JSON.stringify(context());
          var portable = entry[0] === 'portable_rule_form';
          if (!localForm || Array.isArray(localForm) || Object.keys(localForm).sort().join(',') !== (portable ? 'context,flow,view' : 'context,flow') ||
              typeof localForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(localForm.context) ||
              typeof localForm.flow !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(localForm.flow) ||
              (portable && localForm.view !== 'qualify')) return;
          var localDestination = node('dd', undefined, list);
          var localControl = portable ? window.LightworkPortableRules : window.LightworkWorkGrouping;
          var localLabel = portable ? 'Open complete target qualification controls' : 'Open separate case groups and deadlines';
          if (localControl && typeof localControl.open === 'function') button(localLabel, localDestination, async function (event) {
            var isCurrent = function () { return active(localStarted) && JSON.stringify(context()) === localSelection; };
            if (!isCurrent() || busy) return;
            var localButton = event.currentTarget; localButton.disabled = true;
            try {
              var opened = await localControl.open(localForm, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected controls are open.' : 'Your current work is kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The controls could not be opened. Your current work is kept.'; }
            finally { if (isCurrent() && localButton.isConnected) localButton.disabled = false; }
          });
          else {
            var localLink = node('a', localLabel, localDestination);
            localLink.href = (portable ? '/learning/portable-rules?view=qualify&flow=' : '/learning/work-restructuring?flow=') + encodeURIComponent(localForm.flow);
            localLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'private_task_computation_author') {
          var privateAuthor = entry[1], privateStarted = generation, privateSelection = JSON.stringify(context());
          if (!privateAuthor || Array.isArray(privateAuthor) || Object.keys(privateAuthor).sort().join(',') !== 'binding,context,id' ||
              typeof privateAuthor.context !== 'string' || !/^[a-f0-9]{64}$/.test(privateAuthor.context) ||
              !((privateAuthor.id === null && privateAuthor.binding === null) ||
                (typeof privateAuthor.id === 'string' && /^PTC-[a-f0-9]{32}$/.test(privateAuthor.id) &&
                 typeof privateAuthor.binding === 'string' && /^[a-f0-9]{64}$/.test(privateAuthor.binding)))) return;
          var privateDestination = node('dd', undefined, list), privateControl = window.LWPrivateTaskComputation;
          var privateLabel = privateAuthor.id ? 'Open all private calculation choices' : 'Open the complete private calculation form';
          if (privateControl && typeof privateControl.openAuthor === 'function') button(privateLabel, privateDestination, async function (event) {
            var isCurrent = function () { return active(privateStarted) && JSON.stringify(context()) === privateSelection; };
            if (!isCurrent() || busy) return;
            var privateButton = event.currentTarget; privateButton.disabled = true;
            try {
              var opened = await privateControl.openAuthor(privateAuthor, {isCurrent: isCurrent});
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected form is open.' : 'Your current draft is kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The form could not be opened. Your current draft is kept.'; }
            finally { if (isCurrent() && privateButton.isConnected) privateButton.disabled = false; }
          });
          else {
            var privateLink = node('a', privateLabel, privateDestination);
            privateLink.href = '/private-task-computation' + (privateAuthor.id ? '?check=' + encodeURIComponent(privateAuthor.id) : '') + '#ptc-author';
            privateLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'recovery_visibility_form') {
          var visibilityForm = entry[1], visibilityStarted = generation, visibilitySelection = JSON.stringify(context());
          if (!visibilityForm || Array.isArray(visibilityForm) || Object.keys(visibilityForm).join(',') !== 'context' ||
              typeof visibilityForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(visibilityForm.context)) return;
          var visibilityDestination = node('dd', undefined, list), visibilityControl = window.LightworkRecoveryVisibility;
          if (visibilityControl && typeof visibilityControl.open === 'function') button('Open complete local practice controls', visibilityDestination, async function (event) {
            var isCurrent = function () { return active(visibilityStarted) && JSON.stringify(context()) === visibilitySelection; };
            if (!isCurrent() || busy) return;
            var visibilityButton = event.currentTarget; visibilityButton.disabled = true;
            try {
              var opened = await visibilityControl.open(visibilityForm.context, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected practice controls are open.' : 'Your current work is kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The practice controls could not be opened. Your current work is kept.'; }
            finally { if (isCurrent() && visibilityButton.isConnected) visibilityButton.disabled = false; }
          });
          else { var visibilityLink = node('a', 'Open complete local practice controls', visibilityDestination); visibilityLink.href = '/learning/recovery-visibility'; visibilityLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'runtime_policy_recovery') {
          var policyForm = entry[1], policyStarted = generation, policySelection = JSON.stringify(context());
          if (!policyForm || Array.isArray(policyForm) || Object.keys(policyForm).sort().join(',') !== 'context,original' ||
              typeof policyForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(policyForm.context) || typeof policyForm.original !== 'boolean') return;
          var policyDestination = node('dd', undefined, list), policyControl = window.LightworkRuntimePolicyRecovery;
          var policyLabel = policyForm.original ? 'Read my original safety settings restoration' : 'Open complete saved safety settings';
          if (policyControl && typeof policyControl.open === 'function') button(policyLabel, policyDestination, async function (event) {
            var isCurrent = function () { return active(policyStarted) && JSON.stringify(context()) === policySelection; };
            if (!isCurrent() || busy) return;
            var policyButton = event.currentTarget; policyButton.disabled = true;
            try {
              var opened = await policyControl.open(policyForm.context, policyForm.original, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected safety settings controls are open.' : 'Your current choices are kept. Reload Help to review current access and saved copies.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The safety settings controls could not be opened. Your current choices are kept.'; }
            finally { if (isCurrent() && policyButton.isConnected) policyButton.disabled = false; }
          });
          else { var policyLink = node('a', policyLabel, policyDestination); policyLink.href = '/help#runtime-policy-recovery'; policyLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'installation_health') {
          var healthForm = entry[1], healthStarted = generation, healthSelection = JSON.stringify(context());
          if (!healthForm || Array.isArray(healthForm) || Object.keys(healthForm).join(',') !== 'context' ||
              typeof healthForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(healthForm.context)) return;
          var healthDestination = node('dd', undefined, list), healthControl = window.LightworkInstallationHealth;
          if (healthControl && typeof healthControl.open === 'function') button('Open installation health checks', healthDestination, async function (event) {
            var isCurrent = function () { return active(healthStarted) && JSON.stringify(context()) === healthSelection; };
            if (!isCurrent() || busy) return;
            var healthButton = event.currentTarget; healthButton.disabled = true;
            try {
              var opened = await healthControl.open(healthForm.context, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected health controls are open. Review and start the checks there.' : 'The current installation or access changed. Reload Help to review the checks.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The health controls could not be opened. Open Help to review the current checks.'; }
            finally { if (isCurrent() && healthButton.isConnected) healthButton.disabled = false; }
          });
          else { var healthLink = node('a', 'Open installation health checks', healthDestination); healthLink.href = '/help#installation-health'; healthLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'company_saml_setup') {
          var samlForm = entry[1], samlControl = window.LightworkCompanySamlSetup;
          if (!samlForm || Array.isArray(samlForm) || Object.keys(samlForm).sort().join(',') !== 'context,original' ||
              typeof samlForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(samlForm.context) || typeof samlForm.original !== 'boolean') return;
          protectedControls(node('dd', undefined, list), 'Open complete single sign-on setup',
            '/settings/all#company-saml-setup', samlControl && typeof samlControl.open === 'function'
              ? function (isCurrent) { return samlControl.open(samlForm.context, samlForm.original, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'channel_message_test') {
          var channelTest = entry[1], channelTestControl = window.LightworkChannelMessageTests;
          if (!channelTest || Array.isArray(channelTest) || Object.keys(channelTest).sort().join(',') !== 'channel,context' ||
              typeof channelTest.context !== 'string' || !/^[a-f0-9]{64}$/.test(channelTest.context) ||
              !['telegram', 'discord', 'whatsapp_cloud', 'mattermost'].includes(channelTest.channel)) return;
          protectedControls(node('dd', undefined, list), 'Open the complete channel message test',
            '/channels#channel-message-tests', channelTestControl && typeof channelTestControl.open === 'function'
              ? function (isCurrent) { return channelTestControl.open(channelTest.context, channelTest.channel, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'company_signin_migration') {
          var signinForm = entry[1], signinControl = window.LightworkCompanySigninMigration;
          if (!signinForm || Array.isArray(signinForm) || Object.keys(signinForm).sort().join(',') !== 'context,original' ||
              typeof signinForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(signinForm.context) || typeof signinForm.original !== 'boolean') return;
          protectedControls(node('dd', undefined, list), 'Open reviewed company sign-in controls',
            '/settings/all#company-signin-migration', signinControl && typeof signinControl.open === 'function'
              ? function (isCurrent) { return signinControl.open(signinForm.context, signinForm.original, isCurrent); } : null);
          return;
        }
        if (entry[0] === 'settings_catalog_form') {
          var catalogForm = entry[1], catalogStarted = generation, catalogSelection = JSON.stringify(context());
          if (!catalogForm || Array.isArray(catalogForm) || Object.keys(catalogForm).sort().join(',') !== 'context,original' ||
              typeof catalogForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(catalogForm.context) || typeof catalogForm.original !== 'boolean') return;
          var catalogDestination = node('dd', undefined, list), catalogControl = window.LightworkSettingsCatalog;
          var catalogLabel = catalogForm.original ? 'Read my original settings requests' : 'Open protected organization settings';
          if (catalogControl && typeof catalogControl.open === 'function') button(catalogLabel, catalogDestination, async function (event) {
            var isCurrent = function () { return active(catalogStarted) && JSON.stringify(context()) === catalogSelection; };
            if (!isCurrent() || busy) return;
            var catalogButton = event.currentTarget; catalogButton.disabled = true;
            try {
              var opened = await catalogControl.open(catalogForm.context, catalogForm.original, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected settings controls are open.' : 'Your entered work is kept. Refresh the current settings before continuing.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The settings controls could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && catalogButton.isConnected) catalogButton.disabled = false; }
          });
          else { var catalogLink = node('a', catalogLabel, catalogDestination); catalogLink.href = catalogForm.original ? '/settings/all#settings-original-requests' : '/settings/all'; catalogLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'applicability_form') {
          var regionForm = entry[1], regionStarted = generation, regionSelection = JSON.stringify(context());
          if (!regionForm || Array.isArray(regionForm) || Object.keys(regionForm).sort().join(',') !== 'context,flow,original' ||
              typeof regionForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(regionForm.context) ||
              typeof regionForm.flow !== 'string' || regionForm.flow.length < 1 || regionForm.flow.length > 128 ||
              typeof regionForm.original !== 'string' || regionForm.original && !/^APR-[a-f0-9]{32}$/.test(regionForm.original)) return;
          var regionDestination = node('dd', undefined, list), regionControl = window.LightworkApplicabilityRegions;
          if (regionControl && typeof regionControl.open === 'function') button('Open complete checked answer regions', regionDestination, async function (event) {
            var isCurrent = function () { return active(regionStarted) && JSON.stringify(context()) === regionSelection; };
            if (!isCurrent() || busy) return;
            var regionButton = event.currentTarget; regionButton.disabled = true;
            try {
              var opened = await regionControl.open(regionForm, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete checked answer form is open.' : 'Your entered work is kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The checked answer form could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && regionButton.isConnected) regionButton.disabled = false; }
          });
          else { var regionLink = node('a', 'Open complete checked answer regions', regionDestination); regionLink.href = '/learning/applicability?' + new URLSearchParams({flow: regionForm.flow, original: regionForm.original}).toString() + '#apr-author-h'; regionLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'capability_assessment') {
          var assessmentForm = entry[1], assessmentStarted = generation, assessmentSelection = JSON.stringify(context());
          if (!assessmentForm || Array.isArray(assessmentForm) || Object.keys(assessmentForm).sort().join(',') !== 'context,kind,review,revision,source,subject' ||
              !/^[a-f0-9]{64}$/.test(assessmentForm.context || '') || !/^[a-f0-9]{64}$/.test(assessmentForm.source || '') ||
              !['agent', 'flow'].includes(assessmentForm.kind) || typeof assessmentForm.subject !== 'string' ||
              !assessmentForm.subject || assessmentForm.subject.length > 256 || !Number.isSafeInteger(assessmentForm.revision) ||
              assessmentForm.revision < 0 || typeof assessmentForm.review !== 'boolean') return;
          var assessmentDestination = node('dd', undefined, list), assessmentControls = window.LightworkCapabilityAssessments;
          var assessmentLabel = assessmentForm.review ? 'Open the complete assessment review' : 'Read the complete assessment findings';
          if (window.location.pathname === '/assessments' && assessmentControls && typeof assessmentControls.open === 'function') button(assessmentLabel, assessmentDestination, async function (event) {
            var isCurrent = function () { return active(assessmentStarted) && JSON.stringify(context()) === assessmentSelection; };
            if (!isCurrent() || busy) return;
            var assessmentButton = event.currentTarget; assessmentButton.disabled = true;
            try {
              var opened = await assessmentControls.open(assessmentForm.context, assessmentForm.kind, assessmentForm.subject,
                assessmentForm.revision, assessmentForm.source, assessmentForm.review, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete current assessment is open. Review any decision there.' : 'Your current work is kept. Check the selected assessment and access again.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The assessment could not be opened. Your current review is kept.'; }
            finally { if (isCurrent() && assessmentButton.isConnected) assessmentButton.disabled = false; }
          });
          else { var assessmentLink = node('a', assessmentLabel, assessmentDestination); assessmentLink.href = '/assessments'; assessmentLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'report_download') {
          var reportForm = entry[1], reportStarted = generation, reportSelection = JSON.stringify(context());
          if (!reportForm || Array.isArray(reportForm) || Object.keys(reportForm).sort().join(',') !== 'context,kind' ||
              typeof reportForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(reportForm.context) ||
              !['soc2', 'ai_inventory', 'oscal', 'soa', 'public_key'].includes(reportForm.kind)) return;
          var reportDestination = node('dd', undefined, list), reportControls = window.LightworkReportDownloads;
          if (reportControls && typeof reportControls.open === 'function') button('Open the protected download controls', reportDestination, async function (event) {
            var isCurrent = function () { return active(reportStarted) && JSON.stringify(context()) === reportSelection; };
            if (!isCurrent() || busy) return;
            var reportButton = event.currentTarget; reportButton.disabled = true;
            try {
              var opened = await reportControls.open(reportForm.context, reportForm.kind, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected download control is open. Choose Download there when ready.' : 'Your current work is kept. Check access in the full download controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The download controls could not be opened. Your current work is kept.'; }
            finally { if (isCurrent() && reportButton.isConnected) reportButton.disabled = false; }
          });
          else { var reportLink = node('a', 'Open the protected download controls', reportDestination); reportLink.href = reportForm.kind === 'public_key' ? '/consent/publishing#cpp-signing' : '/compliance#cmp-reports'; reportLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'automation_import_form') {
          var importForm = entry[1], importStarted = generation, importSelection = JSON.stringify(context());
          if (!importForm || Array.isArray(importForm) || Object.keys(importForm).sort().join(',') !== 'context,original' ||
              typeof importForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(importForm.context) ||
              typeof importForm.original !== 'string' || importForm.original && !/^AIR-[a-f0-9]{32}$/.test(importForm.original)) return;
          var importDestination = node('dd', undefined, list), importControls = window.LightworkAutomationImports;
          var importLabel = importForm.original ? 'Read the original automation import' : 'Open complete automation import controls';
          if (importControls && typeof importControls.open === 'function') button(importLabel, importDestination, async function (event) {
            var isCurrent = function () { return active(importStarted) && JSON.stringify(context()) === importSelection; };
            if (!isCurrent() || busy) return;
            var importButton = event.currentTarget; importButton.disabled = true;
            try {
              var opened = await importControls.open(importForm, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected import controls are open.' : 'Your entered import work is kept. Review current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The import controls could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && importButton.isConnected) importButton.disabled = false; }
          });
          else { var importLink = node('a', importLabel, importDestination); importLink.href = '/automations' + (importForm.original ? '?import_original=' + encodeURIComponent(importForm.original) : '') + '#auto-import-h'; importLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'access_key_form') {
          var keyForm = entry[1], keyStarted = generation, keySelection = JSON.stringify(context());
          if (!keyForm || Array.isArray(keyForm) || Object.keys(keyForm).sort().join(',') !== 'context,original' ||
              typeof keyForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(keyForm.context) || typeof keyForm.original !== 'boolean') return;
          var keyDestination = node('dd', undefined, list), keyControls = window.LightworkAccessKeys;
          if (keyControls && typeof keyControls.open === 'function') button(keyForm.original ? 'Read an original access-key request' : 'Open protected access-key controls', keyDestination, async function (event) {
            var isCurrent = function () { return active(keyStarted) && JSON.stringify(context()) === keySelection; };
            if (!isCurrent() || busy) return;
            var keyButton = event.currentTarget; keyButton.disabled = true;
            try {
              var opened = await keyControls.open(keyForm.context, keyForm.original, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected access-key controls are open.' : 'Your entered key work is kept. Read current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The protected controls could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && keyButton.isConnected) keyButton.disabled = false; }
          });
          else { var keyLink = node('a', keyForm.original ? 'Read an original access-key request' : 'Open protected access-key controls', keyDestination); keyLink.href = '/account/api-keys#ak-requests'; keyLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'governed_rule_evolution_author') {
          var evolutionAuthor = entry[1], evolutionStarted = generation, evolutionSelection = JSON.stringify(context());
          if (!evolutionAuthor || Array.isArray(evolutionAuthor) || Object.keys(evolutionAuthor).sort().join(',') !== 'binding,context,flow' ||
              typeof evolutionAuthor.context !== 'string' || !/^[a-f0-9]{64}$/.test(evolutionAuthor.context) ||
              typeof evolutionAuthor.binding !== 'string' || !/^[a-f0-9]{64}$/.test(evolutionAuthor.binding) ||
              typeof evolutionAuthor.flow !== 'string' || evolutionAuthor.flow.length < 1 || evolutionAuthor.flow.length > 256) return;
          var evolutionDestination = node('dd', undefined, list), evolutionControl = window.LWGovernedRuleEvolution;
          if (evolutionControl && typeof evolutionControl.openAuthor === 'function') button('Open all rule evolution controls', evolutionDestination, async function (event) {
            var isCurrent = function () { return active(evolutionStarted) && JSON.stringify(context()) === evolutionSelection; };
            if (!isCurrent() || busy) return;
            var evolutionButton = event.currentTarget; evolutionButton.disabled = true;
            try {
              var opened = await evolutionControl.openAuthor(evolutionAuthor, {isCurrent: isCurrent});
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected rule form is open.' : 'Your entered rule work is kept. Review current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The rule form could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && evolutionButton.isConnected) evolutionButton.disabled = false; }
          });
          else { var evolutionLink = node('a', 'Open all rule evolution controls', evolutionDestination); evolutionLink.href = '/learning/rule-evolution?flow=' + encodeURIComponent(evolutionAuthor.flow) + '#gre-author'; evolutionLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'operator_acquisition_author') {
          var acquisitionAuthor = entry[1], acquisitionStarted = generation, acquisitionSelection = JSON.stringify(context());
          if (!acquisitionAuthor || Array.isArray(acquisitionAuthor) || Object.keys(acquisitionAuthor).sort().join(',') !== 'binding,context,flow' ||
              typeof acquisitionAuthor.context !== 'string' || !/^[a-f0-9]{64}$/.test(acquisitionAuthor.context) ||
              typeof acquisitionAuthor.binding !== 'string' || !/^[a-f0-9]{64}$/.test(acquisitionAuthor.binding) ||
              typeof acquisitionAuthor.flow !== 'string' || acquisitionAuthor.flow.length < 1 || acquisitionAuthor.flow.length > 256) return;
          var acquisitionDestination = node('dd', undefined, list), acquisitionControl = window.LWOperatorAcquisition;
          if (acquisitionControl && typeof acquisitionControl.openAuthor === 'function') button('Open the complete teaching plan', acquisitionDestination, async function (event) {
            var isCurrent = function () { return active(acquisitionStarted) && JSON.stringify(context()) === acquisitionSelection; };
            if (!isCurrent() || busy) return;
            var acquisitionButton = event.currentTarget; acquisitionButton.disabled = true;
            try {
              var opened = await acquisitionControl.openAuthor(acquisitionAuthor, {isCurrent: isCurrent});
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected teaching form is open.' : 'Your entered teaching work is kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The teaching form could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && acquisitionButton.isConnected) acquisitionButton.disabled = false; }
          });
          else { var acquisitionLink = node('a', 'Open the complete teaching plan', acquisitionDestination); acquisitionLink.href = '/learning/acquisition?flow=' + encodeURIComponent(acquisitionAuthor.flow) + '#oac-author'; acquisitionLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'commitment_economic_author') {
          var economicAuthor = entry[1], economicStarted = generation, economicSelection = JSON.stringify(context());
          if (!economicAuthor || Array.isArray(economicAuthor) || Object.keys(economicAuthor).sort().join(',') !== 'binding,context,parent' ||
              typeof economicAuthor.context !== 'string' || !/^[a-f0-9]{64}$/.test(economicAuthor.context) ||
              typeof economicAuthor.binding !== 'string' || !/^[a-f0-9]{64}$/.test(economicAuthor.binding) ||
              typeof economicAuthor.parent !== 'string' || !/^CMV-[a-f0-9]{48}$/.test(economicAuthor.parent)) return;
          var economicDestination = node('dd', undefined, list), economicControl = window.LWCommitmentEconomics;
          if (economicControl && typeof economicControl.openAuthor === 'function') button('Open all financial assumptions and choices', economicDestination, async function (event) {
            var isCurrent = function () { return active(economicStarted) && JSON.stringify(context()) === economicSelection; };
            if (!isCurrent() || busy) return;
            var economicButton = event.currentTarget; economicButton.disabled = true;
            try {
              var opened = await economicControl.openAuthor(economicAuthor, {isCurrent: isCurrent});
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected financial form is open.' : 'Your entered assumptions are kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The financial form could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && economicButton.isConnected) economicButton.disabled = false; }
          });
          else { var economicLink = node('a', 'Open all financial assumptions and choices', economicDestination); economicLink.href = '/commitment-reviews?review=' + encodeURIComponent(economicAuthor.parent) + '#cea-author'; economicLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'workflow_step_check_form') {
          var stepForm = entry[1], stepStarted = generation, stepSelection = JSON.stringify(context());
          if (!stepForm || Array.isArray(stepForm) || Object.keys(stepForm).sort().join(',') !== 'context,flow,step' ||
              typeof stepForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(stepForm.context) ||
              typeof stepForm.flow !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/.test(stepForm.flow) ||
              typeof stepForm.step !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$/.test(stepForm.step)) return;
          var stepDestination = node('dd', undefined, list), stepControl = window.LWWorkflowStepChecks;
          if (stepControl && typeof stepControl.open === 'function') button('Open named values for this taught step', stepDestination, async function (event) {
            var isCurrent = function () { return active(stepStarted) && JSON.stringify(context()) === stepSelection; };
            if (!isCurrent() || busy) return;
            var stepButton = event.currentTarget; stepButton.disabled = true;
            try {
              var opened = await stepControl.open(stepForm, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected input form is open. Nothing has run yet.' : 'Your current step and entered work are kept. Review the current controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The step form could not be opened. Your work is kept.'; }
            finally { if (isCurrent() && stepButton.isConnected) stepButton.disabled = false; }
          });
          else { var stepLink = node('a', 'Open the workflow and select this taught step', stepDestination); stepLink.href = '/flows/designer/' + encodeURIComponent(stepForm.flow) + '#fd-selected-step-check'; stepLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'procedure_interaction_form' || entry[0] === 'request_program_form') {
          var combinedForm = entry[1], combinedStarted = generation, combinedSelection = JSON.stringify(context());
          var joint = entry[0] === 'procedure_interaction_form';
          if (!combinedForm || Array.isArray(combinedForm) ||
              Object.keys(combinedForm).sort().join(',') !== (joint ? 'context,first,second' : 'context') ||
              typeof combinedForm.context !== 'string' || !/^[a-f0-9]{64}$/.test(combinedForm.context) ||
              (joint && ['first', 'second'].some(function (key) { return typeof combinedForm[key] !== 'string' ||
                !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(combinedForm[key]); }))) return;
          var combinedDestination = node('dd', undefined, list);
          var combinedControl = joint ? window.LightworkJointRules : window.LightworkRequestProgram;
          var combinedLabel = joint ? 'Open complete joint rule controls' : 'Open the complete request form';
          if (combinedControl && typeof combinedControl.open === 'function') button(combinedLabel, combinedDestination, async function (event) {
            var isCurrent = function () { return active(combinedStarted) && JSON.stringify(context()) === combinedSelection; };
            if (!isCurrent() || busy) return;
            var combinedButton = event.currentTarget; combinedButton.disabled = true;
            try {
              var opened = await combinedControl.open(joint ? combinedForm : combinedForm.context, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete protected form is open.' : 'Your current work is kept. Review the current form.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The form could not be opened. Your entered work is kept.'; }
            finally { if (isCurrent() && combinedButton.isConnected) combinedButton.disabled = false; }
          });
          else {
            var combinedLink = node('a', combinedLabel, combinedDestination);
            combinedLink.href = joint ? '/learning/rules-together?first=' + encodeURIComponent(combinedForm.first) +
              '&second=' + encodeURIComponent(combinedForm.second) : '/learning/request-program';
            combinedLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'grc_draft_form') {
          var draft = entry[1], draftStarted = generation, draftSelection = JSON.stringify(context());
          if (!draft || Array.isArray(draft) || Object.keys(draft).sort().join(',') !== 'context,original' ||
              typeof draft.context !== 'string' || !/^[a-f0-9]{64}$/.test(draft.context) || typeof draft.original !== 'boolean') return;
          var draftDestination = node('dd', undefined, list), draftForm = window.LightworkGRCDraft;
          var draftLabel = draft.original ? 'Read the original draft save' : 'Review and save a blueprint draft';
          if (draftForm && typeof draftForm.open === 'function') button(draftLabel, draftDestination, async function (event) {
            var isCurrent = function () { return active(draftStarted) && JSON.stringify(context()) === draftSelection; };
            if (!isCurrent() || busy) return;
            var draftButton = event.currentTarget; draftButton.disabled = true;
            try {
              var opened = await draftForm.open(draft.context, draft.original, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected blueprint controls are open.' : 'The current draft or access changed. Review the full controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'The blueprint controls could not be opened. Check the current full controls.'; }
            finally { if (isCurrent() && draftButton.isConnected) draftButton.disabled = false; }
          });
          else {
            var draftLink = node('a', draftLabel, draftDestination);
            draftLink.href = '/compliance/grc-studio' + (draft.original ? '#grcs-save-original' : '#grcs-builder-panel');
            draftLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'distinction_cells') {
          var cells = entry[1], cellsStarted = generation, cellsSelection = JSON.stringify(context());
          if (!cells || Array.isArray(cells) || Object.keys(cells).sort().join(',') !== 'comparisons,context,flow' ||
              typeof cells.context !== 'string' || !/^[a-f0-9]{64}$/.test(cells.context) ||
              typeof cells.flow !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(cells.flow) ||
              !Array.isArray(cells.comparisons) || !cells.comparisons.length || cells.comparisons.length > 20 ||
              new Set(cells.comparisons).size !== cells.comparisons.length ||
              !cells.comparisons.every(function (id) { return typeof id === 'string' && /^FCP-[a-f0-9]{32}$/.test(id); })) return;
          var cellsDestination = node('dd', undefined, list), cellsForm = window.LightworkLearningDistinctions;
          if (cellsForm && typeof cellsForm.openCells === 'function') button('Open exact observed cells', cellsDestination, async function (event) {
            var isCurrent = function () { return active(cellsStarted) && JSON.stringify(context()) === cellsSelection; };
            if (!isCurrent() || busy) return;
            var cellsButton = event.currentTarget; cellsButton.disabled = true;
            try {
              var opened = await cellsForm.openCells(cells, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The complete recorded comparison evidence is open.' : 'The selected evidence or current form changed. Review the full controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'This evidence could not be opened. Read its current full controls before continuing.'; }
            finally { if (isCurrent() && cellsButton.isConnected) cellsButton.disabled = false; }
          });
          else {
            var cellsLink = node('a', 'Open exact observed cells', cellsDestination);
            cellsLink.href = '/learning/distinctions?flow=' + encodeURIComponent(cells.flow) + '&comparisons=' + encodeURIComponent(cells.comparisons.join(',')) + '#ld-cells';
            cellsLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'rule_requalification') {
          var rules = entry[1], rulesStarted = generation, rulesSelection = JSON.stringify(context());
          if (!rules || Array.isArray(rules) || Object.keys(rules).sort().join(',') !== 'context,workflow' ||
              !/^[a-f0-9]{64}$/.test(rules.context || '') || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(rules.workflow || '')) return;
          var rulesDestination = node('dd', undefined, list), ruleForm = window.LightworkRuleRequalification;
          if (ruleForm && typeof ruleForm.open === 'function') button('Review component evidence and changed rules', rulesDestination, async function (event) {
            var isCurrent = function () { return active(rulesStarted) && JSON.stringify(context()) === rulesSelection; };
            if (!isCurrent() || busy) return;
            var rulesButton = event.currentTarget; rulesButton.disabled = true;
            try {
              var opened = await ruleForm.open(rules.context, rules.workflow, isCurrent);
              if (!isCurrent()) return;
              status.textContent = opened ? 'The protected rule-check form is open.' : 'The selected workflow or current form changed. Review the native controls.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) { if (isCurrent()) status.textContent = 'This form could not be opened. Read its current native controls before continuing.'; }
            finally { if (isCurrent() && rulesButton.isConnected) rulesButton.disabled = false; }
          });
          else { var rulesLink = node('a', 'Review component evidence and changed rules', rulesDestination); rulesLink.href = '/learning/recheck-rules?workflow=' + encodeURIComponent(rules.workflow); }
          return;
        }
        if (entry[0] === 'learning_saved_point') {
          var saved = entry[1], savedStarted = generation;
          if (!saved || Array.isArray(saved) || Object.keys(saved).sort().join(',') !== 'name,revision' ||
              !/^[A-Za-z0-9._-]{1,80}$/.test(saved.name || '') || !/^[a-f0-9]{64}$/.test(saved.revision || '')) return;
          var savedDestination = node('dd', undefined, list);
          if (window.LightworkLearningSavedPoints) button('Open this saved point', savedDestination, async function (event) {
            if (!active(savedStarted) || busy) return;
            var savedButton = event.currentTarget; savedButton.disabled = true;
            try {
              var opened = await window.LightworkLearningSavedPoints.open(saved.name, saved.revision);
              if (!active(savedStarted)) return;
              if (opened) {
                var close = document.getElementById('mv-copilot-close'); if (close) close.click();
                var pointSelect = document.getElementById('lrn-snapshot'); if (pointSelect) pointSelect.focus({preventScroll: true});
              } else status.textContent = 'This saved point changed or could not be opened. Review current saved points in Learning.';
            } catch (_) { if (active(savedStarted)) status.textContent = 'This saved point could not be opened. Check current saved points in Learning.'; }
            finally { if (active(savedStarted) && savedButton.isConnected) savedButton.disabled = false; }
          });
          else { var savedLink = node('a', 'Open saved learning points', savedDestination); savedLink.href = '/learning#learning-review'; }
          return;
        }
        if (entry[0] === 'compliance_mapping_form') {
          var mapping = entry[1], mappingStarted = generation;
          if (!mapping || Array.isArray(mapping) || Object.keys(mapping).sort().join(',') !== 'context,mode' ||
              !/^[a-f0-9]{64}$/.test(mapping.context || '') || !['create', 'revise'].includes(mapping.mode)) return;
          var mappingDestination = node('dd', undefined, list), mappingForm = window.LightworkComplianceMapping;
          var mappingLabel = mapping.mode === 'revise' ? 'Revise a saved task mapping' : 'Design a task mapping';
          if (mappingForm && typeof mappingForm.open === 'function') button(mappingLabel, mappingDestination, async function (event) {
            if (!active(mappingStarted) || busy) return;
            var mappingButton = event.currentTarget; mappingButton.disabled = true;
            try {
              var opened = await mappingForm.open(mapping.context, mapping.mode);
              if (!active(mappingStarted)) return;
              status.textContent = opened ? 'The protected task-mapping form is open.' :
                'This form could not be opened. Check current access on the task-mapping page.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) {
              if (active(mappingStarted)) status.textContent = 'This form could not be opened. Check current access on the task-mapping page.';
            } finally { if (active(mappingStarted) && mappingButton.isConnected) mappingButton.disabled = false; }
          });
          else { var mappingLink = node('a', mappingLabel, mappingDestination); mappingLink.href = '/compliance/scope-actions/mapping'; mappingLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'privacy_notice_proposal_form') {
          var noticeProposal = entry[1], noticeStarted = generation;
          if (!noticeProposal || Array.isArray(noticeProposal) || Object.keys(noticeProposal).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(noticeProposal.context || '')) return;
          var noticeDestination = node('dd', undefined, list), noticeForm = window.LightworkPrivacyNoticeProposals;
          if (noticeForm && typeof noticeForm.open === 'function') button('Prepare a notice update', noticeDestination, async function (event) {
            if (!active(noticeStarted) || busy) return;
            var noticeButton = event.currentTarget; noticeButton.disabled = true;
            try {
              var opened = await noticeForm.open(noticeProposal.context);
              if (!active(noticeStarted)) return;
              status.textContent = opened ? 'The protected notice-update form is open.' :
                'This form could not be opened. Check current access on the privacy-notices page.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) {
              if (active(noticeStarted)) status.textContent = 'This form could not be opened. Check current access on the privacy-notices page.';
            } finally { if (active(noticeStarted) && noticeButton.isConnected) noticeButton.disabled = false; }
          });
          else { var noticeLink = node('a', 'Prepare a notice update', noticeDestination); noticeLink.href = '/privacy/notice-governance#notice-update-proposal'; noticeLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'installed_practice_environment') {
          var environment = entry[1], environmentStarted = generation;
          if (!environment || Array.isArray(environment) || Object.keys(environment).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(environment.context || '')) return;
          var environmentDestination = node('dd', undefined, list);
          var environmentForm = window.LightworkInstalledPracticeEnvironment;
          if (environmentForm && typeof environmentForm.open === 'function') button('Choose an installed practice environment', environmentDestination, async function (event) {
            if (!active(environmentStarted) || busy) return;
            var environmentButton = event.currentTarget; environmentButton.disabled = true;
            try {
              var opened = await environmentForm.open(environment.context);
              if (!active(environmentStarted)) return;
              status.textContent = opened ? 'The practice environment setting is open.' :
                'This setting could not be opened. Check your current access in Settings.';
              if (opened) {
                var close = document.getElementById('mv-copilot-close'); if (close) close.click();
              }
            } catch (_) {
              if (active(environmentStarted)) status.textContent = 'This setting could not be opened. Check your current access in Settings.';
            } finally { if (active(environmentStarted) && environmentButton.isConnected) environmentButton.disabled = false; }
          });
          else {
            var environmentLink = node('a', 'Choose an installed practice environment', environmentDestination);
            environmentLink.href = '/settings/all?id=plugins.workbench_image'; environmentLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'workspace_people') {
          var people = entry[1], peopleStarted = generation;
          if (!people || Array.isArray(people) || Object.keys(people).join(',') !== 'context' ||
              !/^[a-f0-9]{64}$/.test(people.context || '')) return;
          var peopleDestination = node('dd', undefined, list), peopleForm = window.LightworkWorkspacePeople;
          if (peopleForm && typeof peopleForm.open === 'function') button('Manage workspace people', peopleDestination, async function (event) {
            if (!active(peopleStarted) || busy) return;
            var peopleButton = event.currentTarget; peopleButton.disabled = true;
            try {
              var opened = await peopleForm.open(people.context);
              if (!active(peopleStarted)) return;
              status.textContent = opened ? 'The workspace people controls are open.' : 'These controls changed or are unavailable. Refresh People before continuing.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) {
              if (active(peopleStarted)) status.textContent = 'The workspace people controls could not be opened. Check current access in People.';
            } finally { if (active(peopleStarted) && peopleButton.isConnected) peopleButton.disabled = false; }
          });
          else { var peopleLink = node('a', 'Manage workspace people', peopleDestination); peopleLink.href = '/users#wi-title'; peopleLink.className = 'btn btn--ghost'; }
          return;
        }
        if (entry[0] === 'model_answer_form') {
          var answers = entry[1], answersStarted = generation;
          if (!answers || Array.isArray(answers) || Object.keys(answers).sort().join(',') !== 'context,model,split,task_set' ||
              typeof answers.task_set !== 'string' || !answers.task_set.length || answers.task_set.length > 120 ||
              !['holdout', 'validation', 'train'].includes(answers.split) || typeof answers.model !== 'string' ||
              answers.model.length > 200 || !/^[a-f0-9]{64}$/.test(answers.context || '')) return;
          var answerDestination = node('dd', undefined, list), answerForm = window.LightworkModelAnswerScoring;
          if (answerForm && typeof answerForm.open === 'function') button('Enter and review answers', answerDestination, async function (event) {
            if (!active(answersStarted) || busy) return;
            var answerButton = event.currentTarget;
            answerButton.disabled = true;
            try {
              var opened = await answerForm.open(answers, function () { return active(answersStarted) && !busy; });
              if (!active(answersStarted)) return;
              status.textContent = opened ? 'The answer questions are open. No check has started.' : 'These questions or your current work changed. Refresh the answer form before continuing.';
              if (opened) { var close = document.getElementById('mv-copilot-close'); if (close) close.click(); }
            } catch (_) {
              if (active(answersStarted)) status.textContent = 'The answer questions could not be opened. Your current work is kept.';
            } finally { if (active(answersStarted) && answerButton.isConnected) answerButton.disabled = false; }
          });
          else {
            var answerLink = node('a', 'Enter and review answers', answerDestination);
            var answerQuery = new URLSearchParams({scoring_task_set: answers.task_set, scoring_split: answers.split, scoring_model: answers.model});
            answerLink.href = '/learning?' + answerQuery.toString() + '#lo-mi-answer-h'; answerLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'plugin_practice_page') {
          var practice = entry[1], practiceStarted = generation;
          if (!practice || Array.isArray(practice) || Object.keys(practice).sort().join(',') !== 'fingerprint,receipt' ||
              !/^[a-f0-9]{64}$/.test(practice.fingerprint || '') || !/^[a-f0-9]{32}$/.test(practice.receipt || '')) return;
          var practiceDestination = node('dd', undefined, list);
          var practiceForm = window.LightworkPluginPractice;
          if (practiceForm && typeof practiceForm.open === 'function') button('Open guided practice check', practiceDestination, async function (event) {
            if (!active(practiceStarted) || busy) return;
            var practiceButton = event.currentTarget; practiceButton.disabled = true;
            try {
              var opened = await practiceForm.open(practice.fingerprint, practice.receipt);
              if (!active(practiceStarted)) return;
              status.textContent = opened ? 'The guided practice check is open in Plugins.' :
                'This inspection changed or is unavailable. Read the original inspection in Plugins.';
              if (opened) {
                var close = document.getElementById('mv-copilot-close'); if (close) close.click();
              }
            } catch (_) {
              if (active(practiceStarted)) status.textContent = 'The guided check could not be opened. Check current access in Plugins.';
            } finally { if (active(practiceStarted) && practiceButton.isConnected) practiceButton.disabled = false; }
          });
          else {
            var practiceLink = node('a', 'Open guided practice checks', practiceDestination);
            practiceLink.href = '/plugins#plugin-workbench'; practiceLink.className = 'btn btn--ghost';
          }
          return;
        }
        if (entry[0] === 'knowledge_request_page') {
          var page = entry[1], started = generation;
          if (!page || Array.isArray(page) || Object.keys(page).sort().join(',') !== 'cursor,view' ||
              !['active', 'archive', 'ready'].includes(page.view) || typeof page.cursor !== 'string' ||
              page.cursor.length > 2048 || (page.cursor && !/^[A-Za-z0-9_-]+$/.test(page.cursor))) return;
          node('dt', 'Saved requests', list);
          var destination = node('dd', undefined, list);
          if (window.LightworkKnowledgeRequests && typeof window.LightworkKnowledgeRequests.openBatch === 'function') {
            button('Open these requests', destination, async function (event) {
              if (!active(started) || busy) return;
              var control = event.currentTarget; control.disabled = true;
              try {
                var opened = await window.LightworkKnowledgeRequests.openBatch(page.view, page.cursor);
                if (active(started)) status.textContent = opened ? 'These requests are open in Knowledge.' : 'This batch could not be opened. Check your current access in Knowledge.';
                if (opened && active(started)) {
                  var close = document.getElementById('mv-copilot-close');
                  if (close) close.click();
                  document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {
                    detail: {selection: {kind: 'knowledge_request_batch', view: page.view, cursor: page.cursor}}
                  }));
                  var heading = document.getElementById('ka-requests-heading');
                  if (heading) heading.focus({preventScroll: true});
                }
              } catch (_) {
                if (active(started)) status.textContent = 'This batch could not be opened. Check your current access in Knowledge.';
              } finally { if (active(started)) control.disabled = false; }
            });
          } else {
            var knowledge = node('a', 'Open Knowledge requests', destination);
            knowledge.href = '/knowledge-access'; knowledge.className = 'btn btn--ghost';
          }
          return;
        }
        var label = entry[0].replace(/_/g, ' ');
        node('dt', label.charAt(0).toUpperCase() + label.slice(1), list);
        append(node('dd', undefined, list), entry[1], depth + 1);
      });
    }
    append(parent, value, 0);
    return complete;
  }
  function safeLocalHref(href) {
    if (typeof href !== 'string' || !href.startsWith('/') || href.startsWith('//') || /[\\\u0000-\u0020]/.test(href)) return false;
    try { return new URL(href, window.location.origin).origin === window.location.origin; } catch (_) { return false; }
  }
  function nativeLink(item, parent) {
    if (!safeLocalHref(item.direct_ui)) return;
    var link = node('a', 'Open full controls', parent); link.className = 'btn btn--ghost'; link.href = item.direct_ui;
  }
  async function refresh(options) {
    var keepResult = options && options.keepResult === true;
    var started = generation, previous = catalog;
    status.textContent = 'Checking your current controls…';
    try {
      var fresh = await request('/catalog', payload());
      if (!active(started)) return null;
      if (fresh.schema !== 1 || !Array.isArray(fresh.operations) || JSON.stringify(fresh.selection) !== JSON.stringify(context())) throw new Error('The current record could not be confirmed. Refresh the page and try again.');
      if (previous && previous.context !== fresh.context) {
        clear(formHost); selected = null;
        // When the account, role or suites changed (``access``), bubble, so
        // pages that clear private content on window hear it too. Only the
        // permitted Copilot actions changing, or a selection change (below),
        // stays on document.
        document.dispatchEvent(new CustomEvent('lightwork:copilot-context-changed', {bubbles: accessChanged(previous, fresh)}));
      }
      catalog = fresh; host.hidden = fresh.operations.length === 0; clear(buttons);
      fresh.operations.forEach(function (item) {
        var control = button(item.label, buttons, function () { openOperation(item.id); });
        control.dataset.available = item.available === true ? 'true' : 'false'; control.disabled = busy || !item.available;
        if (item.blocked) control.title = item.blocked;
      });
      filterControls();
      var changes = fresh.operations.some(function (item) { return item.confirmation_required === true; });
      status.textContent = uncertainty || (changes
        ? 'Current controls for this page. Changes require a separate review and confirmation.'
        : 'Current status for this page. These controls show information or open the page\'s own form; nothing changes unless you confirm there.');
      return fresh;
    } catch (error) {
      if (active(started)) {
        catalog = null; clear(buttons); selected = null; host.hidden = false;
        if (!keepResult) clear(formHost);
        if (noMatches) noMatches.hidden = true;
        status.textContent = keepResult ? 'Your saved result is below. Current controls could not be refreshed. ' + error.message : error.message;
      }
      return null;
    }
  }
  function createField(spec, parent, controls) {
    var row = node('div', undefined, parent), id = 'mv-operation-' + spec.name;
    var label = node('label', spec.label || spec.name, row); label.htmlFor = id;
    var control;
    function install(choices) {
      if (control) control.remove();
      if (choices && spec.kind === 'multiselect' && spec.presentation === 'checkboxes') {
        control = node('fieldset', undefined, row); control.id = id; control.name = spec.name; control.className = 'input';
        label.id = id + '-label'; control.setAttribute('aria-labelledby', label.id);
        control.style.minInlineSize = '0'; control.style.maxHeight = '18rem'; control.style.overflowY = 'auto';
        var note = node('p', undefined, control), boxes = [], limit = Number(spec.max_selections) || choices.length;
        note.className = 'muted'; note.setAttribute('role', 'status'); note.setAttribute('aria-live', 'polite');
        function chosen() { return boxes.filter(function (box) { return box.checked; }); }
        function updateChoices() {
          var count = chosen().length;
          boxes.forEach(function (box) { box.disabled = busy || !box.checked && count >= limit; });
          if (boxes[0]) boxes[0].setCustomValidity(spec.required && !count ? 'Choose at least one saved question.' :
            count > limit ? 'Choose no more than ' + limit + ' saved questions.' : '');
          note.textContent = count + ' selected. Choose up to ' + limit + '.' +
            (count >= limit ? ' Uncheck a question before choosing another.' : '');
        }
        choices.forEach(function (choice) {
          var option = node('label', undefined, control), box = node('input', undefined, option);
          option.style.display = 'flex'; option.style.alignItems = 'flex-start'; option.style.gap = 'var(--space-2)';
          option.style.paddingBlock = 'var(--space-2)';
          box.type = 'checkbox'; box.name = spec.name + '_choice'; box._typedValue = choice.value;
          box.style.flexShrink = '0'; box.checked = Array.isArray(spec.value) && spec.value.indexOf(choice.value) >= 0;
          var text = node('span', choice.label, option); text.style.minWidth = '0'; text.style.overflowWrap = 'anywhere';
          box.addEventListener('change', updateChoices); boxes.push(box);
        });
        controls[spec.name] = function () { return chosen().map(function (box) { return box._typedValue; }); };
        updateChoices(); return;
      }
      control = node(choices ? 'select' : spec.kind === 'textarea' ? 'textarea' : 'input', undefined, row);
      control.id = id; control.name = spec.name; control.className = 'input'; control.required = spec.required === true;
      if (!choices && spec.kind === 'boolean') control.classList.remove('input');
      if (choices && spec.kind === 'multiselect') control.multiple = true;
      if (choices) choices.forEach(function (choice, index) { var option = node('option', choice.label, control); option.value = String(index); option._typedValue = choice.value; if (spec.kind === 'multiselect' ? Array.isArray(spec.value) && spec.value.indexOf(choice.value) >= 0 : choice.value === spec.value) option.selected = true; });
      else { if (control.tagName !== 'TEXTAREA') control.type = spec.kind === 'boolean' ? 'checkbox' : spec.kind === 'number' ? 'number' : spec.kind === 'datetime-local' ? 'datetime-local' : 'text'; if (spec.kind === 'number') { control.step = 'any'; control.min = '0'; } control.maxLength = spec.max_length || 2000; control.value = spec.value === null || spec.value === undefined ? '' : String(spec.value); if (spec.kind === 'boolean') control.checked = spec.value === true; }
      controls[spec.name] = function () { if (choices && spec.kind === 'multiselect') return Array.from(control.selectedOptions, function (option) { return option._typedValue; }); if (choices) return control.selectedOptions[0] ? control.selectedOptions[0]._typedValue : ''; if (spec.kind === 'boolean') return control.checked; if (spec.kind === 'number') return control.value === '' ? null : Number(control.value); if (spec.kind === 'datetime-local') { var date = new Date(control.value); return Number.isNaN(date.getTime()) ? control.value : date.toISOString(); } return control.value; };
    }
    install(Array.isArray(spec.choices) ? spec.choices : null);
    if (spec.depends_on && spec.choices_by) return function () {
      var related = parent.elements.namedItem(spec.depends_on);
      function update() { install(spec.choices_by[controls[spec.depends_on]()] || null); }
      if (related) { related.addEventListener('change', update); update(); }
    };
    return null;
  }
  async function openWorkflowRun(item, fresh, started) {
    var selection = context();
    var review = await request('/prepare', Object.assign(payload(), {
      operation: item.id, context: fresh.context, revision: item.revision, arguments: {}
    }));
    if (!active(started)) return;
    var details = review.details || {};
    if (review.read_only !== true || review.operation !== item.id ||
        details.flow_id !== selection.id || !/^[0-9a-f]{64}$/.test(details.release_id || '') ||
        !window.LightworkFlowRun || typeof window.LightworkFlowRun.open !== 'function')
      throw new Error('The published workflow could not be confirmed. Reopen it before running.');
    clear(formHost); node('h3', item.label, formHost); node('p', review.summary, formHost);
    node('p', 'The workflow form will check this published version again. Nothing starts until you enter its values and confirm.', formHost);
    var launch = button('Enter workflow inputs', formHost, async function () {
      if (busy || !active(started)) return;
      if (JSON.stringify(context()) !== JSON.stringify(selection)) {
        status.textContent = 'The selected workflow changed. Refresh the current controls.'; return;
      }
      lock(true);
      try {
        var outcome = await window.LightworkFlowRun.open(selection.id, details.release_id);
        if (!active(started)) return;
        clear(formHost);
        if (outcome && outcome.status === 'started' && typeof outcome.run_id === 'string') {
          node('p', 'The workflow run was accepted. Check its progress and any required approvals.', formHost);
          var link = node('a', 'Open run progress', formHost);
          link.href = '/flows/' + encodeURIComponent(selection.id) + '/runs/' + encodeURIComponent(outcome.run_id);
          link.className = 'btn btn--ghost';
          status.textContent = 'Run accepted. This is not a completed business outcome.';
        } else {
          node('p', outcome && outcome.status === 'cancelled' ? 'Run cancelled. Nothing was submitted.' :
            'A new run was not confirmed. Check the workflow status before trying again.', formHost);
          status.textContent = outcome && outcome.status === 'cancelled' ? 'Run cancelled.' :
            'No new run was confirmed.';
        }
        button('Refresh current controls', formHost, function () { clear(formHost); selected = null; refresh(); });
      } catch (_) {
        if (active(started)) status.textContent = 'The run result could not be confirmed. Check workflow progress before trying again.';
      } finally { lock(false); }
    });
    launch.className = 'btn btn--primary'; launch.focus();
    button('Cancel', formHost, function () { clear(formHost); selected = null; status.textContent = 'Run review cancelled.'; });
  }
  async function openTeachingForm(item, fresh, started) {
    var selection = context(), teaching = window.LightworkFlowTeach;
    var review = await request('/prepare', Object.assign(payload(), {
      operation: item.id, context: fresh.context, revision: item.revision, arguments: {}
    }));
    if (!active(started)) return;
    var details = review.details || {}, modes = {
      'learning.workflow_refine': 'recipe_refine', 'learning.rule_teach': 'rule_teach', 'learning.rule_refine': 'rule_refine'
    };
    if (review.read_only !== true || review.operation !== item.id || details.flow_id !== selection.id ||
        details.mode !== modes[item.id] || !teaching || typeof teaching.perform !== 'function')
      throw new Error('The teaching form could not be confirmed. Reopen Teach before continuing.');
    clear(formHost); node('h3', item.label, formHost); node('p', review.summary, formHost);
    button('Review examples on Teach', formHost, function () { teaching.showTeachingInputs(details.mode); });
    var use = button('Use the reviewed teaching examples', formHost, async function () {
      if (busy || !active(started)) return;
      if (JSON.stringify(context()) !== JSON.stringify(selection)) {
        status.textContent = 'The selected flow or step changed. Refresh Copilot.'; return;
      }
      lock(true);
      try {
        var result = await teaching.perform(details);
        if (!active(started)) return;
        status.textContent = result && result.status === 'learned'
          ? 'The learning result is ready on Teach. Review and save it when you are ready; it has not been published or run.'
          : result && result.status === 'cancelled' ? 'Learning cancelled. Nothing was submitted.'
          : result && result.message || 'The learning result was not confirmed. Check the message on Teach before trying again.';
        if (result && result.status === 'learned') {
          clear(formHost); node('p', status.textContent, formHost);
          button('Review the learning result', formHost, function () {
            if (details.mode === 'recipe_refine') teaching.showRecipeReview(); else teaching.showRuleReview();
          });
        }
      } finally { lock(false); }
    });
    use.className = 'btn btn--primary'; use.focus();
    button('Cancel', formHost, function () { clear(formHost); selected = null; status.textContent = 'Teaching review cancelled.'; });
  }
  async function openConsentJobForm(item, fresh, started) {
    var selection = context(), native = window.LightworkConsentBulkJobs;
    var review = await request('/prepare', Object.assign(payload(), {
      operation: item.id, context: fresh.context, revision: item.revision, arguments: {}
    }));
    if (!active(started)) return;
    var details = review.details || {};
    if (review.read_only !== true || review.operation !== item.id || details.form !== 'consent_bulk_job' ||
        typeof details.context !== 'string' || !/^[a-f0-9]{64}$/.test(details.context) ||
        !native || typeof native.openCreate !== 'function')
      throw new Error('The request form is unavailable. Open Consent requests to continue.');
    clear(formHost); node('h3', item.label, formHost); node('p', review.summary, formHost);
    var launch = button('Choose and review the request', formHost, async function () {
      if (busy || !active(started)) return;
      if (JSON.stringify(context()) !== JSON.stringify(selection)) {
        status.textContent = 'Your selection changed. Refresh current controls before preparing a request.'; return;
      }
      lock(true);
      try {
        var result = await native.openCreate({host: formHost, context: details.context,
          active: function () { return active(started) && JSON.stringify(context()) === JSON.stringify(selection); }});
        if (!active(started)) return;
        clear(formHost);
        uncertainty = result && result.status === 'submitted' || result && result.status === 'cancelled' ? '' :
          'This request still needs confirmation. Read the original request in Consent requests before another submission.';
        node('p', result && result.status === 'submitted' ? 'The request was accepted. Its processing result is recorded separately.' :
          result && result.status === 'cancelled' ? 'The form was closed. No new request was submitted.' : uncertainty, formHost);
        if (result && result.status === 'submitted' && result.job) renderData(formHost, result.job);
        nativeLink(item, formHost); status.textContent = uncertainty || 'The request form is finished.';
        if (result && result.status === 'submitted') await refresh({keepResult: true});
      } catch (_) {
        if (active(started)) {
          uncertainty = 'The request result could not be confirmed. Open Consent requests and read the original submission before another attempt.';
          status.textContent = uncertainty; nativeLink(item, formHost);
        }
      } finally { lock(false); }
    });
    launch.className = 'btn btn--primary'; launch.focus(); nativeLink(item, formHost);
  }
  async function openQuestionnaireForm(item, fresh, started) {
    var selection = context(), native = window.LightworkComplianceQuestionnaire;
    var review = await request('/prepare', Object.assign(payload(), {
      operation: item.id, context: fresh.context, revision: item.revision, arguments: {}
    }));
    if (!active(started)) return;
    var details = review.details || {};
    if (review.read_only !== true || review.operation !== item.id || details.form_handoff !== 'compliance-questionnaire' ||
        !/^[a-f0-9]{64}$/.test(details.context || '') || !native || typeof native.openCreate !== 'function')
      throw new Error('The questionnaire form is unavailable. Open questionnaire design to continue.');
    clear(formHost); node('h3', item.label, formHost); node('p', review.summary, formHost);
    var launch = button('Choose and review questions', formHost, async function () {
      if (busy || !active(started)) return;
      if (JSON.stringify(context()) !== JSON.stringify(selection)) {
        status.textContent = 'Your selection changed. Refresh current controls before opening the form.'; return;
      }
      lock(true);
      try {
        var result = await native.openCreate({host: formHost, context: details.context,
          active: function () { return active(started) && JSON.stringify(context()) === JSON.stringify(selection); }});
        if (!active(started)) return;
        clear(formHost);
        status.textContent = result && result.confirmed === true ? 'Questionnaire saved for independent approval.' :
          result === null || result && result.status === 'cancelled' ? 'Questionnaire form closed. Check questionnaire design for any saved or pending request.' :
          'The save is not confirmed. Check the original request in questionnaire design before trying again.';
        node('p', status.textContent, formHost);
        if (result && result.confirmed === true && result.result) renderData(formHost, result.result);
        nativeLink(item, formHost);
      } catch (_) {
        if (active(started)) { status.textContent = 'The form result is not confirmed. Open questionnaire design to check the original request.'; nativeLink(item, formHost); }
      } finally { lock(false); }
    });
    launch.className = 'btn btn--primary'; launch.focus(); nativeLink(item, formHost);
  }
  async function openOperation(id) {
    if (busy) return false;
    var started = generation; lock(true);
    try {
      var fresh = await refresh();
      if (!fresh || !active(started)) return false;
      var item = fresh.operations.find(function (entry) { return entry.id === id && entry.available; });
      if (!item) return false;
      if (item.id === 'learning.workflow_run') {
        await openWorkflowRun(item, fresh, started);
        return true;
      }
      if (item.id === 'consent.jobs.create') {
        await openConsentJobForm(item, fresh, started);
        return true;
      }
      if (item.id === 'compliance.questionnaire.build') {
        await openQuestionnaireForm(item, fresh, started);
        return true;
      }
      if (['learning.workflow_refine', 'learning.rule_teach', 'learning.rule_refine'].includes(item.id)) {
        await openTeachingForm(item, fresh, started);
        return true;
      }
      selected = item; clear(formHost); node('h3', item.label, formHost); node('p', item.summary, formHost);
      node('p', 'Source: ' + item.source + '. Checked ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(fresh.checked_at) : new Date(fresh.checked_at * 1000).toLocaleString()) + '.', formHost);
      nativeLink(item, formHost);
      var form = node('form', undefined, formHost), controls = {}, dependents = [];
      (item.fields || []).forEach(function (spec) { var setup = createField(spec, form, controls); if (setup) dependents.push(setup); });
      dependents.forEach(function (setup) { setup(); });
      var submit = node('button', item.confirmation_required ? 'Review change' : 'Check current status', form); submit.type = 'submit'; submit.className = 'btn btn--primary';
      if (item.id === 'specialists.drafts.save' && controls.name) {
        var initialSpecialist = controls.name(), specialistChoice = form.elements.namedItem('name');
        var selectionNote = node('p', undefined, form), reloadSpecialist = button('Load selected specialist’s current fields', form, async function () {
          if (busy || controls.name() === initialSpecialist) return;
          overrideSelection = Object.assign({}, context(), {name: controls.name()});
          generation += 1; cancelRequests(); catalog = null; selected = null; clear(buttons);
          document.dispatchEvent(new CustomEvent('lightwork:copilot-context-changed', {detail: {reason: 'selection'}}));
          await openOperation(item.id);
        });
        reloadSpecialist.hidden = true;
        specialistChoice.addEventListener('change', function () {
          var changed = controls.name() !== initialSpecialist;
          specialistChoice.setCustomValidity(changed ? 'Load the selected specialist’s current fields before reviewing this draft.' : '');
          selectionNote.textContent = changed ? 'Your entered work is kept below. Loading this specialist replaces these fields with its current settings; returning to the previous choice keeps your edits.' : '';
          reloadSpecialist.hidden = !changed; submit.disabled = busy || changed;
        });
      }
      form.addEventListener('submit', async function (event) {
        event.preventDefault(); if (busy || !form.reportValidity()) return;
        var args = {}; Object.keys(controls).forEach(function (key) { args[key] = controls[key](); });
        var requested = Object.assign(payload(), {operation: item.id, context: fresh.context, revision: item.revision, arguments: args});
        lock(true);
        try {
          var review = await request('/prepare', requested,
            ['learning.qualify_answer_regions', 'learning.answer_region_question'].includes(item.id));
          if (!active(started)) return;
          clear(formHost); node('h3', item.label, formHost); node('p', review.summary, formHost);
          node('p', 'Source: ' + review.source + '. Checked ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(review.checked_at) : new Date(review.checked_at * 1000).toLocaleString()) + '.', formHost);
          var completeReview = true;
          if (review.changes && review.changes.length) {
            completeReview = item.id === 'teams.department.update'
              ? !!(window.LWDepartmentTeamUpdates && window.LWDepartmentTeamUpdates.renderReview &&
                   window.LWDepartmentTeamUpdates.renderReview(formHost, review.changes) === true)
              : ['learning.example_accept', 'learning.example_reject', 'learning.example_grant'].includes(item.id)
                ? !!(window.LightworkLearningCapture && window.LightworkLearningCapture.renderReview &&
                     window.LightworkLearningCapture.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('commitments.capability.')
                ? !!(window.LWCommitmentCapability && window.LWCommitmentCapability.renderReview &&
                     window.LWCommitmentCapability.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('commitments.economics.')
                ? !!(window.LWCommitmentEconomics && window.LWCommitmentEconomics.renderReview &&
                     window.LWCommitmentEconomics.renderReview(formHost, review.changes) === true)
              : ['learning.qualify_answer_regions', 'learning.answer_region_question', 'learning.withdraw_region_answer', 'learning.run_answer_regions'].includes(item.id)
                ? !!(window.LightworkApplicabilityRegions && window.LightworkApplicabilityRegions.renderReview &&
                     window.LightworkApplicabilityRegions.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('learning.rule_evolution.')
                ? !!(window.LWGovernedRuleEvolution && window.LWGovernedRuleEvolution.renderReview &&
                     window.LWGovernedRuleEvolution.renderReview(formHost, review.changes) === true)
              : ['learning.generated_tool_remove', 'learning.generated_tool_cleanup'].includes(item.id)
                ? !!(window.LWGeneratedToolRemoval && window.LWGeneratedToolRemoval.renderReview &&
                     window.LWGeneratedToolRemoval.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('learning.acquisition.')
                ? !!(window.LWOperatorAcquisition && window.LWOperatorAcquisition.renderReview &&
                     window.LWOperatorAcquisition.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('tasks.private_check.')
                ? !!(window.LWPrivateTaskComputation && window.LWPrivateTaskComputation.renderReview &&
                     window.LWPrivateTaskComputation.renderReview(formHost, review.changes) === true)
              : item.id === 'learning.run_joint_rules'
                ? !!(window.LightworkJointRules && window.LightworkJointRules.renderReview &&
                     window.LightworkJointRules.renderReview(formHost, review.changes) === true)
              : ['learning.factory_guidance_check', 'learning.factory_guidance_adopt', 'learning.factory_guidance_restore'].includes(item.id)
                ? !!(window.LWFactoryGuidance && window.LWFactoryGuidance.renderReview &&
                     window.LWFactoryGuidance.renderReview(formHost, review.changes) === true)
              : ['learning.pilot_prepare_task', 'learning.pilot_freeze_plan', 'learning.pilot_observe', 'learning.pilot_independent_review'].includes(item.id)
                ? !!(window.LightworkOutcomePilots && window.LightworkOutcomePilots.renderReview &&
                     window.LightworkOutcomePilots.renderReview(formHost, review.changes) === true)
              : item.id === 'workspaces.erase'
                ? !!(window.LWWorkspaceErasure && window.LWWorkspaceErasure.renderReview &&
                     window.LWWorkspaceErasure.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('specialists.drafts.')
                ? !!(window.LWSpecialistDrafts && window.LWSpecialistDrafts.renderReview &&
                     window.LWSpecialistDrafts.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('conversations.human.')
                ? !!(window.LWHumanConversations && window.LWHumanConversations.renderReview &&
                     window.LWHumanConversations.renderReview(formHost, review.changes) === true)
              : item.id.startsWith('decisions.')
                ? !!(window.LWDecisionEvidence && window.LWDecisionEvidence.renderReview &&
                     window.LWDecisionEvidence.renderReview(formHost, review.changes) === true)
              : renderData(formHost, review.changes, {complete: review.read_only !== true});
          }
          if (review.read_only) { renderData(formHost, review.details); status.textContent = 'Current information checked. Nothing was changed.'; }
          else if (completeReview) renderConfirmation(item, review, started);
          else {
            node('p', 'This complete review could not be displayed here. Open the full controls to review and confirm it; nothing was submitted.', formHost);
            status.textContent = 'Open the full controls for the complete review. Nothing was submitted.';
          }
          nativeLink(item, formHost);
          button('Refresh current controls', formHost, function () { clear(formHost); selected = null; refresh(); });
        } catch (error) { if (active(started)) status.textContent = error.message; }
        finally { lock(false); }
      });
      var focus = form.querySelector('select,input,textarea,button'); if (focus) focus.focus();
      return true;
    } catch (error) {
      if (active(started)) status.textContent = error.message;
      return false;
    } finally { lock(false); }
  }
  function renderConfirmation(item, review, started) {
    function originalOutcomeButton() {
      if (review.recovery_available !== true || Date.now() >= review.expires_at * 1000) return;
      button('Check original outcome', formHost, async function () {
        if (busy || !active(started)) return;
        lock(true);
        try {
          var original = await request('/recover', {token: review.token});
          if (!active(started)) return;
          if (original.operation !== item.id || !['confirmed', 'replayed', 'queued', 'unconfirmed'].includes(original.status))
            throw new Error('The original result could not be verified. Open the full controls.');
          clear(formHost); node('h3', item.label, formHost); node('p', original.message, formHost);
          if (original.details) renderData(formHost, original.details);
          uncertainty = ['confirmed', 'replayed'].includes(original.status) ? '' :
            'The original outcome is still unconfirmed. No action was repeated.';
          status.textContent = uncertainty || 'The original saved outcome was checked. No action was repeated.';
          nativeLink(item, formHost);
          if (uncertainty) originalOutcomeButton();
          else button('Refresh current controls', formHost, function () { refresh({keepResult: true}); });
        } catch (error) { if (active(started)) status.textContent = error.message; }
        finally { lock(false); }
      });
    }
    var line = node('label', undefined, formHost), consent = node('input', undefined, line); consent.type = 'checkbox';
    line.appendChild(document.createTextNode(' I reviewed these exact changes and want to apply them.'));
    var apply = button('Apply reviewed change', formHost, async function () {
      if (busy || !consent.checked) { status.textContent = 'Review the changes and select the confirmation box first.'; return; }
      if (Date.now() >= review.expires_at * 1000) { status.textContent = 'This review expired. Refresh controls and review again.'; return; }
      lock(true); uncertainty = 'A submitted action needs a status check before another attempt.';
      var submitted = false;
      try {
        if (item.id === 'schedules.repair') {
          var recovery = window.LightworkScheduleRecovery;
          if (!recovery || typeof recovery.rememberReview !== 'function') {
            uncertainty = 'Nothing was submitted. Open this schedule in Automations to keep its recovery reference.';
            throw new Error(uncertainty);
          }
          try { await recovery.rememberReview(review.token); }
          catch (error) { uncertainty = 'Nothing was submitted. The recovery reference could not be saved.'; throw error; }
          if (!active(started)) return;
        }
        submitted = true;
        var result = await request('/execute', {token: review.token, confirmed: true},
          ['learning.rule_evolution.build', 'learning.rule_evolution.check',
           'learning.qualify_answer_regions', 'learning.answer_region_question'].includes(item.id));
        if (!active(started)) return;
        clear(formHost); node('h3', item.label, formHost); node('p', result.message, formHost);
        uncertainty = result.status === 'confirmed' || result.status === 'replayed' ? '' : 'This outcome still needs confirmation. Check native status; do not submit it again automatically.';
        if (result.operation === 'learning.workflow_teach') {
          var teaching = window.LightworkFlowTeach;
          var delivered = result.status === 'confirmed' && teaching && typeof teaching.acceptRecipe === 'function' &&
            await teaching.acceptRecipe(result.details && result.details.flow_id, result.details && result.details.recipe);
          if (delivered) {
            button('Review the learned procedure', formHost, function () { teaching.showRecipeReview(); });
          } else {
            uncertainty = 'The procedure was learned; your current draft is kept. Finish or cancel that draft, then open this learned result.';
            if (teaching && typeof teaching.acceptRecipe === 'function') button('Open this learned result', formHost, async function () {
              if (await teaching.acceptRecipe(result.details.flow_id, result.details.recipe)) {
                uncertainty = ''; status.textContent = 'The learned procedure is ready on Teach.';
                teaching.showRecipeReview();
              }
            });
          }
        } else if (result.details) renderData(formHost, result.details);
        if (result.operation === 'preferences.update' && result.status === 'confirmed' && result.details) {
          var revision = document.querySelector('meta[name="lightwork-preference-revision"]');
          if (revision && result.details.revision) revision.content = result.details.revision;
          Object.entries(result.details.values || {}).forEach(function (entry) {
            if (window.mvApplyDisplayPreference) window.mvApplyDisplayPreference(entry[0], entry[1]);
            var picker = document.querySelector('[data-ui-preference="' + entry[0] + '"]');
            if (picker) picker.value = entry[1];
          });
        }
        nativeLink(item, formHost); status.textContent = uncertainty || 'The server confirmed the result.';
        if (uncertainty) originalOutcomeButton();
        document.dispatchEvent(new CustomEvent('lightwork:product-operation-complete', {detail: {operation: result.operation, status: result.status}}));
        if (result.status === 'confirmed' || result.status === 'replayed') {
          button('Refresh current controls', formHost, function () { refresh({keepResult: true}); });
          await refresh({keepResult: true});
        }
      } catch (error) {
        if (active(started)) {
          clear(formHost); node('p', error.message, formHost); nativeLink(item, formHost); status.textContent = uncertainty;
          if (submitted) originalOutcomeButton();
        }
      } finally { lock(false); }
    });
    apply.className = 'btn btn--primary';
    apply._lightworkConsent = consent; apply.disabled = true;
    consent.addEventListener('change', function () { apply.disabled = busy || !consent.checked; });
    button('Cancel this review', formHost, function () { clear(formHost); selected = null; status.textContent = 'Review cancelled. Nothing was submitted.'; });
  }
  window.LightworkProductOperations = {
    open: function () { generation += 1; refresh(); },
    close: function () { generation += 1; cancelRequests(); catalog = null; selected = null; clear(formHost); clear(buttons); },
    isBusy: function () { return busy; },
    propose: async function (message) {
      if (busy || !catalog || !catalog.operations.some(function (item) { return item.available; })) return false;
      var started = generation; lock(true);
      try {
        var result = await request('/propose', Object.assign(payload(), {message: message, context: catalog.context}));
        if (!active(started)) return true;
        if (result.context !== catalog.context) {
          var before = catalog;
          clear(formHost); catalog = null; status.textContent = 'Your context changed. Reopen Copilot.';
          document.dispatchEvent(new CustomEvent('lightwork:copilot-context-changed', {bubbles: accessChanged(before, result)}));
          return true;
        }
        if (!result.operation) return false;
        lock(false); return await openOperation(result.operation);
      } catch (error) { if (active(started)) status.textContent = error.message; return 'unavailable'; }
      finally { lock(false); }
    }
  };
  window.addEventListener('pagehide', function () { generation += 1; cancelRequests(); });
  document.addEventListener('lightwork:copilot-selection', function (event) {
    generation += 1; cancelRequests(); overrideSelection = event.detail && event.detail.selection || null; catalog = null; selected = null; clear(formHost); clear(buttons);
    document.dispatchEvent(new CustomEvent('lightwork:copilot-context-changed', {detail: {reason: 'selection'}}));
    if (!panel.hidden) refresh();
  });
  if (['/approvals', '/oversight'].includes(window.location.pathname)) window.addEventListener('hashchange', function () {
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: null}}));
  });
}());
