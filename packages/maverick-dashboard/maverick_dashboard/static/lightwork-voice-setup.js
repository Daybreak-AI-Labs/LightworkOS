/* Optional, explicit setup of the deployment's pinned speech-to-text model. */
(function () {
  'use strict';
  var el = function (name) { return document.getElementById('voice-setup-' + name); };
  if (!el('status')) return;
  var base = '/api/v1/voice/setup', state = null, context = null;
  var locked = false, writing = false, reading = false, generation = 0, timer = null, readController = null;
  var activeStates = ['checking', 'downloading', 'cancelling'];
  function active() { return state && state.job && activeStates.includes(state.job.state); }
  function plainError(message) { var error = new Error(message); error.plain = true; return error; }
  function text(name, value, values) { var node=el(name); delete node.dataset.userContent; if(window.LightworkI18n) window.LightworkI18n.set(node,value,values); else { node.textContent=value.replace(/\{(\w+)\}/g,function(_,key){return String((values||{})[key]??'');}); node.lang='en'; node.dir='ltr'; } }
  function raw(name, value) { var node=el(name); node.textContent=value; node.lang='und'; node.dir='auto'; node.dataset.userContent=''; }
  function formatted(source) { return window.LightworkI18n?window.LightworkI18n.text(source):source; }
  function number(value, options) { return window.LightworkI18n?window.LightworkI18n.number(value,options):new Intl.NumberFormat('en',options).format(value); }
  function stopTimer() { window.clearTimeout(timer); timer = null; }
  function controls() {
    var allowed = !locked && !writing && state && state.enabled && state.can_download && state.model && !active();
    el('confirm').disabled = !allowed;
    el('start').disabled = !allowed || !el('confirm').checked;
    el('cancel').disabled = locked || writing || !active() || state.job.state === 'cancelling';
    el('refresh').disabled = locked || writing || reading;
  }
  function clearPrivate(message) {
    locked = true; state = null; context = null; generation += 1; stopTimer();
    ['model', 'model-details', 'technical', 'policy', 'readiness', 'progress-text'].forEach(function (name) { text(name, ''); });
    el('try').hidden = true;
    el('progress').hidden = true; el('progress').removeAttribute('value'); el('confirm').checked = false;
    text('status', message); controls();
  }
  function problem(message) {
    state = null; stopTimer(); el('confirm').checked = false; el('progress').hidden = true; el('try').hidden = true;
    text('progress-text', ''); text('status', '{reason} Refresh setup status before trying again; an earlier download may still be running.', {reason:formatted(message)}); controls();
  }
  function valid(data) {
    function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
    function bounded(value, maximum) { return Number.isSafeInteger(value) && value >= 0 && value <= maximum; }
    if (!object(data) || !/^[a-f0-9]{64}$/.test(data.context || '') || typeof data.enabled !== 'boolean' ||
        typeof data.can_download !== 'boolean' || typeof data.engine_available !== 'boolean' ||
        !['missing', 'present_unverified', 'verified'].includes(data.model_state) || !object(data.configuration) ||
        typeof data.configuration.managed_path !== 'boolean' || typeof data.configuration.auto_fetch !== 'boolean' ||
        typeof data.configuration.backend !== 'string' || data.configuration.backend.length > 100 ||
        !(data.reason === null || typeof data.reason === 'string' && data.reason.length <= 2000)) return false;
    var model = data.model;
    if (model !== null && (!object(model) || !/^(tiny|base|small|medium)(\.en)?$|^large-v3(-turbo)?$/.test(model.id || '') ||
        !/^[a-f0-9]{64}$/.test(model.sha256 || '') || !bounded(model.size_bytes, 10 * 1024 ** 3) || model.size_bytes < 1 ||
        model.source_url !== 'https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-' + model.id + '.bin')) return false;
    if (data.can_download && (!model || data.configuration.managed_path || !data.enabled)) return false;
    var job = data.job;
    if (job !== null && (!object(job) || !/^[A-Za-z0-9_-]{16,100}$/.test(job.id || '') ||
        !activeStates.concat(['cancelled', 'ready', 'failed']).includes(job.state) ||
        !bounded(job.received_bytes, 10 * 1024 ** 3) || !bounded(job.total_bytes, 10 * 1024 ** 3) ||
        job.received_bytes > job.total_bytes || !(job.error === null || typeof job.error === 'string' && job.error.length <= 2000))) return false;
    return true;
  }
  async function request(path, body, signal) {
    var data;
    try {
      data = await window.mvFetchJSON(base + path, {method: body ? 'POST' : 'GET', cache: 'no-store', body: body || undefined, signal: signal || undefined,
        headers: context ? {'X-Lightwork-Voice-Context': context} : {},
        onAccess: function () { clearPrivate('Voice setup access is no longer available. Sign in with an administrator account and reload this page.'); }},
        'confirm this voice setup request');
    } catch (error) {
      if (error.accessChanged) throw new Error('Access changed');
      if (error.status === 409) {
        clearPrivate('The account, workspace or voice setup changed. Please reload this page and review its current status.');
        throw new Error('Setup changed');
      }
      error.plain = error.status > 0 || error.unreadable === true;
      throw error;
    }
    if (!valid(data)) throw plainError('Voice setup information could not be verified. Refresh the page and try again.');
    if (context && context !== data.context) {
      clearPrivate('The account, workspace or voice configuration changed. Please reload this page before continuing.');
      throw new Error('Context changed');
    }
    return data;
  }
  function render(data) {
    state = data; context = data.context;
    var model = data.model, job = data.job;
    var names = {tiny:'Compact multilingual model', 'tiny.en':'Compact English model', base:'Standard multilingual model', 'base.en':'Standard English model',
      small:'Larger multilingual model', 'small.en':'Larger English model', medium:'Advanced multilingual model', 'medium.en':'Advanced English model',
      'large-v3':'Largest multilingual model', 'large-v3-turbo':'Fast large multilingual model'};
    text('model', model ? names[model.id] : 'Managed by your deployment');
    text('model-details', model ? 'About {size} MB. Download source: Hugging Face, whisper.cpp model catalog.' : "This setup supports the configured model from Lightwork’s fixed catalog.", {size:model?number(model.size_bytes / 1e6,{minimumFractionDigits:1,maximumFractionDigits:1}):''});
    text('technical', model ? '{model} · {bytes} bytes · {source} · SHA-256: {hash} · Configured speech backend: {backend}' : '', model?{model:model.id,bytes:number(model.size_bytes),source:model.source_url,hash:model.sha256,backend:data.configuration.backend}:{});
    text('policy', data.configuration.auto_fetch ? 'Your deployment allows automatic model downloads. This setup uses the same policy.' : 'Automatic model downloads are off. This setup downloads only after you confirm.');
    text('readiness', data.engine_available ? (data.configuration.backend === 'local' ? 'The local speech engine is installed. Dictation is configured to run on this computer.' : 'The local speech engine is installed. Dictation follows your selected speech provider and may use a configured cloud service.') :
      'The speech engine is not available in this installation. Downloading the voice model alone won’t turn on dictation on this computer; your selected speech provider is used instead.');
    var messages = {checking:'Checking the existing model file and verifying its bytes…', downloading:'Downloading model…',
      cancelling:'Cancelling… Stopping the download and cleaning up.', cancelled:'Download cancelled. Review the model and confirm again to retry.',
      ready:data.engine_available ? 'Model file verified during the last setup. Try dictation using the microphone in Chat.' : 'Model file verified during the last setup.', failed:'Setup failed. Review the connection and available disk space, then confirm again to retry.'};
    var unavailable = !data.enabled || !data.can_download || data.configuration.managed_path || !model;
    var status = unavailable ? 'Voice model setup is unavailable for this deployment. Ask your administrator if you need it.' :
      job && job.state === 'ready' && data.model_state !== 'verified' ? 'The previously verified model file has changed or is missing. Confirm below to check it again.' :
      job ? messages[job.state] : data.model_state === 'verified' ? messages.ready :
        data.model_state === 'present_unverified' ? 'A model file is present but has not been verified by setup. Confirm below to check it and repair it if needed.' :
          'The configured model is not installed. Review the source and download size before confirming.';
    if(unavailable && data.reason) raw('status',data.reason);
    else if(!unavailable && job && job.state==='failed' && job.error) text('status','Setup failed. {reason}',{reason:job.error});
    else text('status', status);
    el('try').hidden = !(data.enabled && data.engine_available && data.model_state === 'verified' && ['auto', 'local'].includes(data.configuration.backend));
    el('progress').hidden = !active();
    if (active() && job.total_bytes > 0) { el('progress').max = job.total_bytes; el('progress').value = job.received_bytes; }
    else el('progress').removeAttribute('value');
    text('progress-text', active() ? '{received} MB of {total} MB ({percent}). Lightwork checks the file before using it.' : '',active()?{received:number(job.received_bytes / 1e6,{minimumFractionDigits:1,maximumFractionDigits:1}),total:number(job.total_bytes / 1e6,{minimumFractionDigits:1,maximumFractionDigits:1}),percent:number(job.total_bytes?Math.floor(job.received_bytes*100/job.total_bytes)/100:0,{style:'percent',maximumFractionDigits:0})}:{});
    controls(); schedule();
  }
  function schedule() {
    stopTimer(); if (!locked && active()) timer = window.setTimeout(function () { return load(); }, 1500);
  }
  async function load() {
    if (locked || reading || writing) return;
    reading = true; var expected = generation, controller = new AbortController(); readController = controller; controls();
    try { var data = await request('', null, controller.signal); if (!locked && expected === generation) render(data); }
    catch (error) { if (!locked && expected === generation) problem(error && error.plain ? error.message : 'Voice setup status is unavailable. Lightwork may not be responding. Try again in a minute.'); }
    finally { if (readController === controller) { readController = null; reading = false; } controls(); }
  }
  async function mutate(path, body) {
    if (locked || writing) return;
    writing = true; generation += 1; stopTimer();
    if (readController) { readController.abort(); readController = null; reading = false; }
    el('confirm').checked = false; controls();
    try { var data = await request(path, body); if (!locked) render(data); }
    catch (error) { if (!locked) problem(error && error.plain ? error.message : 'Voice setup could not confirm the action. Lightwork may not be responding. Try again in a minute.'); }
    finally { writing = false; controls(); }
  }
  el('confirm').addEventListener('change', controls);
  el('start').addEventListener('click', function () {
    if (locked || writing || !state || !state.enabled || !state.can_download || active() || !state.model || !el('confirm').checked) return;
    return mutate('/download', {confirm:true, model:state.model.id, sha256:state.model.sha256, size_bytes:state.model.size_bytes});
  });
  el('cancel').addEventListener('click', function () {
    if (locked || writing || !active() || state.job.state === 'cancelling') return;
    return mutate('/cancel', {job_id:state.job.id});
  });
  el('refresh').addEventListener('click', function () { el('confirm').checked = false; return load(); });
  window.addEventListener('pagehide', function () {
    if (readController) readController.abort();
    clearPrivate('Reload this page to verify voice setup access and current progress.');
  });
  load();
})();
