/* A single cancellable playback owner across server and browser voices. */
(function () {
  'use strict';
  var owner = null;
  function copy(node, source, values) { if (window.LightworkI18n) window.LightworkI18n.set(node, source, values); else { node.textContent = source.replace(/\{(\w+)\}/g, function (_, key) { return String((values || {})[key] ?? ''); }); node.lang = 'en'; node.dir = 'ltr'; } }
  function label(source) { return window.LightworkI18n ? window.LightworkI18n.text(source) : source; }
  function number(value) { return window.LightworkI18n ? window.LightworkI18n.number(value) : String(value); }
  window.lwReadAloud = function (button) {
    if (!button || button.dataset.readAloudBound) return;
    if (owner) owner.dispose();
    button.dataset.readAloudBound = "true";
    var generation = 0, active = false, paused = false, player = null, url = null, request = null;
    var parts = [], index = 0, browserOnly = false, utterance = null, contentLanguage = 'und';
    var status = document.createElement('span');
    status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
    var pause = document.createElement('button'); pause.type = 'button'; pause.className = 'btn btn--ghost'; pause.hidden = true;
    copy(pause, 'Pause reading');
    var options = document.createElement('label'), skip = document.createElement('input');
    skip.type = 'checkbox'; skip.checked = true;
    var optionLabel = document.createElement('span'); copy(optionLabel, 'Skip code and tables when reading');
    options.append(skip, ' ', optionLabel);
    button.after(pause, options, status);
    function release() {
      if (player) { player.pause(); player.onended = null; player.onerror = null; player = null; }
      if (url) { URL.revokeObjectURL(url); url = null; }
    }
    function stop(message) {
      generation += 1; active = false; paused = false;
      if (request) request.abort(); request = null;
      release();
      if (window.lwVoice) window.lwVoice.stop();
      else if (window.speechSynthesis) window.speechSynthesis.cancel();
      utterance = null; pause.hidden = true;
      button.setAttribute('aria-pressed', 'false'); button.setAttribute('aria-busy', 'false');
      button.setAttribute('aria-label', label('Read the result aloud')); copy(button, 'Read aloud');
      if (message) copy(status, message);
    }
    function next(token) {
      if (!active || token !== generation) return;
      index += 1; release();
      if (index >= parts.length) { stop('Reading finished.'); return; }
      play(token);
    }
    function browser(text, token) {
      if (!window.speechSynthesis || !window.SpeechSynthesisUtterance) { stop('Audio is unavailable. Try reading again when a voice is available.'); return; }
      var clean = window.lwVoice ? window.lwVoice.humanize(text, contentLanguage) : text;
      utterance = new SpeechSynthesisUtterance(clean);
      var voice = window.lwVoice && window.lwVoice.best(contentLanguage);
      if (voice) { utterance.voice = voice; utterance.lang = voice.lang; }
      utterance.onend = function () { next(token); };
      utterance.onerror = function (event) { if (token === generation && event.error !== 'canceled') stop('Playback stopped. Select Read aloud to try again.'); };
      window.speechSynthesis.cancel(); window.speechSynthesis.speak(utterance);
      if (paused) window.speechSynthesis.pause();
    }
    async function play(token) {
      if (!active || token !== generation) return;
      copy(status, browserOnly ? 'Reading part {current} of {total} with the device voice.' : 'Reading part {current} of {total}.', {current:number(index + 1), total:number(parts.length)});
      if (browserOnly) { browser(parts[index], token); return; }
      request = new AbortController();
      var controller = request, timer = setTimeout(function () { controller.abort(); }, 20000);
      button.setAttribute('aria-busy', 'true');
      try {
        var response = await fetch('/api/v1/voice/speak', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text: parts[index]}), signal: controller.signal});
        if (!response.ok) throw new Error('Voice unavailable');
        var blob = await response.blob();
        if (!active || token !== generation) return;
        url = URL.createObjectURL(blob); player = new Audio(url);
        player.onended = function () { next(token); };
        player.onerror = function () { if (token === generation) stop('Audio could not play. Select Read aloud to retry.'); };
        if (!paused) {
          try { await player.play(); }
          catch (_) { if (token === generation) stop('Your browser blocked audio. Select Read aloud to try again.'); }
        }
      } catch (_) {
        if (!active || token !== generation) return;
        browserOnly = true;
        copy(status, 'The server voice is unavailable. Reading the complete selection with the device voice.');
        browser(parts[index], token);
      } finally {
        clearTimeout(timer);
        if (request === controller) request = null;
        if (token === generation) button.setAttribute('aria-busy', 'false');
      }
    }
    button.addEventListener('click', function () {
      if (active) { stop('Reading stopped.'); return; }
      var source = document.getElementById('result') || document.getElementById('deliverable') || document.getElementById('result-section');
      if (!source) { copy(status, 'No result is available to read yet. Read aloud works once the task has a result.'); return; }
      // Result language is content metadata, never the interface or inherited html language.
      contentLanguage = source.getAttribute('lang') || 'und';
      var selection = source.cloneNode(true);
      if (skip.checked) selection.querySelectorAll('pre, code, table').forEach(function (node) { node.remove(); });
      var text = (selection.textContent || '').trim();
      if (!text) { copy(status, 'No readable text remains with these options.'); return; }
      // Complete content, bounded per request. Never silently slice the result.
      var answerPanel = button.closest('#answer-panel');
      parts = text.match(/[\s\S]{1,3000}/gu) || []; index = 0;
      browserOnly = !!answerPanel && answerPanel.dataset.operate !== '1'; active = true;
      button.setAttribute('aria-pressed', 'true'); button.setAttribute('aria-label', label('Stop reading')); copy(button, 'Stop reading');
      pause.hidden = false; copy(pause, 'Pause reading'); play(++generation);
    });
    pause.addEventListener('click', function () {
      if (!active) return;
      paused = !paused; copy(pause, paused ? 'Resume reading' : 'Pause reading');
      if (player) { if (paused) player.pause(); else player.play().catch(function () { stop('Playback blocked. Select Read aloud to retry.'); }); }
      if (window.speechSynthesis) { if (paused) window.speechSynthesis.pause(); else window.speechSynthesis.resume(); }
    });
    owner = {stop: stop, dispose: function () {
      stop(); pause.remove(); options.remove(); status.remove();
    }};
    copy(button, 'Read aloud'); button.setAttribute('aria-label', label('Read the result aloud'));
    if (button.getAttribute('data-voice-only') === '1') button.click();
  };
  document.addEventListener('lightwork:answer-ready', function () { if (owner) owner.stop(); });
  document.addEventListener('lightwork:answer-panel-before-update', function () {
    if (owner) owner.dispose(); owner = null;
  });
  document.addEventListener('lightwork:answer-panel-updated', function () {
    var button = document.getElementById('read-aloud');
    // Refresh never starts another paid voice request without a new click.
    if (button) button.removeAttribute('data-voice-only');
    window.lwReadAloud(button);
  });
  window.addEventListener('pagehide', function () { if (owner) owner.stop(); });
})();
