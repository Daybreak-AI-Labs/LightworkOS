/* Concierge voice — makes the browser's speech output sound like a person.
 *
 * The bare Web Speech default (whatever robotic voice the OS ships first)
 * is what makes an agent "sound AI". This module fixes the three causes:
 *   1. VOICE — rank the installed voices and pick the most natural one
 *      (neural/premium/enhanced first, known-good named voices next,
 *      novelty and eSpeak voices never), with a persisted user override.
 *   2. TEXT — never speak UI text verbatim: strip markdown/emoji/symbols,
 *      expand citations ("Art. 28" -> "Article 28"), replace record ids
 *      with human phrases, and give acronyms speakable forms.
 *   3. DELIVERY — speak sentence-by-sentence (also dodges Chrome's
 *      long-utterance cutoff) at a slightly brisk, natural rate.
 *
 * Vanilla JS, no deps.
 */
window.lwVoice = (function () {
  'use strict';
  var PREF_KEY = 'lw-voice-name';
  var AVOID = /espeak|compact|robot|whisper|novelty|zarvox|trinoids|albert|bad news|bells|boing|bubbles|cellos|wobble|jester|organ|superstar|fred|junior|kathy|ralph/i;
  var cached = [];

  function refresh() {
    if (!window.speechSynthesis) return [];
    var all = window.speechSynthesis.getVoices() || [];
    cached = all.filter(function (v) {
      return !AVOID.test(v.name || '');
    });
    return cached;
  }
  if (window.speechSynthesis &&
      typeof window.speechSynthesis.addEventListener === 'function') {
    window.speechSynthesis.addEventListener('voiceschanged', refresh);
  }

  function score(v) {
    var n = v.name || '';
    var s = 0;
    if (/natural|neural|premium|enhanced|studio/i.test(n)) s += 30;
    if (/google (us|uk) english/i.test(n)) s += 25;
    if (/samantha|ava|allison|zoe|karen|daniel|moira|serena|tessa|aria|jenny|guy|libby|sonia|ryan|emma/i.test(n)) s += 15;
    if (/^en-us/i.test(v.lang || '')) s += 4;
    if (v.default) s += 1;
    return s;
  }

  function options() {
    var list = cached.length ? cached : refresh();
    return list.slice().sort(function (a, b) { return score(b) - score(a); });
  }

  function best(contentLanguage) {
    var list = options();
    if (!list.length) return null;
    var want = null;
    try { want = window.localStorage.getItem(PREF_KEY); } catch (e) { /* private mode */ }
    if (want) {
      for (var i = 0; i < list.length; i++) {
        if (list[i].name === want) return list[i];
      }
    }
    var language = String(contentLanguage || '').toLowerCase();
    if (/^[a-z]{2,3}(?:-[a-z0-9]+)*$/.test(language) && language !== 'und') {
      var exact = list.find(function (voice) { return (voice.lang || '').toLowerCase() === language; });
      if (exact) return exact;
      var base = language.split('-')[0];
      var matching = list.find(function (voice) { return (voice.lang || '').toLowerCase().split('-')[0] === base; });
      if (matching) return matching;
    }
    // Unknown source language must not be guessed from interface preferences.
    return list.find(function (voice) { return voice.default; }) || null;
  }

  function setVoice(name) {
    try { window.localStorage.setItem(PREF_KEY, name || ''); } catch (e) { /* best effort */ }
  }

  // Speakable forms. The SCREEN text never changes — only what is said.
  // Arrows/dashes become pauses BEFORE the symbol strip so they read as
  // phrasing, not silence.
  var SAY = [
    [/\s*(?:—|–|->|→)\s*/g, ', '],
    [/[✅✓✔✖❌❗️]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|\uD83E[\uDC00-\uDFFF]|[☀-⛿✀-➿]/g, ' '],
    [/https?:\/\/[^\s"')\]]+/gi, 'the link on screen'],
    [/\bOT-ASMT-[\w-]+/gi, 'the OneTrust record'],
    [/\bLW-(?:PIA|DSAR)-[\w-]+/gi, 'this case'],
    [/\bPRV\w+/gi, 'the ticket'],
    [/\bArt\.\s*/gi, 'Article '],
    [/\be\.g\.\s*/gi, 'for example, '],
    [/\bi\.e\.\s*/gi, 'that is, '],
    [/\bDPIA\b/g, 'D P I A'],
    [/\bPIA\b/g, 'P I A'],
    [/\bDSARs\b/g, 'dee-sars'],
    [/\bDSAR\b/g, 'dee-sar'],
    [/\bGDPR\b/g, 'G D P R'],
    [/\bCCPA\b/g, 'C C P A'],
    [/\bRoPA\b/g, 'roh-pah'],
    [/\bSCCs\b/g, 'standard contractual clauses'],
    [/\bSCC\b/g, 'standard contractual clause'],
    [/[*_`#>|]+/g, ' '],
    [/\s*·\s*/g, ', '],
    [/\s{2,}/g, ' '],
  ];

  function humanize(text, contentLanguage) {
    var out = String(text == null ? '' : text);
    if (contentLanguage && !/^en(?:-|$)/i.test(contentLanguage)) return out.trim();
    for (var i = 0; i < SAY.length; i++) out = out.replace(SAY[i][0], SAY[i][1]);
    return out.trim();
  }

  // Sentence-ish chunks, capped so Chrome never hits its cutoff mid-thought.
  var MAX_CHUNK = 200;
  function chunks(text) {
    var parts = text.match(/[^.!?]+[.!?]+["')\]]*\s*|[^.!?]+$/g) || [text];
    var out = [];
    var cur = '';
    for (var i = 0; i < parts.length; i++) {
      if ((cur + parts[i]).length > MAX_CHUNK && cur) { out.push(cur); cur = ''; }
      cur += parts[i];
    }
    if (cur.trim()) out.push(cur);
    return out;
  }

  function speak(text) {
    if (!window.speechSynthesis || !window.SpeechSynthesisUtterance) return false;
    var clean = humanize(text);
    if (!clean) return false;
    var voice = best();
    try { window.speechSynthesis.cancel(); } catch (e) { /* already idle */ }
    chunks(clean).forEach(function (part) {
      var u = new window.SpeechSynthesisUtterance(part.trim());
      if (voice) { u.voice = voice; u.lang = voice.lang; }
      u.rate = 1.04;   // a touch brisk reads as attentive, not rushed
      u.pitch = 1.0;
      window.speechSynthesis.speak(u);
    });
    return true;
  }

  function stop() {
    if (window.speechSynthesis) {
      try { window.speechSynthesis.cancel(); } catch (e) { /* idle */ }
    }
  }

  return { speak: speak, stop: stop, humanize: humanize, options: options,
           best: best, setVoice: setVoice, _chunks: chunks };
})();
