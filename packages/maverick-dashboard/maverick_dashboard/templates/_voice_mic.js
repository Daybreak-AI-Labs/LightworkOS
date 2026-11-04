/* Shared mic helpers (Jinja-included into chat.html / chat_goal.html).
 *
 * lwVoiceToWav16k(blob) -> Promise<Blob>
 *   Re-encodes a MediaRecorder clip (webm/ogg) to 16 kHz mono PCM16 WAV in
 *   the browser — exactly what the server's local Whisper engines read with
 *   NO ffmpeg installed. Resolves with the ORIGINAL blob when Web Audio
 *   can't decode, so the server-side conversion chain still gets its shot.
 *
 * lwVoiceUpload(blob, opts) -> Promise
 *   Encodes then POSTs to /api/v1/voice/transcribe. A 503 WITH Retry-After
 *   means the server is still warming the local model (first-run download):
 *   retry a few times with opts.onStatus feedback. A terminal 503 (no
 *   Retry-After) calls opts.onFallback (browser speech recognition).
 *   opts: { onResult(text), onFallback(), onStatus(msg), filename }
 */
function lwVoiceToWav16k(blob) {
  var AC = window.AudioContext || window.webkitAudioContext;
  if (!AC || !window.OfflineAudioContext) return Promise.resolve(blob);
  return blob.arrayBuffer().then(function (buf) {
    var ctx = new AC();
    return ctx.decodeAudioData(buf).then(function (audio) {
      ctx.close();
      var frames = Math.max(1, Math.ceil(audio.duration * 16000));
      var off = new OfflineAudioContext(1, frames, 16000);
      var src = off.createBufferSource();
      src.buffer = audio;
      src.connect(off.destination);
      src.start();
      return off.startRendering();
    });
  }).then(function (rendered) {
    var pcm = rendered.getChannelData(0);
    var out = new DataView(new ArrayBuffer(44 + pcm.length * 2));
    function str(o, s) { for (var i = 0; i < s.length; i++) out.setUint8(o + i, s.charCodeAt(i)); }
    str(0, 'RIFF'); out.setUint32(4, 36 + pcm.length * 2, true); str(8, 'WAVE');
    str(12, 'fmt '); out.setUint32(16, 16, true); out.setUint16(20, 1, true);
    out.setUint16(22, 1, true); out.setUint32(24, 16000, true);
    out.setUint32(28, 32000, true); out.setUint16(32, 2, true); out.setUint16(34, 16, true);
    str(36, 'data'); out.setUint32(40, pcm.length * 2, true);
    for (var i = 0; i < pcm.length; i++) {
      var s = Math.max(-1, Math.min(1, pcm[i]));
      out.setInt16(44 + i * 2, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
    }
    return new Blob([out.buffer], { type: 'audio/wav' });
  }).catch(function () { return blob; });
}

function lwVoiceUpload(blob, opts) {
  opts = opts || {};
  var attempts = 0;
  function post(body, filename) {
    var fd = new FormData();
    fd.append('file', body, filename);
    return window.mvFetchJSON('/api/v1/voice/transcribe', { method: 'POST', body: fd })
      .then(function (d) { if (d && opts.onResult) opts.onResult(d.text); }, function (failure) {
        var later = failure.headers && typeof failure.headers.get === 'function' && failure.headers.get('Retry-After');
        if (failure.status === 503 && later && attempts < 3) {
          attempts += 1;
          if (opts.onStatus) opts.onStatus(window.LightworkI18n ? window.LightworkI18n.text('Setting up voice (first use)…') : 'Setting up voice (first use)…');
          return new Promise(function (res) { setTimeout(res, 4000); })
            .then(function () { return post(body, filename); });
        }
        if (failure.status === 503) { if (opts.onFallback) opts.onFallback(); return null; }
        if (!failure.status) throw failure;
        throw new Error('We couldn\u2019t turn your recording into text. Try again, or type your message.');
      });
  }
  return lwVoiceToWav16k(blob).then(function (encoded) {
    var name = encoded === blob
      ? (opts.filename || 'voice-command.webm')
      : 'voice-command.wav';
    return post(encoded, name);
  });
}
