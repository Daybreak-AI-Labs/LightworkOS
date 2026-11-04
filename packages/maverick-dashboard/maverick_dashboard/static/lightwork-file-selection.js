// Review and remove selected files without clearing the rest of a draft.
(function () {
  'use strict';
  function text(source, values) { return window.LightworkI18n ? window.LightworkI18n.text(source, values) : source.replace(/\{(\w+)\}/g, function (_, key) { return (values || {})[key] === undefined ? '{' + key + '}' : values[key]; }); }
  function copy(node, source, values) { if (window.LightworkI18n) window.LightworkI18n.set(node, source, values); else node.textContent = text(source, values); }
  function product(source, values) { var node = document.createElement('span'); copy(node, source, values); return node; }
  function user(value) { var node = document.createElement('bdi'); node.lang = 'und'; node.dir = 'auto'; node.dataset.userContent = ''; node.textContent = value; return node; }
  ['attach-input', 'reply-files'].forEach(function (id) {
    var input = document.getElementById(id);
    if (!input) return;
    var host = document.createElement('div'); host.className = 'panel'; host.hidden = true;
    var list = document.createElement('ul'); list.setAttribute('aria-label', text('Files selected for this message')); list.lang = window.LightworkI18n ? window.LightworkI18n.languageFor('Files selected for this message') : 'en';
    var status = document.createElement('p'); status.setAttribute('role', 'status');
    var clear = document.createElement('button'); clear.type = 'button'; clear.className = 'btn btn--ghost'; copy(clear, 'Remove all selected files');
    host.append(list, clear, status); input.closest('form').after(host);
    function remove(index) {
      try {
        var transfer = new DataTransfer();
        Array.from(input.files).forEach(function (file, i) { if (i !== index) transfer.items.add(file); });
        input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles: true}));
      } catch (_) { copy(status, 'This browser cannot remove one file. Choose Remove all selected files, then select the files to keep.'); }
    }
    function render() {
      list.replaceChildren(); status.textContent = ''; host.hidden = !input.files.length;
      var seen = new Set();
      Array.from(input.files).forEach(function (file, index) {
        var row = document.createElement('li');
        var key = file.name + ':' + file.size + ':' + file.lastModified;
        var size = window.LightworkI18n ? window.LightworkI18n.number(Math.ceil(file.size / 1024), {style: 'unit', unit: 'kilobyte', unitDisplay: 'short'}) : Math.ceil(file.size / 1024) + ' KB';
        row.append(user(file.name), ' · ', file.type ? user(file.type) : product('Unknown type'), ' · ', document.createTextNode(size));
        if (seen.has(key)) row.append(' · ', product('Possible duplicate'));
        row.append(' ');
        seen.add(key);
        var button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn--ghost';
        copy(button, 'Remove {file}', {file: file.name}); button.addEventListener('click', function () { remove(index); });
        row.append(button); list.append(row);
      });
      if (input.files.length > 128) copy(status, 'Choose at most 128 files. The server checks file type, size and workspace limits before admission.');
    }
    clear.addEventListener('click', function () { input.value = ''; input.dispatchEvent(new Event('change', {bubbles: true})); });
    input.addEventListener('change', render);
    window.addEventListener('lightwork:composer-sent', function () { render(); });
    render();
  });
}());
