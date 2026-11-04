/* Finance command center: "Check separation of duties" runs the same check as
   the finance roster check and lists what it found in plain sentences. */
(function () {
  'use strict';

  var button = document.getElementById('fb-sod-check');
  if (!button) return;
  var status = document.getElementById('fb-sod-check-status');
  var out = document.getElementById('fb-sod-check-out');

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  button.addEventListener('click', async function () {
    button.disabled = true;
    out.textContent = '';
    status.textContent = 'Checking…';
    try {
      var response = await window.fetch('/api/v1/finance/sod-check', {
        credentials: 'same-origin', cache: 'no-store', headers: {Accept: 'application/json'}
      });
      if (!response.ok) throw response;
      var data = await response.json();
      status.textContent = data.summary;
      if (data.findings.length) {
        var list = el('ul', 'fb-sod-findings');
        data.findings.forEach(function (finding) {
          var item = el('li');
          item.appendChild(el('strong', null, finding.team + ': '));
          item.appendChild(document.createTextNode(finding.sentence));
          list.appendChild(item);
        });
        out.appendChild(list);
      }
      var details = el('details');
      details.appendChild(el('summary', null, 'Technical details'));
      var pre = el('pre', 'governance-output');
      pre.textContent = data.technical.join('\n');
      details.appendChild(pre);
      out.appendChild(details);
    } catch (failure) {
      status.textContent = window.mvErrorText
        ? window.mvErrorText(failure, 'check separation of duties')
        : 'Could not check separation of duties. Try again.';
    } finally {
      button.disabled = false;
    }
  });
})();
