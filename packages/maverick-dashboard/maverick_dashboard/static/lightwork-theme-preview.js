/* Preview only the selected colour row; never recolour the editor itself. */
(function () {
  'use strict';
  function luminance(hex) {
    var value = hex.slice(1);
    if (value.length === 3) value = value.split('').map(function (c) { return c + c; }).join('');
    return [0, 2, 4].reduce(function (total, offset, index) {
      var channel = parseInt(value.slice(offset, offset + 2), 16) / 255;
      return total + (channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + .055) / 1.055, 2.4)) * [.2126, .7152, .0722][index];
    }, 0);
  }
  function contrast(first, second) {
    var a = luminance(first), b = luminance(second);
    return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
  }
  function values(row) {
    var result = {};
    row.querySelectorAll('[data-cell]').forEach(function (cell) {
      var input = cell.querySelector('[data-cell-input]'), use = cell.querySelector('[data-cell-use]');
      if (input && (!use || use.checked) && /^#(?:[a-f0-9]{3}|[a-f0-9]{6})$/i.test(input.value)) result[cell.dataset.cell] = input.value;
    });
    return result;
  }
  function preview(event) {
    var row = event.target.closest('[data-setting-id="dashboard.themes"] [data-grid-row]');
    if (!row) return;
    var owner = row.closest('[data-setting-id]'), panel = owner.querySelector('[data-theme-preview]');
    if (!panel) {
      panel = document.createElement('section'); panel.dataset.themePreview = ''; panel.setAttribute('aria-label', 'Colour accessibility preview');
      owner.appendChild(panel);
    }
    var palette = values(row), problems = [];
    ['bg', 'panel', 'text', 'accent'].forEach(function (key) { if (!palette[key]) problems.push('Choose ' + key + ' before saving.'); });
    ['border', 'muted', 'warn', 'danger'].forEach(function (key) {
      if (!palette[key] && palette.text) palette[key] = palette.text;
    });
    if (!problems.length) ['bg', 'panel'].forEach(function (background) {
      ['text', 'muted', 'accent', 'warn', 'danger', 'border'].forEach(function (foreground) {
        if (!palette[foreground]) return;
        var ratio = contrast(palette[foreground], palette[background]), minimum = foreground === 'border' ? 3 : 4.5;
        if (ratio < minimum) problems.push(foreground + ' on ' + background + ': ' + ratio.toFixed(2) + ':1; needs ' + minimum + ':1.');
      });
    });
    panel.replaceChildren();
    var message = document.createElement('p'); message.setAttribute('role', 'status');
    message.textContent = problems.length ? 'Improve contrast before saving. ' + problems.join(' ') : 'Text, status, control and focus colours meet the checked contrast thresholds. Device and background review is still needed.';
    panel.appendChild(message);
    var sample = document.createElement('div'); sample.style.cssText = 'padding:1rem;border-radius:.5rem';
    sample.style.background = palette.panel || '#fff'; sample.style.color = palette.text || '#111';
    var label = document.createElement('label'); label.textContent = 'Example task name ';
    var field = document.createElement('input'); field.value = 'Quarterly review'; field.readOnly = true;
    field.style.border = '2px solid ' + (palette.border || palette.accent || '#111'); field.style.background = palette.bg || '#fff'; field.style.color = palette.text || '#111';
    label.appendChild(field); sample.appendChild(label);
    var button = document.createElement('button'); button.type = 'button'; button.textContent = 'Focus example';
    button.style.outline = '3px solid ' + (palette.accent || '#111'); button.style.margin = '1rem'; sample.appendChild(button);
    var disabled = document.createElement('button'); disabled.textContent = 'Unavailable example'; disabled.disabled = true; sample.appendChild(disabled);
    ['warn', 'danger'].forEach(function (key) {
      var badge = document.createElement('p'); badge.textContent = key === 'warn' ? 'Warning: review needed' : 'Error: task could not finish'; badge.style.color = palette[key] || palette.text || '#111'; sample.appendChild(badge);
    });
    var chart = document.createElement('meter'); chart.min = 0; chart.max = 100; chart.value = 60; chart.setAttribute('aria-label', 'Example progress: 60 percent'); sample.appendChild(chart);
    panel.appendChild(sample);
    var advice = document.createElement('p'); advice.textContent = 'The editor keeps its current colours. Omitted optional colours use this theme\'s text colour. Older unreadable saved palettes use readable derived colours so settings remain reachable.'; panel.appendChild(advice);
  }
  document.addEventListener('input', preview);
  document.addEventListener('focusin', preview);
})();
