(function () {
  'use strict';
  const data = document.getElementById('model-guidance-data');
  const filter = document.getElementById('model-capability-filter');
  if (!data || !filter) return;
  let metadata;
  try { metadata = JSON.parse(data.textContent); } catch (_) { return; }
  const picks = Array.from(document.querySelectorAll('[data-model-picker]'));
  function yesNo(value) { return value === true ? 'Reported support' : value === false ? 'Reported unsupported' : 'Unknown'; }
  function matches(item) {
    if (filter.value === 'all') return true;
    if (filter.value === 'unknown') return item.tools == null || item.vision == null;
    return item[filter.value] === true;
  }
  picks.forEach(function (picker, index) {
    const details = document.createElement('div');
    details.className = 'muted';
    details.id = 'model-guidance-' + index;
    details.setAttribute('role', 'status');
    details.setAttribute('aria-live', 'polite');
    picker.setAttribute('aria-describedby', [picker.getAttribute('aria-describedby'), details.id].filter(Boolean).join(' '));
    picker.parentElement.appendChild(details);
    function refresh() {
      Array.from(picker.options).forEach(function (option) {
        // Never silently replace a selected model when filtering.
        option.hidden = !!option.value && option.value !== '__custom__' && option.value !== picker.value && !matches(metadata[option.value] || {});
      });
      details.replaceChildren();
      if (!picker.value) { details.textContent = 'Follows the effective default. Runtime limits and approved-model policy still apply.'; return; }
      const item = metadata[picker.value] || {};
      const lines = [
        'Tools: ' + yesNo(item.tools) + '. Images: ' + yesNo(item.vision) + '.',
        'Context: ' + (item.context_tokens ? item.context_tokens.toLocaleString() + ' tokens' : 'Unknown') +
          '. Output limit: ' + (item.output_tokens ? item.output_tokens.toLocaleString() + ' tokens' : 'Unknown') + '.',
        'Latency: Unknown; depends on provider and workload.'
      ];
      if (item.tools === false) lines.unshift('Warning: this model reports no tool support. Task roles that use tools may not work.');
      if (item.vision === false) lines.push('Choose an image-capable model for image tasks.');
      if (item.tools == null || item.vision == null) lines.push('Confirm required capabilities with your provider before saving. Unknown is not a successful capability check.');
      if (!matches(item)) lines.push('Your current selection remains visible although it does not match this filter.');
      if (item.fetched_at) {
        const when = new Date(item.fetched_at);
        lines.push('Capabilities: ' + (item.capability_source || 'Unknown') + ', checked ' + (Number.isNaN(when.getTime()) ? 'at an unknown time' : window.mvTimeAbsolute ? window.mvTimeAbsolute(when.getTime()) : when.toLocaleString()) + (item.capability_stale ? ' (stale).' : '.'));
      }
      const price = item.price;
      if (price) {
        lines.push(price.currency + ' per million tokens: input ' + price.input + ', output ' + price.output + '.');
        lines.push('Price as of ' + price.as_of + (price.expired ? ' (expired)' : price.stale ? ' (more than 30 days old)' : '') +
          (price.operator_approved ? '; administrator-entered spending ceiling, not a provider invoice.' :
            price.verified ? '; tracked source.' : '; estimate only, not a provider invoice.'));
        lines.push(price.basis + '. ' + price.applicability);
      } else lines.push('Price unavailable. Under known-price controls, this model stops before a paid request. Choose a priced model or review its rate in Settings below.');
      lines.forEach(function (line) { const paragraph = document.createElement('p'); paragraph.textContent = line; details.appendChild(paragraph); });
      if (price && /^https:\/\//i.test(price.source || '')) {
        const source = document.createElement('a'); source.href = price.source;
        source.textContent = 'Pricing source'; source.rel = 'noopener noreferrer'; source.target = '_blank';
        details.appendChild(source);
      }
    }
    picker.addEventListener('change', refresh);
    filter.addEventListener('change', refresh);
    refresh();
  });
})();
