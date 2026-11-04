// Learned run inputs are derived from the retained artifact, never Flow.inputs.
// Server graph, lineage, domain and execution checks remain authoritative.
var FDRecipeInputs = (function () {
  'use strict';
  var TYPES = ['object', 'array', 'string', 'integer', 'number', 'boolean', 'null'];
  // The native v1 recipe language admits 512 scalar leaves. Do not reject a
  // valid retained workflow just because the browser form once stopped at 64.
  var MAX_FIELDS = 512, MAX_NODES = 8192;
  var DOMAINS = ['lightwork.action-recipe.v2', 'lightwork.action-choice.v1',
    'lightwork.workflow-transducer.v1', 'lightwork.workflow-memory.v1'];
  function fail(message) { throw new Error('Workflow inputs: ' + message); }
  function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
  function keys(value, allowed) {
    if (!object(value) || Object.keys(value).some(function (key) { return allowed.indexOf(key) < 0; }))
      fail('this workflow needs fields this form cannot display yet. Ask your workspace administrator to review it.');
  }
  function strings(values) {
    return Array.isArray(values) && values.every(function (value) { return typeof value === 'string'; }) &&
      new Set(values).size === values.length;
  }
  function label(path) {
    return path.map(function (part) {
      if (typeof part === 'number') return 'Item ' + (part + 1);
      var words = part.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim();
      return words ? words.charAt(0).toUpperCase() + words.slice(1) : '(unnamed field)';
    }).join(' › ');
  }
  // Keep the original signed evidence opaque. JSON.parse/JSON.stringify alone
  // changes Python float 1.0 into integer 1 and rounds large integer literals.
  // Custody stays with its exact holder through history and encrypted recovery;
  // never look up original evidence by an already-rounded global fingerprint.
  var EVIDENCE = ['learned_recipe', 'recipe_lineage', 'recipe_teaching', 'learned_operator'];
  var RESPONSE_FIELDS = ['artifact', 'value', 'question', 'predictions', 'output'];
  var CUSTODY = '_fdEvidence';
  function projection(value) {
    var remaining = 262144;
    function encode(item, depth) {
      if (--remaining < 0 || depth > 128) fail('the learning evidence is too complex to submit safely.');
      if (Array.isArray(item)) return '[' + item.map(function (child) { return encode(child, depth + 1); }).join(',') + ']';
      if (object(item)) return '{' + Object.keys(item).sort().map(function (key) {
        return JSON.stringify(key) + ':' + encode(item[key], depth + 1);
      }).join(',') + '}';
      return JSON.stringify(item);
    }
    return encode(value, 0);
  }
  function members(raw) {
    var found = new Map(), i = 0;
    function space() { while (/\s/.test(raw.charAt(i)) && i < raw.length) i++; }
    function quoted() {
      var start = i++;
      while (i < raw.length) {
        if (raw[i] === '\\') i += 2;
        else if (raw[i++] === '"') return raw.slice(start, i);
      }
      fail('the saved workflow could not be read. Reopen it and try again.');
    }
    function valueEnd() {
      var depth = 0;
      while (i < raw.length) {
        var char = raw[i];
        if (char === '"') { quoted(); continue; }
        if (char === '[' || char === '{') { if (++depth > 128) fail('this workflow is too large to open safely.'); }
        else if (char === ']' || char === '}') { if (depth === 0) return; depth--; }
        else if (char === ',' && depth === 0) return;
        i++;
      }
    }
    space(); var array = raw[i] === '[';
    if (raw[i++] !== (array ? '[' : '{')) return found;
    while (i < raw.length) {
      space(); if (raw[i] === (array ? ']' : '}')) break;
      var key = array ? found.size : JSON.parse(quoted());
      if (!array) { space(); i++; }
      space(); var start = i;
      valueEnd();
      if (found.has(key)) fail('the saved workflow repeats a field. Reopen a valid copy.');
      found.set(key, raw.slice(start, i).trim());
      if (raw[i] === ',') i++; else break;
    }
    return found;
  }
  function parseText(raw) {
    if (typeof raw !== 'string' || raw.length > 4 * 1024 * 1024) fail('this workflow is too large to open safely.');
    var parsed = JSON.parse(raw), flow = parsed, parts = object(parsed) ? members(raw) : new Map();
    var remaining = 8192, retained = 0;
    function bind(holder, source, extra) {
      if (!object(holder) || --remaining < 0) fail('the saved workflow has too many nested steps to open safely.');
      var spans = members(source), prior = holder[CUSTODY], custody = {}, fields = EVIDENCE.concat(extra || []);
      if (prior != null && (!object(prior) || Object.keys(prior).some(function (key) { return fields.indexOf(key) < 0; })))
        fail('the original learning evidence is unavailable or changed. Reopen the saved workflow before continuing.');
      fields.forEach(function (key) {
        if (holder[key] == null) return;
        var exact = prior && prior[key] != null ? prior[key] : spans.get(key);
        if (typeof exact !== 'string' || exact.length > 2 * 1024 * 1024 ||
            projection(JSON.parse(exact)) !== projection(holder[key]) || (retained += exact.length) > 4 * 1024 * 1024)
          fail('the original learning evidence is unavailable or changed. Reopen the saved workflow before continuing.');
        custody[key] = exact;
      });
      if (Object.keys(custody).length) holder[CUSTODY] = custody; else delete holder[CUSTODY];
      if (Array.isArray(holder.nodes)) {
        var nodes = members(spans.get('nodes'));
        holder.nodes.forEach(function (node, index) { bind(node, nodes.get(index)); });
      }
      if (object(holder.body)) bind(holder.body, spans.get('body'));
      if (Array.isArray(holder.branches)) {
        var branches = members(spans.get('branches'));
        holder.branches.forEach(function (branch, index) { bind(branch, branches.get(index)); });
      }
    }
    if (object(parsed) && !Array.isArray(parsed.nodes)) bind(parsed, raw, RESPONSE_FIELDS);
    else if (Array.isArray(parsed)) {
      var items = members(raw);
      parsed.forEach(function (item, index) { if (object(item)) bind(item, items.get(index), RESPONSE_FIELDS); });
    }
    if (object(parsed) && object(parsed.flow)) { flow = parsed.flow; raw = parts.get('flow'); }
    else if (object(parsed) && object(parsed.draft)) { flow = parsed.draft; raw = parts.get('draft'); }
    if (object(flow) && flow !== parsed) bind(flow, raw);
    else if (object(flow) && Array.isArray(flow.nodes)) bind(flow, raw);
    return parsed;
  }
  function fieldText(holder, key) {
    var exact = holder && holder[CUSTODY] && holder[CUSTODY][key];
    if (EVIDENCE.concat(RESPONSE_FIELDS).indexOf(key) < 0 || typeof exact !== 'string' ||
        exact.length > 2 * 1024 * 1024 || projection(JSON.parse(exact)) !== projection(holder[key]))
      fail('the original learning evidence is unavailable or changed. Reopen the saved workflow before continuing.');
    return exact;
  }
  function flowText(flow) {
    var remaining = 8192, retained = 0;
    function encode(holder) {
      if (!object(holder)) return JSON.stringify(holder);
      if (--remaining < 0) fail('this workflow has too many nested steps to submit safely.');
      return '{' + Object.keys(holder).filter(function (key) { return key !== CUSTODY && holder[key] !== undefined; }).map(function (key) {
        var value = holder[key], exact;
        if (EVIDENCE.indexOf(key) >= 0 && value != null) {
          exact = holder[CUSTODY] && holder[CUSTODY][key];
          if (typeof exact !== 'string' || exact.length > 2 * 1024 * 1024 ||
              projection(JSON.parse(exact)) !== projection(value) || (retained += exact.length) > 4 * 1024 * 1024)
            fail('the original learning evidence is unavailable or changed. Reopen the saved workflow before continuing.');
        } else if ((key === 'nodes' || key === 'branches') && Array.isArray(value)) exact = '[' + value.map(encode).join(',') + ']';
        else if (key === 'body' && object(value)) exact = encode(value);
        else exact = JSON.stringify(value);
        return JSON.stringify(key) + ':' + exact;
      }).join(',') + '}';
    }
    return encode(flow);
  }
  function responseJson(response) { return response.text().then(parseText); }
  // Legacy encrypted drafts can recover custody only from the freshly read,
  // authorized SAME base version, never by reconstructing rounded numbers.
  function inheritEvidence(target, source) {
    var remaining = 8192;
    function visit(left, right) {
      if (!object(left) || !object(right) || --remaining < 0) return;
      EVIDENCE.forEach(function (key) {
        if (left[key] == null || (left[CUSTODY] && left[CUSTODY][key] != null) ||
            !right[CUSTODY] || typeof right[CUSTODY][key] !== 'string' ||
            projection(left[key]) !== projection(right[key])) return;
        if (!left[CUSTODY]) left[CUSTODY] = {};
        left[CUSTODY][key] = right[CUSTODY][key];
      });
      if (Array.isArray(left.nodes) && Array.isArray(right.nodes)) {
        var byId = new Map(right.nodes.map(function (node) { return [node.id, node]; }));
        left.nodes.forEach(function (node) { visit(node, byId.get(node.id)); });
      }
      if (object(left.body)) visit(left.body, right.body);
      if (Array.isArray(left.branches) && Array.isArray(right.branches))
        left.branches.forEach(function (branch, index) { visit(branch, right.branches[index]); });
    }
    visit(target, source);
  }
  function plan(artifact) {
    if (!object(artifact)) fail('the saved workflow is unavailable. Reopen it and try again.');
    var fields = [], remaining = MAX_NODES, rows, consumed = new Set();
    function visit(source, path, legacy) {
      if (--remaining < 0 || path.length > 12) fail('this workflow has too many nested fields for this form. Ask your workspace administrator to review it.');
      var type, children = [], node;
      if (legacy) {
        var identity = JSON.stringify(path);
        source = rows.get(identity);
        if (!source || consumed.has(identity)) fail('the saved fields are incomplete. Reopen a valid workflow.');
        consumed.add(identity); type = source.kind;
        keys(source, ['path', 'kind'].concat(type === 'object' ? ['keys'] : type === 'array' ? ['length'] : []));
      } else {
        if (!object(source)) fail('the saved fields are unavailable. Reopen the workflow.');
        type = source.type;
        var allowed = { object: ['properties', 'required', 'additionalProperties'],
          array: ['items', 'minItems', 'maxItems'], string: ['minLength', 'maxLength'],
          integer: ['minimum', 'maximum'], number: ['minimum', 'maximum'], boolean: [], null: [] };
        if (TYPES.indexOf(type) < 0) fail('this workflow needs a kind of field this form cannot display yet. Ask your workspace administrator to review it.');
        keys(source, ['type'].concat(allowed[type]));
      }
      if (TYPES.indexOf(type) < 0) fail('this workflow needs a kind of field this form cannot display yet.');
      node = { type: type, path: path.slice(), label: label(path), children: children, declared: !legacy };
      if (type === 'object') {
        var names = legacy ? source.keys : object(source.properties) && Object.keys(source.properties);
        if (!strings(names) || names.length > (legacy ? MAX_FIELDS : 64) ||
            names.some(function (key) { return key.length > 1024; }))
          fail('the saved field names cannot be displayed safely. Ask your workspace administrator to review them.');
        if (!legacy && (source.additionalProperties !== false || !strings(source.required) ||
            JSON.stringify(source.required.slice().sort()) !== JSON.stringify(names.slice().sort())))
          fail('the workflow must specify all its fields before this form can be used.');
        names.slice().sort().forEach(function (key) {
          children.push({ key: key, node: visit(legacy ? null : source.properties[key], path.concat(key), legacy) });
        });
      } else if (type === 'array') {
        var count = legacy ? source.length : source.minItems;
        if (!Number.isSafeInteger(count) || count < 0 || count > (legacy ? MAX_FIELDS : 64) ||
            (!legacy && count !== source.maxItems))
          fail('this workflow has a list this form cannot display safely. Ask your workspace administrator to review it.');
        // Validate an empty list's declared item schema too; never ignore an unsupported keyword.
        if (!legacy && count === 0) {
          var before = fields.length;
          visit(source.items, path.concat(0), false);
          fields.splice(before);
        }
        for (var i = 0; i < count; i++) children.push({ key: i, node: visit(legacy ? null : source.items, path.concat(i), legacy) });
      } else {
        if (fields.length >= MAX_FIELDS)
          fail('this workflow needs more than ' + MAX_FIELDS + ' values. Ask your workspace administrator to review it.');
        if (type === 'string') {
          node.min = legacy ? 0 : (source.minLength === undefined ? 0 : source.minLength);
          node.max = legacy ? 1024 : source.maxLength;
          if (!Number.isSafeInteger(node.min) || !Number.isSafeInteger(node.max) || node.min < 0 ||
              node.min > node.max || node.max < 1 || node.max > 1024) fail('the saved text limits are unavailable. Ask your workspace administrator to review them.');
        } else if (type === 'integer' || type === 'number') {
          node.min = legacy ? (type === 'integer' ? -Number.MAX_SAFE_INTEGER : -Number.MAX_VALUE) : source.minimum;
          node.max = legacy ? (type === 'integer' ? Number.MAX_SAFE_INTEGER : Number.MAX_VALUE) : source.maximum;
          if (!Number.isFinite(node.min) || !Number.isFinite(node.max) || node.min > node.max)
            fail('the saved number limits are unavailable. Ask your workspace administrator to review them.');
          if (type === 'integer' && (!Number.isSafeInteger(node.min) || !Number.isSafeInteger(node.max)))
            fail('this workflow allows whole numbers too large to enter safely here. Ask your workspace administrator to review it.');
        }
        node.id = 'recipe-input-' + fields.length;
        fields.push(node);
      }
      return node;
    }
    var tree;
    if (artifact.schema === 'lightwork.action-recipe.v1') {
      if (!Array.isArray(artifact.input_shape) || artifact.input_shape.length > MAX_NODES)
        fail('the saved fields cannot be displayed. Ask your workspace administrator to review them.');
      rows = new Map();
      artifact.input_shape.forEach(function (row) {
        if (!object(row) || !Array.isArray(row.path) || row.path.length > 12 || row.path.some(function (part) {
          return typeof part !== 'string' && !(Number.isSafeInteger(part) && part >= 0);
        })) fail('a saved field name cannot be displayed. Ask your workspace administrator to review it.');
        var key = JSON.stringify(row.path);
        if (rows.has(key)) fail('the saved workflow repeats a field. Reopen a valid copy.');
        rows.set(key, row);
      });
      tree = visit(null, [], true);
      if (consumed.size !== rows.size) fail('some saved fields are disconnected. Ask your workspace administrator to review them.');
    } else if (DOMAINS.indexOf(artifact.schema) >= 0) {
      tree = visit(artifact.domain && artifact.domain.inputs, [], false);
    } else fail('this kind of learned workflow does not have a supported input form yet. Ask your workspace administrator to review it.');
    if (tree.type !== 'object') fail('the saved workflow must declare named input fields.');
    return { tree: tree, fields: fields };
  }
  function scalar(node, raw) {
    if (node.type === 'null') return null;
    if (typeof raw !== 'string') fail(node.label + ': enter a value.');
    if (node.type === 'string') {
      var chars = Array.from(raw);
      if (chars.some(function (char) { var code = char.charCodeAt(0); return char.length === 1 && code >= 0xd800 && code <= 0xdfff; }))
        fail(node.label + ': replace the character that cannot be submitted and try again.');
      if (chars.length < node.min || chars.length > node.max) fail(node.label + ': use ' + node.min + '–' + node.max + ' characters.');
      return raw;
    }
    if (node.type === 'boolean') {
      if (raw !== 'true' && raw !== 'false') fail(node.label + ': choose Yes or No.');
      return raw === 'true';
    }
    raw = raw.trim();
    if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(raw)) fail(node.label + ': enter a decimal number.');
    var value = Number(raw);
    if (!Number.isFinite(value)) fail(node.label + ': enter a valid number.');
    if (node.type === 'integer' && !/^-?\d+$/.test(raw)) fail(node.label + ': enter a whole number without a decimal point.');
    if (node.type === 'integer' && !Number.isSafeInteger(value)) fail(node.label + ': this number is too large to enter safely here.');
    if (value < node.min || value > node.max) fail(node.label + ': enter a value from ' + node.min + ' to ' + node.max + '.');
    return value;
  }
  function read(model, values) {
    var expected = model.fields.filter(function (field) { return field.type !== 'null'; }).map(function (field) { return field.id; }).sort();
    if (!object(values) || JSON.stringify(Object.keys(values).sort()) !== JSON.stringify(expected)) fail('some input fields are missing or changed.');
    function build(node) {
      if (node.type !== 'object' && node.type !== 'array') {
        try { return scalar(node, values[node.id]); }
        catch (error) { error.fieldId = node.id; throw error; }
      }
      var result = node.type === 'array' ? [] : Object.create(null);
      node.children.forEach(function (child) { result[child.key] = build(child.node); });
      return result;
    }
    return { input: build(model.tree) };
  }
  function wireData(model, data) {
    keys(data, ['input']);
    function encode(node, value) {
      if (node.type === 'object' || node.type === 'array') {
        if (node.type === 'object' ? !object(value) : !Array.isArray(value)) fail('the expected fields changed. Reopen the workflow.');
        if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(node.children.map(function (child) { return String(child.key); }).sort()))
          fail('the expected fields changed. Reopen the workflow.');
        var parts = node.children.map(function (child) {
          return (node.type === 'object' ? JSON.stringify(child.key) + ':' : '') + encode(child.node, value[child.key]);
        });
        return node.type === 'object' ? '{' + parts.join(',') + '}' : '[' + parts.join(',') + ']';
      }
      var expectedType = { string: 'string', integer: 'number', number: 'number', boolean: 'boolean', null: 'object' }[node.type];
      if (typeof value !== expectedType || (node.type === 'null' && value !== null)) fail('a value no longer matches its field. Reopen the form.');
      if (node.type !== 'null') scalar(node, String(value));
      var raw = JSON.stringify(value);
      // Python deliberately distinguishes integer and number (float) domains.
      if (node.type === 'number') {
        if (Object.is(value, -0)) return '-0.0';
        if (!/[.eE]/.test(raw)) raw += '.0';
      }
      return raw;
    }
    return '{"input":' + encode(model.tree, data.input) + '}';
  }
  function payloadText(model, payload) {
    return '{' + Object.keys(payload).map(function (key) {
      return JSON.stringify(key) + ':' + (key === 'data' && model ? wireData(model, payload.data) : key === 'flow' ? flowText(payload.flow) : JSON.stringify(payload[key]));
    }).join(',') + '}';
  }
  var open = false;
  function prompt(model, options) {
    if (open) return Promise.resolve(null);
    var dialog = document.createElement('dialog');
    if (typeof dialog.showModal !== 'function') return Promise.reject(new Error('This browser cannot open workflow inputs. Update your browser and try again.'));
    options = options || {}; open = true;
    var opener = options.restoreFocus || document.activeElement;
    dialog.className = 'mv-confirm mv-form fd-recipe-inputs';
    dialog.setAttribute('aria-labelledby', 'recipe-input-title');
    var form = document.createElement('form'); form.className = 'mv-confirm__body';
    form.noValidate = true;
    var heading = document.createElement('h2'); heading.id = 'recipe-input-title'; heading.className = 'mv-form__title'; heading.textContent = options.title || 'Workflow inputs';
    form.appendChild(heading);
    var help = document.createElement('p');
    var inputCount = model.fields.filter(function (field) { return field.type !== 'null'; }).length;
    help.textContent = (inputCount ? 'Enter ' + inputCount + ' value' + (inputCount === 1 ? '' : 's') +
      ' for this case. ' : '') + 'The saved workflow determines the fields. Actions still require their normal approvals.';
    form.appendChild(help);
    var controls = Object.create(null), errors = Object.create(null);
    var fields = document.createElement('div'); fields.className = 'fd-recipe-fields';
    model.fields.forEach(function (field) {
      if (field.type === 'null') return; // Preserved in submission without a meaningless control.
      var wrap = document.createElement('div'); wrap.className = 'mv-form__field';
      var lab = document.createElement(field.type === 'null' ? 'span' : 'label');
      if (field.type !== 'null') lab.setAttribute('for', field.id);
      lab.textContent = field.label;
      wrap.appendChild(lab);
      var control;
      if (field.type === 'null') {
        control = document.createElement('p'); control.textContent = 'No value needed.';
      } else if (field.type === 'boolean') {
        control = document.createElement('select');
        [['', 'Choose…'], ['true', 'Yes'], ['false', 'No']].forEach(function (entry) {
          var option = document.createElement('option'); option.value = entry[0]; option.textContent = entry[1]; control.appendChild(option);
        });
        control.required = true;
      } else if (field.type === 'string') {
        control = document.createElement('textarea'); control.rows = 3; control.autocomplete = 'off';
        control.required = field.min > 0;
      } else {
        control = document.createElement('input'); control.type = 'text'; control.autocomplete = 'off';
        control.inputMode = 'decimal'; control.required = true;
      }
      control.id = field.id; control.className = 'input'; wrap.appendChild(control);
      if (field.type !== 'null') controls[field.id] = control;
      var described = [];
      if (field.declared && field.min !== undefined && (field.type !== 'string' || field.min > 0 || field.max < 1024)) {
        var bounds = document.createElement('p'); bounds.className = 'mv-form__help'; bounds.id = field.id + '-help';
        bounds.textContent = field.type === 'string' ? (field.min ? field.min + '–' + field.max + ' characters.' : 'Up to ' + field.max + ' characters.') :
          (field.type === 'integer' ? 'Whole number' : 'Number') + ', from ' + field.min + ' to ' + field.max + '.';
        described.push(bounds.id); wrap.appendChild(bounds);
      }
      if (field.type !== 'null') {
        var fieldError = document.createElement('p'); fieldError.id = field.id + '-error'; fieldError.className = 'mv-form__err'; fieldError.hidden = true;
        described.push(fieldError.id); errors[field.id] = fieldError; wrap.appendChild(fieldError);
        control.setAttribute('aria-describedby', described.join(' '));
      }
      fields.appendChild(wrap);
    });
    form.appendChild(fields);
    if (!Object.keys(controls).length) { var empty = document.createElement('p'); empty.textContent = 'This workflow has no values to enter.'; form.appendChild(empty); }
    var error = document.createElement('p'); error.className = 'mv-form__err'; error.setAttribute('role', 'alert'); form.appendChild(error);
    var actions = document.createElement('div'); actions.className = 'mv-confirm__row';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.textContent = 'Cancel';
    var submit = document.createElement('button'); submit.type = 'submit'; submit.className = 'btn btn--primary'; submit.textContent = options.okText || 'Continue';
    actions.appendChild(cancel); actions.appendChild(submit); form.appendChild(actions); dialog.appendChild(form); document.body.appendChild(dialog);
    return new Promise(function (resolve) {
      function finish(value) {
        if (!open) return;
        open = false; if (dialog.open) dialog.close(); dialog.remove();
        if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
        resolve(value);
      }
      cancel.addEventListener('click', function () { finish(null); });
      dialog.addEventListener('cancel', function (event) { event.preventDefault(); finish(null); });
      form.addEventListener('submit', function (event) {
        event.preventDefault();
        var values = Object.create(null);
        Object.keys(controls).forEach(function (key) {
          values[key] = controls[key].value; controls[key].removeAttribute('aria-invalid');
          errors[key].hidden = true; errors[key].textContent = '';
        });
        error.textContent = '';
        try { finish(read(model, values)); } catch (err) {
          if (controls[err.fieldId]) {
            errors[err.fieldId].textContent = err.message; errors[err.fieldId].hidden = false;
            controls[err.fieldId].setAttribute('aria-invalid', 'true'); controls[err.fieldId].focus();
            error.textContent = 'Check the highlighted field before continuing.';
          } else error.textContent = err.message;
        }
      });
      dialog.showModal(); (controls[Object.keys(controls)[0]] || submit).focus();
    });
  }
  return { plan: plan, read: read, wireData: wireData, payloadText: payloadText, prompt: prompt,
    parseText: parseText, flowText: flowText, fieldText: fieldText, responseJson: responseJson, inheritEvidence: inheritEvidence };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = FDRecipeInputs;
