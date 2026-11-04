// Pure, DOM-free flow (de)serialization for the visual designer. Kept in its
// own file so it can be unit-tested under node (see tests/js/flow_designer_core.test.js)
// AND included into the designer template. No DOM, no globals beyond FDCore.
var FDCore = (function () {
  'use strict';
  var NODE_DEFAULTS = {
    params: {}, brief: '', tool: '', condition: '', if_true: null, if_false: null,
    cases: [], items: '', var: 'item', limit: 0, concurrent: false, concurrency: 0, prompt: '',
    choices: [], assignee: '', expires_after: 0, on_expire: null, form: [],
    seconds: 0, flow_ref: '',
    retries: 0, retry_backoff: 0, on_error: null, timeout: 0, output: '', label: '',
    assignments: {}, subflow_inputs: {}, body: null, branches: [], next: null,
    learned_operator: null, recipe_step: null
  };
  var SCALARS = ['next', 'tool', 'brief', 'condition', 'if_true', 'if_false',
    'items', 'var', 'prompt', 'flow_ref', 'on_error', 'output', 'label',
    'assignee', 'on_expire'];

  function defaultValue(v) {
    if (Array.isArray(v)) return v.slice();
    if (v && typeof v === 'object') return Object.assign({}, v);
    return v;
  }

  // Upgrade a raw node dict into an editable node object (defaults + id fallback).
  function normalizeNode(nd, i) {
    var n = {}, k;
    for (k in NODE_DEFAULTS) n[k] = defaultValue(NODE_DEFAULTS[k]);
    for (k in (nd || {})) n[k] = nd[k];
    n.id = n.id || ('n' + i);
    return n;
  }

  // Serialize ONE node to the wire dict the server's Flow.from_dict accepts.
  // Recurses into nested body/branches; drops empty sub-flows so they revert to
  // the engine's "no body/branches" validation. Reads only known fields, so it
  // works on both normalized node objects AND raw (never-edited) node dicts.
  function serializeNode(n) {
    var o = { id: n.id, kind: n.kind };
    SCALARS.forEach(function (k) {
      if (n[k] !== '' && n[k] != null) o[k] = n[k];
    });
    if (n.params && Object.keys(n.params).length) o.params = n.params;
    // Preserve the complete evidence-bound attachment across canvas edits.
    // The server validates it and its binding; silently dropping it here would
    // replace learned execution with model work on an unrelated layout save.
    if (n.learned_operator != null) o.learned_operator = n.learned_operator;
    if (n._fdEvidence != null) o._fdEvidence = n._fdEvidence;
    if (typeof n.learned_fallback === 'boolean') o.learned_fallback = n.learned_fallback;
    if (n.recipe_step != null) o.recipe_step = n.recipe_step;
    if (n.seconds) o.seconds = n.seconds;
    if (n.retries) o.retries = n.retries;
    if (n.retry_backoff) o.retry_backoff = n.retry_backoff;
    if (n.timeout) o.timeout = n.timeout;
    if (n.limit) o.limit = n.limit;
    if (n.concurrent) o.concurrent = true;
    if (n.concurrency) o.concurrency = n.concurrency;
    if (n.cases && n.cases.length) o.cases = n.cases;
    if (n.choices && n.choices.length) o.choices = n.choices;
    if (n.expires_after) o.expires_after = n.expires_after;
    if (n.form && n.form.length) o.form = n.form.filter(function (f) { return f && f.name; });
    if (n.assignments && Object.keys(n.assignments).length) o.assignments = n.assignments;
    if (n.subflow_inputs && Object.keys(n.subflow_inputs).length) o.subflow_inputs = n.subflow_inputs;
    if (n.body && n.body.nodes && n.body.nodes.length) o.body = serializeFlow(n.body);
    if (n.branches && n.branches.length) {
      var bs = n.branches.map(serializeFlow).filter(function (b) { return b.nodes.length; });
      if (bs.length) o.branches = bs;
    }
    if (n.x || n.y) { o.x = n.x; o.y = n.y; }
    return o;
  }

  function serializeFlow(f) {
    var out = {
      id: f.id || '', name: f.name || '', start: f.start || '',
      nodes: (f.nodes || []).map(serializeNode)
    };
    if (f.learned_recipe != null) out.learned_recipe = f.learned_recipe;
    if (f.recipe_lineage != null) out.recipe_lineage = f.recipe_lineage;
    if (f.recipe_teaching != null) out.recipe_teaching = f.recipe_teaching;
    if (f._fdEvidence != null) out._fdEvidence = f._fdEvidence;
    return out;
  }

  // Commit raw Params JSON without destroying an invalid draft. The visual
  // editor buffers textarea text in `_paramsRaw`; saving walks the entire
  // graph (including nested loop/scope bodies and parallel branches). A parse
  // failure deliberately leaves that buffer in place so navigating away from
  // the node and back cannot replace the user's text with the last valid
  // object.
  function commitRawParams(f) {
    var errors = [];
    function walk(current, path) {
      (current.nodes || []).forEach(function (n) {
        var nodePath = path ? (path + '/' + n.id) : n.id;
        if (n._paramsRaw !== undefined) {
          try {
            n.params = n._paramsRaw.trim() ? JSON.parse(n._paramsRaw) : {};
            delete n._paramsRaw;
          } catch (e) {
            errors.push(nodePath + '.params');
          }
        }
        if (n.body) walk(n.body, nodePath + '/body');
        (n.branches || []).forEach(function (branch, index) {
          walk(branch, nodePath + '/branch-' + (index + 1));
        });
      });
    }
    walk(f || {}, '');
    return errors;
  }

  // A deep, independent snapshot of a flow (the undo/redo unit). Serialized
  // form, so restoring goes through normalizeNode like a server load.
  function cloneFlow(f) {
    return JSON.parse(JSON.stringify(serializeFlow(f)));
  }

  // Output keys visible to `nodeId` from nodes that can run BEFORE it (any node
  // that reaches it via next/if_true/if_false/on_error) -- the data pills a
  // user clicks to insert an upstream key. Deterministic order: graph order of
  // the flow's nodes. (No double-brace token in this comment: the file is BOTH
  // Jinja-included into the designer AND require()'d by the node tests, so it
  // must stay literal JS with nothing Jinja could try to evaluate.)
  function upstreamOutputs(f, nodeId) {
    var nodes = f.nodes || [];
    var byId = {};
    nodes.forEach(function (n) { byId[n.id] = n; });
    function reaches(fromId, toId) {
      var seen = {}, queue = [fromId];
      while (queue.length) {
        var id = queue.shift();
        if (id === toId) return true;
        if (!id || seen[id]) continue;
        seen[id] = 1;
        var n = byId[id];
        if (!n) continue;
        ['next', 'if_true', 'if_false', 'on_error'].forEach(function (k) {
          if (n[k]) queue.push(n[k]);
        });
      }
      return false;
    }
    var keys = [];
    nodes.forEach(function (n) {
      if (n.id !== nodeId && n.output && reaches(n.id, nodeId) && keys.indexOf(n.output) < 0)
        keys.push(n.output);
    });
    return keys;
  }

  // Client-side structural validation -- the same rules the server's
  // Flow.validate() enforces, so a broken graph is flagged BEFORE the save
  // round-trip. Returns a list of human-readable problems (empty = valid).
  function validateFlow(f) {
    var errs = [];
    var nodes = f.nodes || [];
    if (!nodes.length) return ['flow has no nodes'];
    var ids = {};
    nodes.forEach(function (n) { ids[n.id] = true; });
    if (!f.start || !ids[f.start]) errs.push('start node "' + f.start + '" is not in the flow');
    nodes.forEach(function (n) {
      ['next', 'if_true', 'if_false', 'on_error', 'on_expire'].forEach(function (k) {
        if (n[k] != null && !ids[n[k]]) errs.push(n.id + ': ' + k + ' points at unknown node "' + n[k] + '"');
      });
      if (n.kind === 'action' && !n.tool) errs.push('action ' + n.id + ' has no tool');
      if (n.kind === 'agent' && !n.brief) errs.push('agent ' + n.id + ' has no brief');
      if (n.kind === 'branch' && !n.condition) errs.push('branch ' + n.id + ' has no condition');
      if (n.kind === 'switch') {
        if (!n.condition) errs.push('switch ' + n.id + ' has no key');
        if (!(n.cases && n.cases.length)) errs.push('switch ' + n.id + ' has no cases');
        (n.cases || []).forEach(function (c, i) {
          if (c.to != null && !ids[c.to]) errs.push('switch ' + n.id + ' case ' + i + ' points at unknown node "' + c.to + '"');
        });
      }
      if (n.kind === 'while') {
        if (!n.condition) errs.push('while ' + n.id + ' has no condition');
        if (!(n.body && n.body.nodes && n.body.nodes.length)) errs.push('while ' + n.id + ' has an empty body');
      }
      if (n.kind === 'scope' && !(n.body && n.body.nodes && n.body.nodes.length)) errs.push('scope ' + n.id + ' has an empty body');
      if (n.kind === 'wait_event' && !n.prompt) errs.push('wait ' + n.id + ' has no prompt');
      if (n.kind === 'foreach') {
        if (!n.items) errs.push('foreach ' + n.id + ' has no items key');
        if (!(n.body && n.body.nodes && n.body.nodes.length)) errs.push('foreach ' + n.id + ' has an empty body');
      }
      if (n.kind === 'parallel' && !(n.branches && n.branches.some(function (b) { return b && b.nodes && b.nodes.length; })))
        errs.push('parallel ' + n.id + ' has no branches');
      if (n.kind === 'approval' && !n.prompt) errs.push('approval ' + n.id + ' has no prompt');
      if (n.kind === 'subflow' && !n.flow_ref) errs.push('subflow ' + n.id + ' has no flow reference');
    });
    nestedWaitSteps(f).forEach(function (n) {
      errs.push('Wait for another app step ' + n.id + ' cannot wait inside a loop or parallel path');
    });
    return errs;
  }

  function unreachableNodeIds(f) {
    var nodes = f.nodes || [], byId = {}, seen = {}, queue = f.start ? [f.start] : [];
    nodes.forEach(function (n) { byId[n.id] = n; });
    while (queue.length) {
      var id = queue.shift(), n = byId[id];
      if (!n || seen[id]) continue;
      seen[id] = true;
      var targets = n.kind === 'branch'
        ? [n.if_true || n.next, n.if_false || n.next]
        : n.kind === 'switch'
          ? [n.next].concat((n.cases || []).map(function (c) { return c && (c.to || n.next); }))
          : [n.next];
      if (['agent', 'action', 'scope'].indexOf(n.kind) >= 0) targets.push(n.on_error);
      if (n.kind === 'approval') targets.push(n.on_expire);
      targets.forEach(function (target) { if (target) queue.push(target); });
    }
    return nodes.filter(function (n) { return !seen[n.id]; }).map(function (n) { return n.id; });
  }

  function nestedWaitSteps(f) {
    var found = [];
    function walk(sub) {
      (sub && sub.nodes || []).forEach(function (n) {
        if (n.kind === 'wait_event') found.push(n);
        if (n.body) walk(n.body);
        (n.branches || []).forEach(walk);
      });
    }
    (f.nodes || []).forEach(function (n) {
      if (n.body) walk(n.body);
      (n.branches || []).forEach(walk);
    });
    return found;
  }

  // The same checks in plain words for people: each problem names the step by
  // its label (or its kind of step) instead of an internal id or field name.
  var KIND_WORDS = { agent: 'AI task', action: 'connected action', branch: 'decision', switch: '“choose a path” step',
    foreach: '“repeat for each item” step', while: '“repeat while” step', parallel: '“run together” step',
    approval: 'approval', delay: 'wait', wait_event: '“wait for another app” step', scope: '“handle a failure” step',
    subflow: '“run another flow” step', setvar: '“update data” step' };
  function plainProblems(f) {
    var out = [];
    var nodes = f.nodes || [];
    if (!nodes.length) return ['Add at least one step.'];
    var ids = {};
    nodes.forEach(function (n) { ids[n.id] = true; });
    function name(n) {
      if (n.label && String(n.label).trim()) return 'The step “' + String(n.label).trim() + '”';
      var w = KIND_WORDS[n.kind] || 'step';
      return (/^[aeiouAEIOU]/.test(w) ? 'An ' : 'A ') + w;
    }
    if (!f.start || !ids[f.start]) out.push('Choose which step comes first.');
    nodes.forEach(function (n) {
      var broken = ['next', 'if_true', 'if_false', 'on_error', 'on_expire'].some(function (k) { return n[k] != null && !ids[n[k]]; })
        || (n.cases || []).some(function (c) { return c.to != null && !ids[c.to]; });
      if (broken) out.push(name(n) + ' points to a step that no longer exists. Choose its next step again.');
      if (n.kind === 'action' && !n.tool) out.push(name(n) + ' needs an action chosen.');
      if (n.kind === 'agent' && !n.brief) out.push(name(n) + ' needs instructions for the AI.');
      if ((n.kind === 'branch' || n.kind === 'while') && !n.condition) out.push(name(n) + ' needs a question to check.');
      if (n.kind === 'switch' && !n.condition) out.push(name(n) + ' needs the information to choose by.');
      if (n.kind === 'switch' && !(n.cases && n.cases.length)) out.push(name(n) + ' needs at least one path.');
      if ((n.kind === 'while' || n.kind === 'scope' || n.kind === 'foreach') && !(n.body && n.body.nodes && n.body.nodes.length))
        out.push(name(n) + ' needs at least one step inside it.');
      if (n.kind === 'foreach' && !n.items) out.push(name(n) + ' needs a list to go through.');
      if (n.kind === 'wait_event' && !n.prompt) out.push(name(n) + ' needs to say what it is waiting for.');
      if (n.kind === 'parallel' && !(n.branches && n.branches.some(function (b) { return b && b.nodes && b.nodes.length; })))
        out.push(name(n) + ' needs at least one path with steps.');
      if (n.kind === 'approval' && !n.prompt) out.push(name(n) + ' needs a question for the approver.');
      if (n.kind === 'subflow' && !n.flow_ref) out.push(name(n) + ' needs a flow chosen.');
    });
    var unreachable = unreachableNodeIds(f);
    nodes.forEach(function (n) {
      if (unreachable.indexOf(n.id) >= 0)
        out.push(name(n) + ' can never run. Connect it from an earlier step.');
    });
    nestedWaitSteps(f).forEach(function (n) {
      out.push(name(n) + ' cannot wait inside a repeated or parallel path. Move it to the main flow.');
    });
    return out;
  }

  // The view {x, y, k} that fits every node into a cw x ch canvas with padding.
  // Zoom is clamped to the designer's wheel range; an empty flow gets the
  // default view.
  function fitView(nodes, cw, ch, nodeW, nodeH, pad) {
    if (!nodes || !nodes.length) return { x: 40, y: 20, k: 1 };
    pad = pad == null ? 40 : pad;
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(function (n) {
      minX = Math.min(minX, n.x || 0); minY = Math.min(minY, n.y || 0);
      maxX = Math.max(maxX, (n.x || 0) + nodeW); maxY = Math.max(maxY, (n.y || 0) + nodeH);
    });
    var w = Math.max(1, maxX - minX), h = Math.max(1, maxY - minY);
    var k = Math.min((cw - 2 * pad) / w, (ch - 2 * pad) / h);
    k = Math.max(0.35, Math.min(1, k));
    return {
      x: Math.round((cw - w * k) / 2 - minX * k),
      y: Math.round((ch - h * k) / 2 - minY * k),
      k: k
    };
  }

  // ---- condition grammar (mirrors the server's runner._COND parser) --------
  // Kept HERE (the tested shared module) so the builder UI and any future
  // consumer share one copy; changing an op means updating this + the runner.
  var COND_OPS = ['==', '!=', '>', '<', '>=', '<=', 'contains'];
  var COND_RE = /^\s*(\S+)\s*(==|!=|>=|<=|>|<|contains)\s*(.+?)\s*$/;

  function splitCondition(text, operator) {
    var parts = [], quote = '', start = 0;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (quote) { if (ch === quote) quote = ''; continue; }
      if (ch === "'" || ch === '"') { quote = ch; continue; }
      if (text.slice(i, i + operator.length).toLowerCase() === operator &&
          (i === 0 || /\s/.test(text[i - 1])) &&
          (i + operator.length === text.length || /\s/.test(text[i + operator.length]))) {
        parts.push(text.slice(start, i).trim()); i += operator.length - 1; start = i + 1;
      }
    }
    if (quote) throw new Error('This saved question contains unfinished quotation marks. Its original meaning was kept.');
    parts.push(text.slice(start).trim()); return parts;
  }
  function parseCondition(text) {
    text = String(text || '').trim();
    if (text.length > 16000) throw new Error('This saved question is too large for the visual editor. Its original meaning was kept.');
    if (!text) return [[{key: '', op: '==', kind: 'text', value: ''}]];
    var groups = splitCondition(text, 'or'), count = 0;
    if (groups.length > 32) throw new Error('This saved question has too many groups for the visual editor.');
    return groups.map(function (group) {
      return splitCondition(group, 'and').map(function (part) {
        if (!part || ++count > 64) throw new Error('Every group needs a question; up to 64 questions are supported.');
        var match = COND_RE.exec(part);
        if (!match) {
          if (/\s/.test(part)) throw new Error('This saved question cannot be edited safely. Its original meaning was kept.');
          return {key: part, op: 'truthy', kind: 'text', value: ''};
        }
        var literal = match[3], kind = 'text', value = literal;
        if (literal.length >= 2 && ['"', "'"].includes(literal[0]) && literal[literal.length - 1] === literal[0]) value = literal.slice(1, -1);
        else if (/^(true|false)$/i.test(literal)) { kind = 'boolean'; value = literal.toLowerCase(); }
        else if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(literal) && Number.isFinite(Number(literal))) { kind = 'number'; value = literal; }
        return {key: match[1], op: match[2], kind: kind, value: value, literal: literal};
      });
    });
  }
  function conditionQuestions(groups) {
    var count = 0;
    if (!Array.isArray(groups) || !groups.length || groups.length > 32) throw new Error('Choose between 1 and 32 question groups.');
    var text = groups.map(function (group) {
      if (!Array.isArray(group) || !group.length) throw new Error('Each group needs at least one question.');
      return group.map(function (question) {
        if (++count > 64) throw new Error('Use no more than 64 questions.');
        if (!question.key || /\s/.test(question.key)) throw new Error('Choose the information for every question.');
        if (question.op === 'truthy') return question.key;
        if (!COND_OPS.includes(question.op)) throw new Error('Choose a supported comparison.');
        var value = String(question.value == null ? '' : question.value), literal = question.literal;
        if (literal === undefined) {
          if (question.kind === 'boolean') {
            if (!['true', 'false'].includes(value)) throw new Error('Choose Yes or No.');
            literal = value;
          } else if (question.kind === 'number') {
            if (!/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(value) || !Number.isFinite(Number(value))) throw new Error('Enter a finite number for every number comparison.');
            literal = value;
          } else {
            if (value.includes("'") && value.includes('"')) throw new Error('This text contains both kinds of quotation marks. Choose text with one kind before saving.');
            var quote = value.includes("'") ? '"' : "'"; literal = quote + value + quote;
          }
        }
        return question.key + ' ' + question.op + ' ' + literal;
      }).join(' and ');
    }).join(' or ');
    if (text.length > 16000) throw new Error('Shorten the questions to fit the supported size.');
    return text;
  }
  function conditionProblems(flow) {
    var problems = [];
    (flow.nodes || []).forEach(function (item) {
      if (item._conditionProblem) problems.push((item.label || 'A question step') + ': ' + item._conditionProblem);
      if (item.body) problems = problems.concat(conditionProblems(item.body));
      (item.branches || []).forEach(function (branch) { if (branch) problems = problems.concat(conditionProblems(branch)); });
    });
    return problems;
  }

  return { normalizeNode: normalizeNode, serializeNode: serializeNode,
           serializeFlow: serializeFlow, cloneFlow: cloneFlow,
           commitRawParams: commitRawParams,
           upstreamOutputs: upstreamOutputs, fitView: fitView,
           validateFlow: validateFlow, plainProblems: plainProblems,
           unreachableNodeIds: unreachableNodeIds,
           COND_OPS: COND_OPS, COND_RE: COND_RE,
           parseCondition: parseCondition, conditionQuestions: conditionQuestions,
           conditionProblems: conditionProblems };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDCore;
