/* Guided forms for the AI assurance page (/security/assurance).
 *
 * Every structured request the page sends is built here from labelled
 * fields, selectors and checkboxes, so nobody types data formats, record
 * references, version numbers or fingerprints.  Fingerprints are computed
 * from a chosen file or typed note; evidence is picked from the approved,
 * current records of the chosen AI system.  The server still validates every
 * value exactly as before.
 */
(function () {
  "use strict";

  const human = value => {
    if (typeof window.mvHuman === "function") return window.mvHuman(value);
    const text = String(value === null || value === undefined ? "" : value).replace(/[_-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  };
  let counter = 0;
  const uid = prefix => `lwaf-${prefix}-${++counter}`;
  const fail = message => { throw new Error(message); };

  const make = (tag, props, ...children) => {
    const node = document.createElement(tag);
    Object.entries(props || {}).forEach(([key, value]) => {
      if (value === undefined || value === null || value === false) return;
      if (key === "className") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key in node && typeof value !== "string") node[key] = value;
      else node.setAttribute(key, value === true ? "" : String(value));
    });
    children.flat().forEach(child => {
      if (child === null || child === undefined || child === false) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  };

  /* Turn words a person typed into the short lowercase name the server
   * stores ("Chief risk officer" -> "chief-risk-officer"). */
  const slug = (value, max = 64) => {
    let text = String(value || "").normalize("NFKD").replace(/[̀-ͯ]/g, "")
      .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    if (text.length > max) text = text.slice(0, max).replace(/-+$/g, "");
    return text;
  };
  /* A value that is already a stored short name is kept exactly, so editing
   * a saved record never renames it. */
  const toName = (value, max = 64) => {
    const text = String(value || "").trim();
    if (text.length <= max && /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/.test(text)) return text;
    return slug(text, max);
  };
  const sortKeys = value => {
    if (Array.isArray(value)) return value.map(sortKeys);
    if (value && typeof value === "object") {
      return Object.keys(value).sort().reduce((out, key) => { out[key] = sortKeys(value[key]); return out; }, {});
    }
    return value;
  };
  const canonical = value => JSON.stringify(sortKeys(value));
  const hex = buffer => Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("");
  const sha256Hex = async bytes => hex(await window.crypto.subtle.digest("SHA-256", bytes));
  const MAX_FILE_BYTES = 50 * 1024 * 1024;
  const readBytes = async file => {
    if (typeof file.arrayBuffer === "function") return file.arrayBuffer();
    return new Response(file).arrayBuffer();
  };
  const readText = async file => {
    if (typeof file.text === "function") return file.text();
    return new Response(file).text();
  };
  const fileFingerprint = async file => {
    if (file.size > MAX_FILE_BYTES) fail("That file is too large. Choose a file under 50 MB.");
    return sha256Hex(await readBytes(file));
  };
  const textFingerprint = async text => sha256Hex(new TextEncoder().encode(String(text)));
  /* Read a result file an outside tool produced (never typed by a person). */
  const readRecordFile = async (file, what) => {
    if (!file) fail(`Choose the ${what} file first.`);
    if (file.size > 256 * 1024) fail(`That ${what} file is too large to be a valid result.`);
    let parsed;
    try { parsed = JSON.parse(await readText(file)); } catch (_error) { parsed = null; }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      fail(`That file isn't a ${what} file Lightwork can read. Choose the file your tool produced.`);
    }
    return parsed;
  };

  /* Approved, current evidence for one AI system, offered as checkboxes. */
  class EvidencePool {
    constructor() { this.rows = []; this.listeners = new Set(); this.loaded = false; }
    set(rows) {
      this.loaded = true;
      this.rows = (Array.isArray(rows) ? rows : []).filter(EvidencePool.eligible).map(row => ({
        id: String(row.id || row.evidence_id),
        digest: String(row.payload_sha256 || row.digest || ""),
        label: EvidencePool.label(row)
      })).filter(row => row.id && /^[0-9a-f]{64}$/.test(row.digest));
      this.listeners.forEach(listener => listener());
    }
    clear() { this.loaded = false; this.rows = []; this.listeners.forEach(listener => listener()); }
    static eligible(row) {
      if (!row || row.status !== "approved") return false;
      if ("result" in row && row.result !== "passed") return false;
      return row.current === true || row.freshness === "current";
    }
    static label(row) {
      const when = Number(row.observed_at) > 0 ? (window.mvDateAbsolute ? window.mvDateAbsolute(Number(row.observed_at)) : new Date(Number(row.observed_at) * 1000).toLocaleDateString()) : "";
      const what = human(row.evidence_kind || "evidence");
      const about = String(row.summary || "").trim().slice(0, 120);
      return [what, about, when].filter(Boolean).join(" · ");
    }
    subscribe(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
    has(id) { return this.rows.some(row => row.id === id); }
    bindings(ids) {
      return Array.from(new Set(ids)).sort().map(id => {
        const row = this.rows.find(item => item.id === id);
        if (!row) fail("Some chosen evidence is no longer approved and current. Choose the evidence again.");
        return {evidence_id: row.id, digest: row.digest};
      });
    }
  }

  /* Collect every evidence reference used anywhere in a built value. */
  const citedEvidence = value => {
    const found = new Set();
    const walk = item => {
      if (Array.isArray(item)) { item.forEach(walk); return; }
      if (!item || typeof item !== "object") return;
      Object.entries(item).forEach(([key, child]) => {
        if (key === "evidence_ids" && Array.isArray(child)) child.forEach(id => found.add(String(id)));
        else walk(child);
      });
    };
    walk(value);
    return Array.from(found).sort();
  };

  const labelled = (spec, control, extra) => {
    const hint = spec.hint ? make("span", {className: "assurance-muted", text: spec.hint}) : null;
    return make("label", {className: spec.wide ? "assurance-form__wide" : null}, spec.label, " ", hint, control, extra || null);
  };
  const toDateInput = seconds => {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return "";
    return new Date(value * 1000).toISOString().slice(0, 10);
  };
  const toDateTimeInput = seconds => {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return "";
    const date = new Date(value * 1000);
    const pad = number => String(number).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  };
  const emptyOf = (spec, fallback) => (Object.prototype.hasOwnProperty.call(spec, "empty") ? spec.empty : fallback);
  const requiredMessage = spec => `Fill in “${spec.label}”.`;

  const builders = {
    text(spec) {
      const control = spec.rows
        ? make("textarea", {className: "textarea", rows: spec.rows, maxlength: spec.max || 4000, name: spec.name})
        : make("input", {className: "input", maxlength: spec.max || 512, autocomplete: "off", name: spec.name});
      if (spec.placeholder) control.placeholder = spec.placeholder;
      if (spec.required) control.required = true;
      if (spec.value !== undefined) control.value = spec.value;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { control.value = value === null || value === undefined ? "" : String(value); },
        collect: async () => {
          const value = String(control.value || "").trim();
          if (!value) { if (spec.required) fail(requiredMessage(spec)); return emptyOf(spec, ""); }
          return value;
        }
      };
    },
    token(spec) {
      const control = make("input", {className: "input", maxlength: 200, autocomplete: "off", name: spec.name});
      if (spec.placeholder) control.placeholder = spec.placeholder;
      if (spec.required !== false) control.required = true;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { control.value = value === null || value === undefined ? "" : String(value); },
        collect: async () => {
          const value = toName(control.value, spec.max || 64);
          if (!value) { if (spec.required !== false) fail(`Fill in “${spec.label}” using letters or numbers.`); return emptyOf(spec, ""); }
          return value;
        }
      };
    },
    number(spec) {
      const control = make("input", {className: "input", type: "number", name: spec.name,
        min: spec.min, max: spec.max, step: spec.integer ? 1 : (spec.step || "any")});
      if (spec.required) control.required = true;
      if (spec.value !== undefined) control.value = spec.value;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { control.value = value === null || value === undefined ? "" : String(value); },
        collect: async () => {
          const raw = String(control.value || "").trim();
          if (!raw) { if (spec.required) fail(`Enter a number for “${spec.label}”.`); return emptyOf(spec, null); }
          const value = Number(raw);
          if (!Number.isFinite(value) || (spec.integer && !Number.isInteger(value))) {
            fail(`Enter a ${spec.integer ? "whole " : ""}number for “${spec.label}”.`);
          }
          if ((spec.min !== undefined && value < spec.min) || (spec.max !== undefined && value > spec.max)) {
            fail(`“${spec.label}” must be between ${spec.min} and ${spec.max}.`);
          }
          return value;
        }
      };
    },
    choice(spec) {
      const control = make("select", {className: "select", name: spec.name});
      const setOptions = options => {
        const previous = control.value;
        control.replaceChildren();
        if (spec.placeholder) control.appendChild(new Option(spec.placeholder, ""));
        (options || []).forEach(option => {
          const [value, text] = Array.isArray(option) ? option : [option, human(option)];
          control.appendChild(new Option(text, value));
        });
        if (Array.from(control.options).some(option => option.value === previous)) control.value = previous;
        else if (spec.value !== undefined && Array.from(control.options).some(option => option.value === spec.value)) control.value = spec.value;
      };
      setOptions(spec.options);
      if (spec.required) control.required = true;
      return {
        el: labelled(spec, control), control, setOptions,
        current: () => control.value,
        load: value => { if (value !== null && value !== undefined) control.value = String(value); control.dispatchEvent(new Event("change", {bubbles: true})); },
        collect: async () => {
          const value = control.value;
          if (!value) { if (spec.required) fail(`Choose an option for “${spec.label}”.`); return emptyOf(spec, null); }
          return value;
        }
      };
    },
    boolean(spec) {
      const control = make("input", {type: "checkbox", name: spec.name});
      if (spec.required) control.required = true;
      return {
        el: make("label", {className: "assurance-form__wide"}, control, " ", spec.label), control,
        current: () => control.checked,
        load: value => { control.checked = value === true; },
        collect: async () => {
          if (spec.required && !control.checked) fail(`Tick “${spec.label}” to continue.`);
          return control.checked;
        }
      };
    },
    date(spec) {
      const control = make("input", {className: "input", type: "date", name: spec.name});
      if (spec.required) control.required = true;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { control.value = toDateInput(value); },
        collect: async () => {
          if (!control.value) { if (spec.required) fail(`Choose a date for “${spec.label}”.`); return emptyOf(spec, null); }
          const [year, month, day] = control.value.split("-").map(Number);
          const seconds = Date.UTC(year, month - 1, day) / 1000;
          if (!Number.isFinite(seconds) || seconds <= 0) fail(`Choose a valid date for “${spec.label}”.`);
          return seconds;
        }
      };
    },
    datetime(spec) {
      const control = make("input", {className: "input", type: "datetime-local", name: spec.name});
      if (spec.required) control.required = true;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { control.value = toDateTimeInput(value); },
        collect: async () => {
          if (!control.value) { if (spec.required) fail(`Choose a date and time for “${spec.label}”.`); return emptyOf(spec, null); }
          const milliseconds = Date.parse(control.value);
          if (!Number.isFinite(milliseconds)) fail(`Choose a valid date and time for “${spec.label}”.`);
          return Math.floor(milliseconds / 1000);
        }
      };
    },
    file(spec) {
      const control = make("input", {className: "input", type: "file"});
      const note = make("span", {className: "assurance-muted", role: "status"});
      let previous = null;
      return {
        el: labelled(spec, control, note), control,
        current: () => (control.files && control.files[0]) || previous,
        load: value => {
          previous = typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? value : null;
          note.textContent = previous ? "The file chosen last time is kept unless you choose a new one." : "";
        },
        collect: async () => {
          const file = control.files && control.files[0];
          if (file) return fileFingerprint(file);
          if (previous) return previous;
          if (spec.required !== false) fail(`Choose a file for “${spec.label}”.`);
          return emptyOf(spec, null);
        }
      };
    },
    note(spec) {
      const control = make("textarea", {className: "textarea", rows: spec.rows || 2, maxlength: 8000});
      let previous = null;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { previous = typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? value : null; },
        collect: async () => {
          const text = String(control.value || "").trim();
          if (text) return textFingerprint(text);
          if (previous) return previous;
          if (spec.required) fail(requiredMessage(spec));
          return emptyOf(spec, null);
        }
      };
    },
    lines(spec) {
      const control = make("textarea", {className: "textarea", rows: spec.rows || 3, maxlength: spec.max || 16000});
      if (spec.min) control.required = true;
      return {
        el: labelled({...spec, wide: true}, control), control,
        current: () => control.value,
        load: value => { control.value = Array.isArray(value) ? value.join("\n") : ""; },
        collect: async () => {
          const items = String(control.value || "").split(/\r?\n/).map(line => line.trim()).filter(Boolean);
          if (spec.min && items.length < spec.min) fail(`Add at least one line to “${spec.label}”.`);
          if (spec.limit && items.length > spec.limit) fail(`“${spec.label}” can have at most ${spec.limit} lines.`);
          return items;
        }
      };
    },
    words(spec) {
      const control = make("input", {className: "input", maxlength: 4096, autocomplete: "off", name: spec.name});
      if (spec.placeholder) control.placeholder = spec.placeholder;
      return {
        el: labelled(spec, control), control,
        current: () => control.value,
        load: value => { control.value = Array.isArray(value) ? value.join(", ") : ""; },
        collect: async () => {
          const items = Array.from(new Set(String(control.value || "").split(",").map(item => spec.raw ? item.trim() : toName(item, spec.max || 64)).filter(Boolean)));
          if (spec.required && !items.length) fail(requiredMessage(spec));
          if (spec.limit && items.length > spec.limit) fail(`“${spec.label}” can have at most ${spec.limit} entries.`);
          return spec.sorted ? items.sort() : items;
        }
      };
    },
    checkset(spec) {
      const box = make("div", {className: "assurance-checks"});
      const other = spec.other ? make("input", {className: "input", maxlength: 1024, autocomplete: "off"}) : null;
      const fieldset = make("fieldset", {className: "assurance-form__wide"}, make("legend", {text: spec.label}), box,
        other ? make("label", {}, spec.otherLabel || "Others (separated by commas)", " ", other) : null);
      let options = [];
      const setOptions = next => {
        const chosen = new Set(Array.from(box.querySelectorAll("input:checked")).map(input => input.value));
        options = (next || []).map(option => (Array.isArray(option) ? option : [option, human(option)]));
        box.replaceChildren();
        if (!options.length && spec.emptyText) box.appendChild(make("p", {className: "assurance-muted", text: spec.emptyText}));
        options.forEach(([value, text]) => {
          const input = make("input", {type: "checkbox", value});
          input.checked = chosen.has(value);
          box.appendChild(make("label", {}, input, " ", text));
        });
      };
      setOptions(spec.options);
      return {
        el: fieldset, setOptions,
        current: () => Array.from(box.querySelectorAll("input:checked")).map(input => input.value),
        load: value => {
          const wanted = new Set(Array.isArray(value) ? value.map(String) : []);
          const known = new Set(options.map(([item]) => item));
          box.querySelectorAll("input[type=checkbox]").forEach(input => { input.checked = wanted.has(input.value); });
          if (other) other.value = Array.from(wanted).filter(item => !known.has(item)).join(", ");
        },
        collect: async () => {
          const values = Array.from(box.querySelectorAll("input:checked")).map(input => input.value);
          if (other) String(other.value || "").split(",").map(item => toName(item)).filter(Boolean).forEach(item => values.push(item));
          const unique = Array.from(new Set(values));
          if (spec.required && !unique.length) fail(`Choose at least one option for “${spec.label}”.`);
          return unique;
        }
      };
    },
    evidence(spec, ctx) {
      const pool = ctx.pool;
      const box = make("div", {className: "assurance-checks"});
      const fieldset = make("fieldset", {className: "assurance-form__wide"}, make("legend", {text: spec.label}), box);
      let wanted = new Set();
      const render = () => {
        const chosen = new Set(Array.from(box.querySelectorAll("input:checked")).map(input => input.value));
        wanted.forEach(id => chosen.add(id));
        box.replaceChildren();
        const rows = pool ? pool.rows : [];
        if (!rows.length) {
          box.appendChild(make("p", {className: "assurance-muted", text: pool && pool.loaded
            ? "No approved, current evidence is recorded for this AI system yet. Add and approve evidence on the AI systems page first."
            : "Choose an AI system to see its approved evidence."}));
          return;
        }
        rows.forEach(row => {
          const input = make("input", {type: "checkbox", value: row.id});
          input.checked = chosen.has(row.id);
          box.appendChild(make("label", {}, input, " ", row.label));
        });
        wanted = new Set();
      };
      if (pool) pool.subscribe(render);
      render();
      return {
        el: fieldset,
        current: () => Array.from(box.querySelectorAll("input:checked")).map(input => input.value),
        load: value => { wanted = new Set(Array.isArray(value) ? value.map(String) : []); render(); },
        collect: async () => {
          const ids = Array.from(box.querySelectorAll("input:checked")).map(input => input.value).sort();
          if (spec.required && !ids.length) fail(`Choose at least one piece of evidence for “${spec.label}”.`);
          return ids;
        }
      };
    },
    pairs(spec) {
      const rows = make("div");
      const add = make("button", {className: "btn btn--ghost", type: "button", text: spec.addLabel || "Add a detail"});
      const fieldset = make("fieldset", {className: "assurance-form__wide"}, make("legend", {text: spec.label}),
        spec.hint ? make("p", {className: "assurance-muted", text: spec.hint}) : null, rows, add);
      const addRow = (name = "", value = "") => {
        const nameInput = make("input", {className: "input", maxlength: 128, autocomplete: "off", value: name});
        const valueInput = make("input", {className: "input", maxlength: 4096, autocomplete: "off", value});
        const remove = make("button", {className: "btn btn--ghost", type: "button", text: "Remove"});
        const row = make("div", {className: "assurance-actions"}, make("label", {}, "Detail", " ", nameInput), make("label", {}, "Value", " ", valueInput), remove);
        remove.addEventListener("click", () => row.remove());
        rows.appendChild(row);
      };
      add.addEventListener("click", () => addRow());
      return {
        el: fieldset,
        current: () => rows.children.length,
        load: value => { rows.replaceChildren(); Object.entries(value || {}).forEach(([key, item]) => addRow(key, String(item))); },
        clear: () => rows.replaceChildren(),
        collect: async () => {
          const out = {};
          Array.from(rows.children).forEach(row => {
            const [nameInput, valueInput] = row.querySelectorAll("input");
            const name = String(nameInput.value || "").trim();
            const raw = String(valueInput.value || "").trim();
            if (!name && !raw) return;
            if (!name) fail("Give every detail a name.");
            if (Object.prototype.hasOwnProperty.call(out, name)) fail(`The detail “${name}” is listed twice.`);
            if (raw === "true" || raw === "false") out[name] = raw === "true";
            else if (raw !== "" && /^-?\d+(\.\d+)?$/.test(raw)) out[name] = Number(raw);
            else out[name] = raw;
          });
          return out;
        }
      };
    },
    constant(spec) {
      return {el: null, current: () => spec.value, load: () => {}, collect: async () => spec.value};
    },
    hidden(spec) {
      let stored;
      return {el: null, current: () => stored, load: value => { stored = value; }, reset: () => { stored = undefined; },
        collect: async () => (stored === undefined ? emptyOf(spec, null) : stored)};
    },
    group(spec, ctx) {
      const children = spec.children.map(child => ({spec: child, node: build(child, ctx)}));
      const body = make("div", {className: "assurance-form"});
      children.forEach(({node}) => { if (node.el) body.appendChild(node.el); });
      const el = spec.label
        ? make("fieldset", {className: "assurance-form__wide"}, make("legend", {text: spec.label}),
          spec.hint ? make("p", {className: "assurance-muted", text: spec.hint}) : null, body)
        : body;
      const sibling = key => children.find(item => item.spec.key === key);
      const active = child => {
        if (!child.spec.when) return true;
        const other = sibling(child.spec.when.key);
        return !!other && child.spec.when.in.includes(other.node.current());
      };
      const refresh = () => children.forEach(child => {
        if (child.node.el) child.node.el.hidden = !active(child);
      });
      el.addEventListener("change", refresh);
      refresh();
      return {
        el, refresh,
        child: key => { const found = sibling(key); return found ? found.node : null; },
        current: () => null,
        load: value => {
          if (!value || typeof value !== "object") return;
          const source = spec.untransform ? spec.untransform(value) : value;
          children.forEach(({spec: childSpec, node}) => {
            if (childSpec.flat) node.load(source);
            else if (childSpec.key && Object.prototype.hasOwnProperty.call(source, childSpec.key)) node.load(source[childSpec.key]);
          });
          refresh();
        },
        collect: async () => {
          const out = {};
          for (const child of children) {
            const {spec: childSpec, node} = child;
            if (!active(child)) {
              if (childSpec.key) out[childSpec.key] = emptyOf(childSpec, null);
              continue;
            }
            const value = await node.collect();
            if (childSpec.flat) Object.assign(out, value);
            else if (childSpec.key) out[childSpec.key] = value;
          }
          return spec.transform ? spec.transform(out) : out;
        }
      };
    },
    list(spec, ctx) {
      const items = [];
      const box = make("div");
      const add = make("button", {className: "btn btn--ghost", type: "button", text: spec.addLabel || "Add another"});
      const el = make("fieldset", {className: "assurance-form__wide"}, make("legend", {text: spec.label}),
        spec.hint ? make("p", {className: "assurance-muted", text: spec.hint}) : null, box, add);
      const renumber = () => items.forEach((item, index) => { item.legend.textContent = `${spec.itemLabel || "Item"} ${index + 1}`; });
      const addItem = value => {
        if (spec.limit && items.length >= spec.limit) return null;
        const node = build({type: "group", children: spec.item}, ctx);
        const legend = make("legend");
        const remove = make("button", {className: "btn btn--ghost", type: "button", text: `Remove this ${String(spec.itemLabel || "item").toLowerCase()}`});
        const wrapper = make("fieldset", {className: "assurance-form__wide"}, legend, node.el, remove);
        const item = {node, wrapper, legend};
        remove.addEventListener("click", () => {
          if (items.length <= (spec.min || 0)) return;
          items.splice(items.indexOf(item), 1); wrapper.remove(); renumber();
        });
        items.push(item); box.appendChild(wrapper); renumber();
        if (value) node.load(value);
        return item;
      };
      add.addEventListener("click", () => addItem());
      for (let index = 0; index < (spec.start === undefined ? (spec.min || 1) : spec.start); index += 1) addItem();
      return {
        el, addItem,
        current: () => items.length,
        load: value => {
          items.splice(0).forEach(item => item.wrapper.remove());
          const rows = Array.isArray(value) ? value : [];
          rows.forEach(row => addItem(row));
          while (items.length < (spec.min || 0)) addItem();
          renumber();
        },
        collect: async () => {
          const out = [];
          for (const [index, item] of items.entries()) {
            const value = await item.node.collect();
            (spec.item || []).forEach(child => { if (child.type === "index") value[child.key] = index + 1; });
            out.push(value);
          }
          if (spec.min && out.length < spec.min) fail(`Add at least ${spec.min} to “${spec.label}”.`);
          return spec.finalize ? spec.finalize(out) : out;
        }
      };
    },
    index() { return {el: null, current: () => null, load: () => {}, collect: async () => null}; }
  };

  function build(spec, ctx = {}) {
    const builder = builders[spec.type];
    if (!builder) throw new Error("unknown field type");
    return builder(spec, ctx);
  }

  /* ---------- field lists for each request the page sends ---------- */

  const RISK_TIERS = [["unclassified", "Not classified"], ["low", "Low"], ["medium", "Medium"], ["high", "High"], ["critical", "Critical"]];
  const JURISDICTIONS = [["eu", "European Union"], ["uk", "United Kingdom"], ["us", "United States"], ["ca", "Canada"], ["au", "Australia"], ["global", "Everywhere"]];
  const DATA_CLASSES = [["public", "Public"], ["internal", "Internal"], ["confidential", "Confidential"], ["personal", "Personal"], ["special_category", "Special-category personal"], ["financial", "Financial"], ["health", "Health"]];
  const DEPLOYMENTS = [["production", "Live use"], ["pilot", "Pilot"], ["internal", "Internal only"], ["development", "In development"]];
  const ASSET_TYPES = [["agent", "Agent"], ["model", "Model"], ["application", "Application"], ["dataset", "Dataset"], ["vendor_tool", "Vendor tool"]];

  const conditionFields = () => [
    {type: "checkset", key: "jurisdictions", label: "Where it is used", options: JURISDICTIONS, other: true, otherLabel: "Other places (separated by commas)"},
    {type: "checkset", key: "data_classes", label: "Kinds of data", options: DATA_CLASSES, other: true, otherLabel: "Other kinds of data (separated by commas)"},
    {type: "checkset", key: "deployment_types", label: "How it is deployed", options: DEPLOYMENTS, other: true, otherLabel: "Other deployment kinds (separated by commas)"},
    {type: "checkset", key: "asset_types", label: "Kind of AI system", options: ASSET_TYPES, other: true, otherLabel: "Other kinds (separated by commas)"},
    {type: "words", key: "tags", label: "Labels (separated by commas)", placeholder: "for example: customer facing"},
    {type: "words", key: "use_case_tags", label: "Uses (separated by commas)", placeholder: "for example: support, hiring"}
  ];

  const policyContext = assets => ({type: "group", children: [
    {type: "choice", key: "asset_id", label: "AI system", required: true, placeholder: "Choose an AI system", options: assets},
    {type: "choice", key: "risk_tier", label: "Risk level", options: RISK_TIERS, value: "unclassified"},
    ...conditionFields()
  ]});

  const policyStatements = () => ({type: "list", label: "Rules", itemLabel: "Rule", min: 1, limit: 128, addLabel: "Add another rule",
    item: [
      {type: "hidden", key: "statement_id"},
      {type: "text", key: "text", label: "What the rule says", rows: 2, max: 4000, required: true, wide: true},
      {type: "choice", key: "effect", label: "What happens when it applies", options: [["allow", "Allow"], ["review", "Needs a person's review"], ["restrict", "Restrict"], ["prohibit", "Not allowed"]], value: "review"},
      {type: "group", key: "applicability", label: "Applies when (leave everything empty to apply to every use)", children: [
        {type: "checkset", key: "risk_tiers", label: "Risk levels", options: RISK_TIERS},
        ...conditionFields()
      ]},
      {type: "words", key: "required_control_ids", label: "Safeguards it requires (short names, separated by commas)", limit: 128}
    ],
    finalize: rows => {
      const used = new Set();
      return rows.map((row, index) => {
        let id = row.statement_id || `${slug(row.text, 40) || "rule"}-${index + 1}`;
        while (used.has(id)) id = `${id}-${index + 1}`;
        used.add(id);
        return {...row, statement_id: id};
      });
    }
  });

  const exceptionScope = assets => ({type: "group", children: [
    {type: "checkset", key: "asset_ids", label: "AI systems it covers", options: assets, emptyText: "No AI systems are recorded yet. Add one in the AI system inventory first."},
    {type: "checkset", key: "statement_ids", label: "Rules it covers", options: [], emptyText: "Choose a policy in the table above to see its rules."},
    {type: "checkset", key: "risk_tiers", label: "Risk levels it covers", options: RISK_TIERS}
  ], transform: value => {
    if (!value.asset_ids.length && !value.statement_ids.length && !value.risk_tiers.length) {
      fail("Choose at least one AI system, rule or risk level the exception covers.");
    }
    return value;
  }});

  const MISSING_FIELDS = [
    ["system_name", "AI system name"], ["system_purpose", "What the system is for"], ["incident_occurred_at", "When it happened"],
    ["detected_at", "When it was detected"], ["affected_member_states", "Countries affected"], ["consequences", "Consequences"],
    ["causal_assessment_summary", "Cause assessment"], ["investigation_summary", "Investigation summary"],
    ["root_cause_conclusion", "Root cause"], ["corrective_actions", "Corrective actions"], ["risk_assessment_results", "Risk assessment results"],
    ["expected_next_report_at", "Next report date"], ["provider_organization_reference", "Provider organisation"],
    ["submitter_contact_reference", "Who is submitting"], ["initial_reporter_contact_reference", "Who first reported it"],
    ["contact_reference", "Contact for questions"]
  ];
  const reportDetails = () => ({type: "group", children: [
    {type: "group", flat: true, label: "About the AI system", children: [
      {type: "text", key: "system_name", label: "AI system name", max: 1000},
      {type: "text", key: "system_model", label: "Model or edition", max: 1000},
      {type: "text", key: "system_purpose", label: "What the system is for", rows: 2, max: 4000, wide: true},
      {type: "text", key: "software_version", label: "Software version", max: 256},
      {type: "text", key: "firmware_version", label: "Firmware version (if any)", max: 256},
      {type: "text", key: "serial_number", label: "Serial number (if any)", max: 256},
      {type: "text", key: "lot_batch_number", label: "Lot or batch number (if any)", max: 256},
      {type: "text", key: "catalogue_reference", label: "Catalogue number (if any)", max: 256},
      {type: "text", key: "eu_database_registration_id", label: "EU database registration number (if registered)", max: 256}
    ]},
    {type: "group", flat: true, label: "What happened", children: [
      {type: "datetime", key: "incident_occurred_at", label: "When it happened (if known)"},
      {type: "datetime", key: "detected_at", label: "When it was detected (if known)"},
      {type: "number", key: "estimated_users_affected", label: "About how many people were affected (if known)", integer: true, min: 0, max: 1000000000000},
      {type: "choice", key: "system_operator_type", label: "Who was operating the system", options: [["unknown", "Not known"], ["professional_user", "A professional user"], ["other", "Someone else"]], value: "unknown"},
      {type: "text", key: "causal_assessment_summary", label: "What caused it, as far as you know", rows: 3, max: 8000, wide: true},
      {type: "text", key: "consequences", label: "Consequences", rows: 3, max: 8000, wide: true}
    ]},
    {type: "group", flat: true, label: "Investigation", children: [
      {type: "choice", key: "investigation_status", label: "Investigation", options: [["unknown", "Not known"], ["not_started", "Not started"], ["ongoing", "In progress"], ["completed", "Finished"]], value: "unknown"},
      {type: "datetime", key: "expected_next_report_at", label: "When the next report is expected (not for a final report)"},
      {type: "text", key: "investigation_summary", label: "Investigation so far", rows: 3, max: 12000, wide: true},
      {type: "text", key: "planned_investigations", label: "Planned next steps", rows: 2, max: 12000, wide: true},
      {type: "text", key: "root_cause_conclusion", label: "Root cause", rows: 2, max: 12000, wide: true},
      {type: "text", key: "corrective_actions", label: "Corrective actions", rows: 2, max: 12000, wide: true},
      {type: "text", key: "preservation_actions", label: "What was kept for the investigation", rows: 2, max: 8000, wide: true}
    ]},
    {type: "group", flat: true, label: "Risk assessment", children: [
      {type: "choice", key: "risk_assessment_reviewed", label: "Was the risk assessment reviewed?", options: [["unknown", "Not known"], ["yes", "Yes"], ["no", "No"]], value: "unknown"},
      {type: "choice", key: "risk_assessment_still_adequate", label: "Is it still adequate?", options: [["unknown", "Not known"], ["yes", "Yes"], ["no", "No"], ["not_applicable", "Does not apply"]], value: "unknown"},
      {type: "text", key: "risk_assessment_results", label: "Risk assessment results", rows: 2, max: 12000, wide: true},
      {type: "choice", key: "final_reportability_conclusion", label: "Does it need to be reported?", options: [["undetermined", "Not decided yet"], ["reportable", "Yes, it must be reported"], ["non_reportable", "No"]], value: "undetermined"}
    ]},
    {type: "group", flat: true, label: "People and related reports", children: [
      {type: "text", key: "provider_organization_reference", label: "Provider organisation", max: 256},
      {type: "text", key: "authorized_representative_reference", label: "Authorised representative (if any)", max: 256},
      {type: "text", key: "submitter_contact_reference", label: "Who is submitting the report (role or team)", max: 256},
      {type: "text", key: "initial_reporter_contact_reference", label: "Who first reported it (role or team)", max: 256},
      {type: "text", key: "contact_reference", label: "Who to contact with questions (role or team)", max: 256},
      {type: "lines", key: "related_report_references", label: "Related reports (one per line)", limit: 32},
      {type: "lines", key: "other_regulatory_report_references", label: "Reports made to other regulators (one per line)", limit: 32}
    ]},
    {type: "checkset", key: "known_missing_fields", label: "Details you do not have yet", options: MISSING_FIELDS},
    {type: "boolean", key: "attestation_accepted", label: "I confirm these details are accurate to the best of my knowledge (needed for a final report)"}
  ]});

  const measurementGroup = (name, defs) => ({type: "group", key: name, label: human(name), children: [
    {type: "constant", key: "schema", value: defs.measurement_schema},
    {type: "choice", key: "state", label: "Status", options: [["missing", "Not measured yet"], ["measured", "Measured"], ["not_applicable", "Does not apply"]], value: "missing"},
    {type: "choice", key: "unit", label: "Shown as", options: (defs.measurement_units || ["percent", "rate", "score"]).map(unit => [unit, human(unit)]), value: "percent"},
    {type: "number", key: "value", label: "Result (0 to 100)", min: 0, max: 100, required: true, when: {key: "state", in: ["measured"]}},
    {type: "date", key: "window_start", label: "Measured from", required: true, when: {key: "state", in: ["measured"]}},
    {type: "date", key: "window_end", label: "Measured until", required: true, when: {key: "state", in: ["measured"]}},
    {type: "number", key: "sample_count", label: "How many cases were measured", integer: true, min: 1, max: 1000000000, required: true, empty: 0, when: {key: "state", in: ["measured"]}},
    {type: "number", key: "confidence", label: "Confidence (0 to 1)", min: 0, max: 1, required: true, when: {key: "state", in: ["measured"]}},
    {type: "evidence", key: "evidence_ids", label: "Evidence for this measurement", required: true, empty: [], when: {key: "state", in: ["measured"]}}
  ]});

  const summaryGroup = (key, label, counts, defs) => ({type: "group", key, label, children: [
    {type: "choice", key: "data_state", label: "Status", options: [["missing", "Not recorded yet"], ["measured", "Recorded"]], value: "missing"},
    {type: "date", key: "as_of", label: "As of", required: true, when: {key: "data_state", in: ["measured"]}},
    ...counts.map(([countKey, countLabel]) => ({type: "number", key: countKey, label: countLabel, integer: true, min: 0, max: 1000000000, required: true, when: {key: "data_state", in: ["measured"]}})),
    ...(key === "incident_summary"
      ? [{type: "choice", key: "highest_open_severity", label: "Most serious open incident", options: (defs.severities || []).map(item => [item, human(item)]), value: "none", when: {key: "data_state", in: ["measured"]}}]
      : []),
    {type: "evidence", key: "evidence_ids", label: "Evidence", required: true, empty: [], when: {key: "data_state", in: ["measured"]}}
  ]});

  const insurability = defs => ({type: "group", children: [
    {type: "group", key: "governance_posture", label: "How AI is governed", children: [
      {type: "list", key: "frameworks", label: "Frameworks you follow", itemLabel: "Framework", min: 1, limit: 32, addLabel: "Add another framework", item: [
        {type: "token", key: "framework_id", label: "Framework name", placeholder: "for example: NIST AI RMF", max: 128},
        {type: "choice", key: "posture", label: "How far it is in place", options: (defs.framework_postures || []).map(item => [item, human(item)]), value: "not_assessed"},
        {type: "evidence", key: "evidence_ids", label: "Supporting evidence (optional)"}
      ]},
      {type: "token", key: "accountable_role", label: "Accountable role", placeholder: "for example: Chief risk officer", max: 128},
      {type: "number", key: "review_cadence_days", label: "Reviewed every (days)", integer: true, min: 1, max: 3660, value: 90, required: true}
    ]},
    {type: "group", key: "measurements", label: "Measurements", hint: "Mark each one measured, not measured yet, or does not apply.",
      children: (defs.measurements || []).map(name => measurementGroup(name, defs))},
    summaryGroup("incident_summary", "Incidents", [["open_count", "Open incidents"], ["closed_count", "Closed incidents"]], defs),
    summaryGroup("open_findings_summary", "Open findings", [["total_open", "Open findings"], ["critical_open", "Critical open findings"], ["overdue_open", "Overdue open findings"]], defs),
    {type: "list", key: "safeguards", label: "Safeguards", itemLabel: "Safeguard", min: 1, limit: 64, addLabel: "Add another safeguard", item: [
      {type: "token", key: "control_id", label: "Safeguard name", placeholder: "for example: human review", max: 128},
      {type: "choice", key: "status", label: "Status", options: (defs.safeguard_states || []).map(item => [item, human(item)]), value: "planned"},
      {type: "evidence", key: "evidence_ids", label: "Supporting evidence (optional)"}
    ]},
    {type: "lines", key: "exclusions", label: "What this profile does not cover (one per line)", min: 1, limit: 32},
    {type: "lines", key: "limitations", label: "Known limitations (one per line)", min: 1, limit: 32},
    {type: "group", key: "verifier_instructions", label: "How an insurer can check this", children: [
      {type: "constant", key: "schema_version", value: "v1"},
      {type: "lines", key: "steps", label: "Steps to follow (one per line)", min: 1, limit: 16}
    ]}
  ]});

  const cohortItems = () => [
    {type: "token", key: "cohort_code", label: "Group name", placeholder: "for example: applicants under 25", max: 128},
    {type: "file", key: "definition_sha256", label: "File that defines this group"},
    {type: "number", key: "sample_count", label: "People in the group", integer: true, min: 0, max: 1000000000, required: true},
    {type: "number", key: "favorable_count", label: "Favourable outcomes", integer: true, min: 0, max: 1000000000, required: true},
    {type: "number", key: "missing_count", label: "Missing outcomes", integer: true, min: 0, max: 1000000000, required: true, value: 0},
    {type: "evidence", key: "evidence_ids", label: "Evidence for this group", required: true}
  ];
  const checklistItem = (name, naic) => {
    const done = naic ? "implemented" : "complete";
    const states = naic
      ? [["missing", "Missing"], ["partial", "Partly in place"], ["implemented", "In place"], ["not_applicable", "Does not apply"]]
      : [["missing", "Missing"], ["complete", "Done"], ["not_applicable", "Does not apply"]];
    return {type: "group", key: name, label: human(name), children: [
      {type: "choice", key: "state", label: "Status", options: states, value: "missing"},
      {type: "evidence", key: "evidence_ids", label: "Evidence", required: true, empty: [], when: {key: "state", in: [done]}},
      {type: "note", key: "rationale_sha256", label: "Why it does not apply (kept private)", required: true, empty: null, when: {key: "state", in: ["not_applicable"]}}
    ]};
  };
  const regulated = (packageType, defs) => {
    if (packageType === "credit_adverse_action") return {type: "group", children: [
      {type: "file", key: "model_receipt_sha256", label: "Model record file"},
      {type: "file", key: "input_receipt_sha256", label: "Input record file"},
      {type: "file", key: "explanation_receipt_sha256", label: "Explanation record file"},
      {type: "list", key: "reason_codes", label: "Reasons, most important first", itemLabel: "Reason", min: 1, limit: 16, addLabel: "Add another reason", item: [
        {type: "index", key: "rank"},
        {type: "token", key: "code", label: "Reason", placeholder: "for example: short credit history", max: 128},
        {type: "token", key: "source_factor_code", label: "Model factor it comes from", placeholder: "for example: account age", max: 128},
        {type: "evidence", key: "evidence_ids", label: "Evidence for this reason (optional)"}
      ]}
    ]};
    if (packageType === "fair_lending_aggregate") return {type: "group", children: [
      {type: "token", key: "analysis_scope_code", label: "What was analysed", placeholder: "for example: personal loans 2026", max: 128},
      {type: "date", key: "window_start", label: "Analysis from", required: true},
      {type: "date", key: "window_end", label: "Analysis until", required: true},
      {type: "group", key: "reference_cohort", label: "Comparison baseline group", children: cohortItems()},
      {type: "list", key: "comparison_cohorts", label: "Groups compared with the baseline", itemLabel: "Group", min: 1, limit: 64, addLabel: "Add another group", item: cohortItems()},
      {type: "file", key: "methodology_sha256", label: "Method description file"},
      {type: "words", key: "limitations_codes", label: "Known limitations (short phrases, separated by commas)", limit: 128}
    ]};
    if (packageType === "nyc_ll144") return {type: "group", children: [
      {type: "date", key: "assessment_window_start", label: "Assessment from", required: true},
      {type: "date", key: "assessment_window_end", label: "Assessment until", required: true},
      {type: "group", key: "independent_auditor", label: "Independent auditor", children: [
        {type: "choice", key: "state", label: "Status", options: [["missing", "No audit statement yet"], ["asserted", "Audit statement received"]], value: "missing"},
        {type: "file", key: "assertion_sha256", label: "Auditor's statement file", when: {key: "state", in: ["asserted"]}},
        {type: "date", key: "asserted_at", label: "Statement date", required: true, when: {key: "state", in: ["asserted"]}},
        {type: "date", key: "coverage_start", label: "Audit covers from", required: true, when: {key: "state", in: ["asserted"]}},
        {type: "date", key: "coverage_end", label: "Audit covers until", required: true, when: {key: "state", in: ["asserted"]}},
        {type: "evidence", key: "evidence_ids", label: "Evidence", required: true, empty: [], when: {key: "state", in: ["asserted"]}}
      ]},
      {type: "group", key: "checklist", label: "Checklist", children: ((defs.regulated || {}).nyc_checks || []).map(name => checklistItem(name, false))}
    ]};
    return {type: "group", children: [
      {type: "token", key: "bulletin_version_code", label: "Bulletin edition", placeholder: "for example: 2023 model bulletin", max: 128},
      {type: "words", key: "jurisdiction_scope_codes", label: "States or regions covered (separated by commas)", required: true, limit: 32, sorted: true},
      {type: "file", key: "applicability_assertion_sha256", label: "Statement of where the bulletin applies (file)"},
      {type: "group", key: "checklist", label: "Checklist", children: ((defs.regulated || {}).naic_checks || []).map(name => checklistItem(name, true))}
    ]};
  };

  const bankValue = field => {
    const base = {key: "value", label: "Answer", required: true, when: {key: "state", in: ["verified"]}};
    if (field.kind === "choice") return {...base, type: "choice", options: (field.choices || []).map(item => [item, human(item)])};
    if (field.kind === "integer") return {...base, type: "number", integer: true, min: 0, max: 1000000000};
    if (field.kind === "timestamp") return {...base, type: "date"};
    if (field.kind === "token") return {...base, type: "token", max: 128};
    return {...base, type: "text", rows: 2, max: 512, wide: true};
  };
  const deriveSectionState = assertions => {
    const states = new Set(assertions.map(item => item.state));
    if (states.size === 1 && states.has("verified")) return "verified";
    if (states.has("missing")) return "missing";
    return "unverified";
  };
  const bankMrm = defs => {
    const bank = defs.bank_mrm || {sections: []};
    return {type: "group", children: bank.sections.map(section => ({
      type: "group", key: section.key, label: human(section.key),
      children: [
        ...section.fields.map(field => ({type: "group", key: field.key, label: human(field.key), children: [
          {type: "choice", key: "state", label: "Status", options: [["missing", "Missing"], ["unverified", "Stated, not checked"], ["verified", "Checked"]], value: "missing"},
          bankValue(field)
        ]})),
        {type: "evidence", key: "evidence_ids", label: `Evidence for ${human(section.key).toLowerCase()}`}
      ],
      untransform: value => {
        const out = {evidence_ids: value.evidence_ids || []};
        (value.assertions || []).forEach(item => { out[item.field] = {state: item.state, value: item.value}; });
        return out;
      },
      transform: value => {
        const assertions = section.fields.map(field => ({field: field.key, state: value[field.key].state, value: value[field.key].value}));
        const anyChecked = assertions.some(item => item.state === "verified");
        if (anyChecked && !value.evidence_ids.length) fail(`Choose evidence for “${human(section.key)}” because some answers are marked checked.`);
        if (!anyChecked && value.evidence_ids.length) fail(`Evidence can only be added to “${human(section.key)}” when at least one answer is marked checked.`);
        return {schema: bank.section_schema, state: deriveSectionState(assertions), assertions, evidence_ids: value.evidence_ids};
      }
    }))};
  };

  const DOMAIN_CATEGORIES = ["productivity", "software-development", "customer-support", "marketing", "sales", "analytics", "design", "research", "other"];
  const discoveryObservation = () => ({type: "group", children: [
    {type: "datetime", key: "observed_at", label: "When it was seen", required: true},
    {type: "token", key: "ai_service_code", label: "AI service", placeholder: "for example: chat assistant", max: 64},
    {type: "token", key: "ai_product_code", label: "Product", placeholder: "for example: team chat", max: 64},
    {type: "token", key: "provider_code", label: "Provider", placeholder: "for example: the vendor's name", max: 64},
    {type: "choice", key: "domain_category", label: "Used for", options: DOMAIN_CATEGORIES.map(item => [item, human(item)]), value: "productivity"},
    {type: "choice", key: "deployment_type", label: "How it is provided", options: [["saas", "Online service"], ["hosted_api", "Hosted connection"], ["managed_cloud", "Managed cloud"], ["self_hosted", "Run by us"], ["embedded", "Built into another product"], ["unknown", "Not known"]], value: "saas"},
    {type: "choice", key: "environment_code", label: "Where", options: [["production", "Live use"], ["staging", "Testing before release"], ["development", "Development"], ["test", "Test"], ["unknown", "Not known"]], value: "production"},
    {type: "words", key: "context_codes", label: "Other notes (short words, separated by commas)", limit: 16}
  ]});

  /* ---------- values that come from another system ---------- */

  /* A release name, a filing reference, an employee number or a course
   * edition is copied from the system that issued it, so it is checked with
   * the same limits the server applies and never rewritten. */
  const REFERENCE_RULES = Object.freeze({
    release: {max: 256, pattern: /^[A-Za-z0-9][A-Za-z0-9_.:@\/+=-]*$/, what: "the release name",
      message: "Type the release name as your release system shows it, without spaces: letters, numbers, dots, dashes or underscores."},
    filing: {max: 128, pattern: /^[A-Za-z0-9][A-Za-z0-9_.:@\/-]*$/, what: "the filing reference",
      message: "Type the filing reference exactly as the authority gave it, without spaces."},
    edition: {max: 128, pattern: /^[A-Za-z0-9][A-Za-z0-9_.:\/-]*$/, what: "the course edition",
      message: "Type the course edition as your learning system shows it, without spaces (for example: 2026)."},
    employee: {max: 128, pattern: /^[^\u0000-\u001f\u007f]+$/, what: "the employee number",
      message: "Type the employee number as your HR system shows it."},
    provision: {max: 128, pattern: /^[A-Za-z0-9][A-Za-z0-9 .()\/-]*$/, what: "the provision",
      message: "Type the provision using letters, numbers, spaces, dots, brackets or dashes, for example: Article 6 and Annex III."},
    label: {max: 128, lower: true, pattern: /^[a-z][a-z0-9_.:-]*$/, what: "each data label",
      message: "Type each data label as Microsoft Purview shows it: starting with a letter, without spaces."}
  });
  const checkReference = (value, kind) => {
    const rule = REFERENCE_RULES[kind];
    if (!rule) throw new Error("unknown reference kind");
    let text = String(value === null || value === undefined ? "" : value).trim();
    if (rule.lower) text = text.toLowerCase();
    if (!text) fail(`Fill in ${rule.what}.`);
    if (text.length > rule.max) fail(`Use at most ${rule.max} characters for ${rule.what}.`);
    if (!rule.pattern.test(text)) fail(rule.message);
    return text;
  };

  const shorten = (text, max) => (text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text);
  const OTHER = "__other__";
  /* A searchable list of the legal provisions Lightwork knows, with a
   * secondary "Other (type it)" choice for anything not in it. */
  const provisionPicker = (root, options = {}) => {
    const required = options.required === true;
    const search = root.querySelector("[data-provision-search]");
    const select = root.querySelector("[data-provision-choice]");
    const otherBox = root.querySelector("[data-provision-other]");
    const typed = otherBox ? otherBox.querySelector("input") : null;
    let rows = [];
    let loaded = false;
    let defaultUrl = String(options.defaultUrl || "");
    const toggle = () => { if (otherBox) otherBox.hidden = select.value !== OTHER; };
    const render = () => {
      const previous = select.value;
      const terms = String(search ? search.value : "").toLowerCase().split(/\s+/).filter(Boolean);
      const matches = rows.map((row, index) => [row, index]).filter(([row]) => {
        const text = `${row.regulation} ${row.provision} ${row.title || ""}`.toLowerCase().replace(/\bart\.\s*/g, "article ");
        return terms.every(term => text.includes(term.replace(/^art\.?$/, "article")));
      });
      const first = !loaded ? "Loading provisions…" : terms.length && !matches.length
        ? "Nothing in the list matches — try other words"
        : required ? "Choose a provision" : "No provision";
      select.replaceChildren(new Option(first, ""));
      const groups = new Map();
      matches.forEach(([row, index]) => {
        if (!groups.has(row.regulation)) {
          const group = document.createElement("optgroup");
          group.label = row.regulation;
          groups.set(row.regulation, group);
          select.appendChild(group);
        }
        const about = String(row.title || "").split("; ")[0];
        groups.get(row.regulation).appendChild(new Option(about ? `${row.provision} — ${shorten(about, 110)}` : row.provision, String(index)));
      });
      select.appendChild(new Option("Other (type it)", OTHER));
      if (Array.from(select.options).some(option => option.value === previous)) select.value = previous;
      toggle();
    };
    if (search) search.addEventListener("input", render);
    select.addEventListener("change", () => { toggle(); if (select.value === OTHER && typed) typed.focus(); });
    render();
    return {
      set(list, url) {
        rows = (Array.isArray(list) ? list : []).filter(row => row && typeof row.provision === "string" && typeof row.official_url === "string");
        if (url) defaultUrl = String(url);
        loaded = true;
        render();
      },
      choose(provision) {
        const index = rows.findIndex(row => row.provision === provision);
        if (index >= 0) { if (search) search.value = ""; render(); select.value = String(index); toggle(); }
      },
      value() {
        const choice = select.value;
        if (choice === OTHER) return {provision: checkReference(typed ? typed.value : "", "provision"), official_url: defaultUrl};
        if (!choice) {
          if (required) fail("Choose the legal provision, or choose “Other (type it)” and type it.");
          return null;
        }
        const row = rows[Number(choice)];
        if (!row) fail("Choose the legal provision again.");
        return {provision: row.provision, official_url: row.official_url};
      }
    };
  };

  /* Release names used before in this workspace, shared by every release
   * picker on the page; a new name typed once joins the list. */
  class ReleaseList {
    constructor() { this.rows = []; this.added = []; this.loaded = false; this.listeners = new Set(); }
    set(rows) {
      this.loaded = true;
      this.rows = (Array.isArray(rows) ? rows : []).filter(row => row && typeof row.context_id === "string").map(row => ({
        name: row.context_id,
        when: Number(row.last_used_at) || 0,
        deployments: Array.isArray(row.deployment_ids) ? row.deployment_ids.map(String) : []
      }));
      this.listeners.forEach(listener => listener());
    }
    add(value) {
      const name = checkReference(value, "release");
      if (!this.added.includes(name)) this.added.unshift(name);
      this.listeners.forEach(listener => listener());
      return name;
    }
    choices(deployment) {
      const used = this.rows.filter(row => !deployment || row.deployments.includes(deployment));
      return [
        ...this.added.filter(name => !used.some(row => row.name === name)).map(name => ({name, when: 0, added: true})),
        ...used
      ];
    }
    subscribe(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  }
  const NEW_RELEASE = "__new__";
  const releasePicker = (root, list) => {
    const select = root.querySelector("[data-release-choice]");
    const newBox = root.querySelector("[data-release-new]");
    const typed = newBox ? newBox.querySelector("input") : null;
    let deployment = "";
    const toggle = () => { if (newBox) newBox.hidden = select.value !== NEW_RELEASE; };
    const render = () => {
      const previous = select.value;
      const rows = list.choices(deployment);
      const first = !list.loaded ? "Loading releases…"
        : rows.length ? "Choose a release"
        : deployment ? "No release used with this deployment yet" : "No release used yet";
      select.replaceChildren(new Option(first, ""));
      rows.forEach(row => {
        const when = row.added ? "added just now" : row.when > 0 ? `last used ${(window.mvDateAbsolute ? window.mvDateAbsolute(row.when) : new Date(row.when * 1000).toLocaleDateString())}` : "";
        select.appendChild(new Option(when ? `${row.name} (${when})` : row.name, row.name));
      });
      select.appendChild(new Option("Add a new release…", NEW_RELEASE));
      if (Array.from(select.options).some(option => option.value === previous)) select.value = previous;
      toggle();
    };
    const remember = () => {
      if (!typed || select.value !== NEW_RELEASE || !String(typed.value || "").trim()) return null;
      const name = list.add(typed.value);
      select.value = name;
      typed.value = "";
      toggle();
      return name;
    };
    select.addEventListener("change", () => { toggle(); if (select.value === NEW_RELEASE && typed) typed.focus(); });
    if (typed) typed.addEventListener("change", () => { try { remember(); } catch (_error) { /* shown when the form is sent */ } });
    list.subscribe(render);
    render();
    return {
      setDeployment(value) { deployment = String(value || ""); render(); },
      value() {
        if (select.value === NEW_RELEASE) {
          if (!typed || !String(typed.value || "").trim()) fail("Type the name of the new release, or choose one from the list.");
          return remember();
        }
        if (!select.value) fail("Choose a release, or choose “Add a new release…”.");
        return select.value;
      }
    };
  };

  window.LWAssuranceForms = Object.freeze({
    build, slug, toName, canonical, sha256Hex, fileFingerprint, textFingerprint, readRecordFile,
    EvidencePool, citedEvidence, checkReference, provisionPicker, ReleaseList, releasePicker,
    specs: Object.freeze({policyContext, policyStatements, exceptionScope, reportDetails, insurability, regulated, bankMrm, discoveryObservation})
  });
})();
