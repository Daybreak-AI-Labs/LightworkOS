(function (root) {
  "use strict";

  var bases = {
    consent: "Consent", contract: "Needed for a contract", legal_obligation: "Required by law",
    vital_interests: "Protects someone\u2019s life", public_task: "Public task",
    legitimate_interests: "Legitimate business interest",
  };

  // A typed name ("Email marketing") is stored as a short reference
  // ("email_marketing"); existing references pass through unchanged.
  function normalize(value) {
    var text = typeof value === "string" ? value.trim() : "";
    if (/\s/.test(text)) text = text.toLowerCase().replace(/\s+/g, "_");
    return text;
  }

  function purposeMap(rows) {
    if (!Array.isArray(rows) || !rows.length || rows.length > 128) {
      throw new Error("Add between 1 and 128 purposes.");
    }
    var result = Object.create(null);
    rows.forEach(function (row) {
      var id = normalize(row.id);
      if (!/^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$/.test(id)) {
        throw new Error("Give each use a short name made of letters and numbers (up to 128 characters).");
      }
      if (Object.prototype.hasOwnProperty.call(result, id)) {
        throw new Error("Each use must be unique. “" + id + "” appears more than once.");
      }
      if (!Object.prototype.hasOwnProperty.call(bases, row.basis)) {
        throw new Error("Choose a legal reason for “" + id + "”.");
      }
      result[id] = row.basis;
    });
    return result;
  }

  function parsePurposes(text) {
    var value;
    try { value = JSON.parse(text); }
    catch (_error) { throw new Error("The saved list of uses could not be read (not valid JSON). Use the fields above instead."); }
    if (!value || Array.isArray(value) || typeof value !== "object") {
      throw new Error("Each use needs a legal reason.");
    }
    return purposeMap(Object.keys(value).map(function (id) { return { id: id, basis: value[id] }; }));
  }

  function mount(form, doc, options) {
    options = options || {};
    var rows = doc.getElementById("cp-purpose-rows");
    var add = doc.getElementById("cp-purpose-add");
    var error = doc.getElementById("cp-purpose-error");
    var details = doc.getElementById("cp-purpose-advanced");
    var raw = form.elements.purposes;
    var inputs = [];
    var lastEdit = "fields";

    function fieldMap() {
      return purposeMap(inputs.map(function (row) { return { id: row.id.value, basis: row.basis.value }; }));
    }
    function syncFields() {
      lastEdit = "fields";
      try { raw.value = JSON.stringify(fieldMap(), null, 2); error.textContent = ""; }
      catch (failure) { error.textContent = failure.message; }
    }
    function append(id, basis) {
      var row = doc.createElement("div"); row.className = "cp-purpose-row";
      var idLabel = doc.createElement("label"); idLabel.textContent = "Use of data";
      var idInput = doc.createElement("input"); idInput.className = "input";
      idInput.value = id; idInput.maxLength = 128; idInput.required = true;
      idInput.placeholder = "For example: analytics";
      if (options.suggestions && typeof idInput.setAttribute === "function") idInput.setAttribute("list", options.suggestions);
      idLabel.appendChild(idInput);
      var basisLabel = doc.createElement("label"); basisLabel.textContent = "Legal reason";
      var basisInput = doc.createElement("select"); basisInput.className = "input";
      Object.keys(bases).forEach(function (key) {
        var option = doc.createElement("option"); option.value = key; option.textContent = bases[key];
        basisInput.appendChild(option);
      });
      basisInput.value = basis; basisLabel.appendChild(basisInput);
      var remove = doc.createElement("button"); remove.type = "button"; remove.className = "btn";
      remove.textContent = "Remove";
      var entry = { id: idInput, basis: basisInput, row: row };
      inputs.push(entry);
      [idInput, basisInput].forEach(function (input) { input.addEventListener("input", syncFields); });
      remove.addEventListener("click", function () {
        var index = inputs.indexOf(entry);
        inputs.splice(index, 1); row.remove(); add.disabled = false; syncFields();
        if (inputs.length) inputs[Math.min(index, inputs.length - 1)].id.focus();
        else add.focus();
      });
      row.appendChild(idLabel); row.appendChild(basisLabel); row.appendChild(remove); rows.appendChild(row);
      add.disabled = inputs.length >= 128;
      return idInput;
    }
    function render(value) {
      rows.replaceChildren(); inputs = [];
      Object.keys(value).forEach(function (id) { append(id, value[id]); });
      lastEdit = "fields"; error.textContent = "";
    }
    function applyJson() {
      try { render(parsePurposes(raw.value)); return true; }
      catch (failure) { error.textContent = failure.message; return false; }
    }
    add.addEventListener("click", function () {
      if (inputs.length >= 128) return;
      append("", "consent").focus(); syncFields();
    });
    raw.addEventListener("input", function () { lastEdit = "json"; });
    var applyButton = doc.getElementById("cp-purpose-apply");
    if (applyButton) applyButton.addEventListener("click", function () {
      if (applyJson() && inputs.length) inputs[0].id.focus();
    });
    render(parsePurposes(raw.value));
    return {
      read: function () {
        try {
          var value = lastEdit === "json" ? parsePurposes(raw.value) : fieldMap();
          if (lastEdit === "json") render(value);
          raw.value = JSON.stringify(value, null, 2); error.textContent = "";
          return value;
        } catch (failure) {
          error.textContent = failure.message;
          if (lastEdit === "json" && details) { details.open = true; raw.focus(); }
          throw failure;
        }
      },
      set: function (value) {
        render(purposeMap(Object.keys(value || {}).map(function (id) { return { id: id, basis: value[id] }; })));
        raw.value = JSON.stringify(fieldMap(), null, 2);
      },
    };
  }
  var api = Object.freeze({ purposeMap: purposeMap, parsePurposes: parsePurposes, mount: mount });
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LightworkConsentPolicyEditor = api;
})(typeof window === "object" ? window : globalThis);
