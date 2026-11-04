/* Lightwork consent SDK: structured DOM only; no telemetry or remote code. */
(function (global) {
  "use strict";

  var MAX_RESPONSE_BYTES = 256 * 1024;
  var MAX_RIGHTS_PACKAGE_BYTES = 16 * 1024 * 1024;
  var CONFIGURATION_SIGNATURE_SCHEMA = "lightwork.consent-configuration-signature.v1";
  var UNSIGNED_REFUSAL = "consent configuration is not signed by a trusted key";
  var SESSION_HEADER = "X-Lightwork-Consent-Session";
  var SESSION_REFUSALS = ["consent session required", "consent session expired or invalid"];

  function requireText(value, label) {
    if (typeof value !== "string" || !value || value.length > 2048) {
      throw new Error(label + " is required");
    }
    return value;
  }

  function base64url(bytes) {
    var binary = "";
    bytes.forEach(function (value) { binary += String.fromCharCode(value); });
    return global.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function capability(prefix) {
    var bytes = new Uint8Array(32);
    global.crypto.getRandomValues(bytes);
    return prefix + base64url(bytes);
  }

  async function sha256(value) {
    var encoded = new TextEncoder().encode(value);
    var digest = await global.crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(digest)).map(function (item) {
      return item.toString(16).padStart(2, "0");
    }).join("");
  }

  async function pkceChallenge(value) {
    var encoded = new TextEncoder().encode(value);
    var digest = await global.crypto.subtle.digest("SHA-256", encoded);
    return base64url(new Uint8Array(digest));
  }

  function pythonJSONString(value) {
    var escaped = '"';
    for (var index = 0; index < value.length; index += 1) {
      var code = value.charCodeAt(index);
      if (code === 0x22) escaped += '\\"';
      else if (code === 0x5c) escaped += '\\\\';
      else if (code === 0x08) escaped += '\\b';
      else if (code === 0x09) escaped += '\\t';
      else if (code === 0x0a) escaped += '\\n';
      else if (code === 0x0c) escaped += '\\f';
      else if (code === 0x0d) escaped += '\\r';
      else if (code >= 0x20 && code <= 0x7e) escaped += value[index];
      else escaped += "\\u" + code.toString(16).padStart(4, "0");
    }
    return escaped + '"';
  }

  function pythonFloat(value) {
    if (!Number.isFinite(value) || value <= 0 || value >= 100000000000) {
      throw new Error("canonical timestamp is outside its bound");
    }
    if (Number.isInteger(value)) return String(value) + ".0";
    var rendered = String(value).toLowerCase();
    if (value < 0.0001 && !rendered.includes("e")) {
      var fractional = rendered.split(".")[1] || "";
      var first = fractional.search(/[1-9]/);
      if (first < 0) throw new Error("canonical timestamp is invalid");
      var digits = fractional.slice(first).replace(/0+$/, "");
      rendered = digits[0] + (digits.length > 1 ? "." + digits.slice(1) : "") +
        "e-" + String(first + 1).padStart(2, "0");
    }
    if (rendered.includes("e")) {
      var parts = rendered.split("e");
      var exponent = Number(parts[1]);
      rendered = parts[0] + "e" + (exponent >= 0 ? "+" : "-") +
        String(Math.abs(exponent)).padStart(2, "0");
    }
    return rendered;
  }

  function canonicalJSON(value, key, depth, seen) {
    depth = depth || 0;
    seen = seen || new WeakSet();
    if (depth > 64) throw new Error("canonical JSON exceeds its depth bound");
    if (value === null) return "null";
    if (value === true) return "true";
    if (value === false) return "false";
    if (typeof value === "string") return pythonJSONString(value);
    if (typeof value === "number") {
      if (/(?:_at|_until)$/.test(key || "")) return pythonFloat(value);
      if (!Number.isSafeInteger(value)) throw new Error("canonical integer is invalid");
      return String(value);
    }
    if (!value || typeof value !== "object") throw new Error("canonical JSON type is invalid");
    if (seen.has(value)) throw new Error("canonical JSON cannot contain cycles");
    seen.add(value);
    var encoded;
    if (Array.isArray(value)) {
      encoded = "[" + value.map(function (item) {
        return canonicalJSON(item, "", depth + 1, seen);
      }).join(",") + "]";
    } else {
      var keys = Object.keys(value).sort();
      if (keys.some(function (item) { return !/^[\x20-\x7e]+$/.test(item); })) {
        throw new Error("canonical JSON key is invalid");
      }
      encoded = "{" + keys.map(function (item) {
        return pythonJSONString(item) + ":" + canonicalJSON(value[item], item, depth + 1, seen);
      }).join(",") + "}";
    }
    seen.delete(value);
    return encoded;
  }

  async function canonicalSha256(value) {
    return sha256(canonicalJSON(value));
  }

  function unhex(value) {
    var bytes = new Uint8Array(value.length / 2);
    for (var index = 0; index < bytes.length; index += 1) {
      bytes[index] = parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  // Keys a site trusts for signed configurations: the files downloaded from
  // Lightwork ({key_id, public_key}), one or several (during a key change).
  function trustedPublicationKeys(value) {
    if (value === undefined || value === null) return null;
    var list = Array.isArray(value) ? value : [value];
    var keys = {};
    list.forEach(function (item) {
      if (!item || typeof item !== "object" || typeof item.key_id !== "string" ||
          !/^lwcp-[0-9a-f]{24}$/.test(item.key_id) || typeof item.public_key !== "string" ||
          !/^[0-9a-f]{64}$/.test(item.public_key)) {
        throw new Error("publicationKeys must be Lightwork consent signing key files");
      }
      keys[item.key_id] = item.public_key;
    });
    if (!Object.keys(keys).length) throw new Error("publicationKeys must name at least one key");
    return keys;
  }

  // Refuse a configuration unless its Ed25519 signature is from a trusted key
  // and covers exactly the content, publication and policy about to be used.
  async function verifySignedConfiguration(value, keys) {
    var signature = value && value.signature;
    var statement = signature && signature.statement;
    var fields = ["algorithm", "configuration_sha256", "key_id", "policy_id", "policy_sha256",
      "policy_version", "property_id", "publication_key_id", "publication_sha256", "schema"];
    if (!signature || typeof signature !== "object" ||
        signature.schema !== CONFIGURATION_SIGNATURE_SCHEMA || signature.algorithm !== "Ed25519" ||
        typeof signature.signature !== "string" || !/^[0-9a-f]{128}$/.test(signature.signature) ||
        !hasExactKeys(statement, fields) || statement.schema !== CONFIGURATION_SIGNATURE_SCHEMA ||
        statement.algorithm !== "Ed25519" || statement.key_id !== signature.key_id ||
        !Object.prototype.hasOwnProperty.call(keys, statement.key_id) ||
        !value.property || !value.publication || !value.rule ||
        statement.property_id !== value.property.property_id ||
        statement.publication_sha256 !== value.publication.publication_sha256 ||
        statement.configuration_sha256 !== value.configuration_sha256 ||
        statement.policy_id !== value.policy_id || statement.policy_version !== value.policy_version ||
        statement.policy_sha256 !== value.policy_sha256) {
      throw new Error(UNSIGNED_REFUSAL);
    }
    var digest = await canonicalSha256({
      publication_sha256: value.publication.publication_sha256,
      property_id: value.property.property_id,
      property_revision: value.property.revision,
      consent_group_id: value.property.consent_group_id,
      rule_id: value.rule.rule_id,
      rule_sha256: value.rule.rule_sha256,
      locale: value.rule.locale,
      configuration: value.configuration
    });
    if (digest !== value.configuration_sha256) throw new Error(UNSIGNED_REFUSAL);
    var verified = false;
    try {
      var subtle = global.crypto.subtle;
      var key = await subtle.importKey("raw", unhex(keys[statement.key_id]), { name: "Ed25519" },
        false, ["verify"]);
      verified = await subtle.verify({ name: "Ed25519" }, key, unhex(signature.signature),
        new TextEncoder().encode(canonicalJSON(statement)));
    } catch (_error) {
      verified = false;  // a browser without Ed25519 cannot prove the signature
    }
    if (verified !== true) throw new Error(UNSIGNED_REFUSAL);
  }

  function withoutKey(value, omitted) {
    var result = {};
    Object.keys(value).forEach(function (key) {
      if (key !== omitted) result[key] = value[key];
    });
    return result;
  }

  function element(tag, text, className) {
    var node = global.document.createElement(tag);
    if (typeof text === "string") node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function hasExactKeys(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    var actual = Object.keys(value).sort();
    var expected = keys.slice().sort();
    return actual.length === expected.length && actual.every(function (key, index) {
      return key === expected[index];
    });
  }

  function plainText(value) {
    return typeof value === "string" && value.length > 0 && value.length <= 2048 &&
      !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
  }

  function brandText(value) {
    if (typeof value !== "string" || !value || value !== value.trim() ||
        /[<>\u0000-\u001f\u007f-\u009f]/.test(value) ||
        /(?:javascript|vbscript)\s*:|data\s*:\s*text\/html/i.test(value)) return false;
    for (var index = 0; index < value.length; index += 1) {
      var code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        if (index + 1 >= value.length) return false;
        var next = value.charCodeAt(index + 1);
        if (next < 0xdc00 || next > 0xdfff) return false;
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) return false;
    }
    return new TextEncoder().encode(value).length <= 512;
  }

  function validRef(value) {
    return typeof value === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
  }

  function colorContrast(foreground, background) {
    function luminance(color) {
      var channels = [0, 2, 4].map(function (index) {
        var channel = parseInt(color.slice(index, index + 2), 16) / 255;
        return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    }
    var left = luminance(foreground);
    var right = luminance(background);
    return (Math.max(left, right) + 0.05) / (Math.min(left, right) + 0.05);
  }

  async function certifiedBranding(value) {
    var keys = [
      "branding_sha256", "description", "display_name", "heading", "primary_color",
      "primary_text_color", "resource_sha256", "surface_color", "text_color",
      "theme_token_id", "version"
    ];
    if (!hasExactKeys(value, keys) || !validRef(value.theme_token_id) ||
        !Number.isInteger(value.version) || value.version < 1 ||
        ![value.display_name, value.heading, value.description].every(brandText) ||
        ![value.resource_sha256, value.branding_sha256].every(function (item) {
          return typeof item === "string" && /^[0-9a-f]{64}$/.test(item);
        }) ||
        ![value.primary_color, value.primary_text_color, value.surface_color,
          value.text_color].every(function (item) {
            return typeof item === "string" && /^[0-9a-f]{6}$/.test(item);
          }) ||
        colorContrast(value.primary_text_color, value.primary_color) < 4.5 ||
        colorContrast(value.text_color, value.surface_color) < 4.5) return null;
    try {
      if (await canonicalSha256(withoutKey(value, "branding_sha256")) !==
          value.branding_sha256) return null;
    } catch (_error) {
      return null;
    }
    return value;
  }

  function applyBranding(panel, branding) {
    if (!branding) return;
    panel.setAttribute("data-lightwork-theme", branding.theme_token_id);
    if (panel.style && typeof panel.style.setProperty === "function") {
      panel.style.setProperty("--lightwork-primary", "#" + branding.primary_color);
      panel.style.setProperty("--lightwork-primary-text", "#" + branding.primary_text_color);
      panel.style.setProperty("--lightwork-surface", "#" + branding.surface_color);
      panel.style.setProperty("--lightwork-text", "#" + branding.text_color);
      panel.style.setProperty("background-color", "#" + branding.surface_color);
      panel.style.setProperty("color", "#" + branding.text_color);
    }
  }

  function applyBrandingAction(node, branding) {
    if (!branding || !node.style || typeof node.style.setProperty !== "function") return;
    node.style.setProperty("background-color", "#" + branding.primary_color);
    node.style.setProperty("color", "#" + branding.primary_text_color);
  }

  function publishedProfileDefinitions(configuration) {
    if (!configuration || !configuration.configuration ||
        !Array.isArray(configuration.configuration.custom_preferences)) return null;
    var definitions = new Map();
    var valid = configuration.configuration.custom_preferences.every(function (item) {
      if (!item || typeof item !== "object" || !validRef(item.id) ||
          !Number.isInteger(item.version) || item.version < 1 ||
          !["boolean", "single_select", "multi_select"].includes(item.value_type) ||
          typeof item.required !== "boolean" || !plainText(item.title) ||
          !plainText(item.description) || !Array.isArray(item.option_ids) ||
          item.option_ids.length > 64 || definitions.has(item.id)) return false;
      if (!item.option_ids.every(validRef) || new Set(item.option_ids).size !== item.option_ids.length) {
        return false;
      }
      if (item.value_type === "boolean" && item.option_ids.length !== 0) return false;
      if (item.value_type !== "boolean" && item.option_ids.length === 0) return false;
      definitions.set(item.id, item);
      return true;
    });
    return valid ? definitions : null;
  }

  function certifiedProfilePrompt(value, configuration) {
    if (!hasExactKeys(value, ["assignment_id", "assigned_at", "eligible", "prompts", "reason"]) ||
        typeof value.eligible !== "boolean" || typeof value.reason !== "string" ||
        !Number.isFinite(value.assigned_at) || value.assigned_at <= 0 ||
        !Array.isArray(value.prompts) || value.prompts.length > 64) return null;
    if (value.eligible !== true) {
      return value.assignment_id === null && value.prompts.length === 0 ? value : null;
    }
    if (!validRef(value.assignment_id) || value.prompts.length === 0) return null;
    var definitions = publishedProfileDefinitions(configuration);
    if (!definitions) return null;
    var seen = new Set();
    var prompts = [];
    for (var index = 0; index < value.prompts.length; index += 1) {
      var prompt = value.prompts[index];
      if (!hasExactKeys(prompt, [
        "definition_version", "label_ref", "options", "preference_id",
        "required", "stage_id", "value_type"
      ]) || !validRef(prompt.stage_id) || !validRef(prompt.preference_id) ||
          !validRef(prompt.label_ref) || prompt.label_ref !== prompt.preference_id ||
          !Number.isInteger(prompt.definition_version) || prompt.definition_version < 1 ||
          typeof prompt.required !== "boolean" ||
          !["boolean", "single_select", "multi_select"].includes(prompt.value_type) ||
          !Array.isArray(prompt.options) || prompt.options.length > 64 ||
          seen.has(prompt.preference_id)) return null;
      var definition = definitions.get(prompt.preference_id);
      if (!definition || definition.version !== prompt.definition_version ||
          definition.value_type !== prompt.value_type || definition.required !== prompt.required ||
          definition.option_ids.length !== prompt.options.length) return null;
      for (var optionIndex = 0; optionIndex < prompt.options.length; optionIndex += 1) {
        var option = prompt.options[optionIndex];
        if (!hasExactKeys(option, ["label_ref", "value_id"]) ||
            !validRef(option.value_id) || option.label_ref !== option.value_id ||
            option.value_id !== definition.option_ids[optionIndex]) return null;
      }
      seen.add(prompt.preference_id);
      prompts.push(Object.assign({}, prompt, {options: prompt.options.map(function (option) {
        return {label_ref: option.label_ref, value_id: option.value_id};
      })}));
    }
    prompts.sort(function (left, right) {
      return Number(right.required) - Number(left.required);
    });
    return {
      assignment_id: value.assignment_id,
      assigned_at: value.assigned_at,
      eligible: true,
      prompts: prompts,
      reason: value.reason
    };
  }

  function certifiedExperimentRender(assignment, configuration) {
    if (!hasExactKeys(assignment, [
      "content_sha256", "eligible", "experiment_id", "is_control", "is_holdout",
      "reason", "render", "variant_id"
    ]) || !/^[0-9a-f]{64}$/.test(assignment.content_sha256 || "")) return null;
    var render = assignment.render;
    if (!hasExactKeys(render, ["language", "layout", "template"]) ||
        !["compact", "inline", "stacked"].includes(render.layout) ||
        !/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}$/.test(render.language || "") ||
        render.language !== configuration.rule.locale) return null;
    var template = render.template;
    if (!hasExactKeys(template, ["actions", "body", "title"]) ||
        !hasExactKeys(template.actions, ["accept_all", "reject_all", "save_preferences"])) {
      return null;
    }
    if (![template.title, template.body, template.actions.accept_all,
          template.actions.reject_all, template.actions.save_preferences].every(plainText)) {
      return null;
    }
    return {
      language: render.language,
      layout: render.layout,
      template: {
        title: template.title,
        body: template.body,
        actions: {
          accept_all: template.actions.accept_all,
          reject_all: template.actions.reject_all,
          save_preferences: template.actions.save_preferences
        }
      }
    };
  }

  async function certifiedTrustCenter(value) {
    var keys = [
      "boundaries", "capabilities", "context_revision", "context_sha256",
      "generated_at", "profile_ref_sha256", "property_id", "retained_until",
      "schema", "sections", "snapshot_sha256", "source_pins", "tenant_sha256"
    ];
    if (!hasExactKeys(value, keys) ||
        value.schema !== "lightwork.consumer-trust-center.v1" ||
        !validRef(value.property_id) ||
        ![value.tenant_sha256, value.profile_ref_sha256, value.context_sha256,
          value.snapshot_sha256].every(function (item) {
            return typeof item === "string" && /^[0-9a-f]{64}$/.test(item);
          }) ||
        !Number.isInteger(value.context_revision) || value.context_revision < 1 ||
        !Number.isFinite(value.generated_at) || !Number.isFinite(value.retained_until) ||
        !Array.isArray(value.capabilities) || !value.sections ||
        typeof value.sections !== "object" || Array.isArray(value.sections) ||
        !value.source_pins || typeof value.source_pins !== "object" ||
        Array.isArray(value.source_pins)) return null;
    var mapping = {
      active_publication: "publication",
      consent_history: "consent",
      profile_data: "profile_data",
      rights_cases: "rights"
    };
    if (new Set(value.capabilities).size !== value.capabilities.length ||
        value.capabilities.some(function (capability) { return !mapping[capability]; })) return null;
    var expectedSections = value.capabilities.map(function (capability) {
      return mapping[capability];
    }).sort();
    var actualSections = Object.keys(value.sections).sort();
    if (expectedSections.length !== actualSections.length ||
        expectedSections.some(function (name, index) { return name !== actualSections[index]; })) {
      return null;
    }
    var actualPins = Object.keys(value.source_pins).sort();
    if (actualPins.length !== actualSections.length ||
        actualPins.some(function (name, index) { return name !== actualSections[index]; })) return null;
    for (var index = 0; index < actualSections.length; index += 1) {
      var name = actualSections[index];
      var section = value.sections[name];
      if (!section || typeof section !== "object" || Array.isArray(section) ||
          !/^[0-9a-f]{64}$/.test(value.source_pins[name] || "") ||
          value.source_pins[name] !== section.source_sha256) return null;
      try {
        if (await canonicalSha256(withoutKey(section, "source_sha256")) !==
            section.source_sha256) return null;
      } catch (_error) {
        return null;
      }
    }
    if (value.sections.publication && value.sections.publication.branding !== undefined &&
        !(await certifiedBranding(value.sections.publication.branding))) return null;
    try {
      if (await canonicalSha256(withoutKey(value, "snapshot_sha256")) !==
          value.snapshot_sha256) return null;
    } catch (_error) {
      return null;
    }
    return value;
  }

  function certifiedRightsStatus(value) {
    var outer = [
      "evidence_sha256", "payload", "signature", "signing_key_authority_sha256",
      "signing_key_ref", "signing_key_revision"
    ];
    if (!hasExactKeys(value, outer) || !value.payload ||
        typeof value.payload !== "object" || Array.isArray(value.payload) ||
        value.payload.schema !== "lightwork.privacy-rights-intake-status.v1" ||
        !validRef(value.payload.case_id) || !Array.isArray(value.payload.rights) ||
        !Number.isInteger(value.signing_key_revision) || value.signing_key_revision < 1 ||
        !/^(?:env|vault|secret|kms):[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}$/.test(
          value.signing_key_ref || ""
        ) || ![value.evidence_sha256, value.signature,
               value.signing_key_authority_sha256].every(function (item) {
          return typeof item === "string" && /^[0-9a-f]{64}$/.test(item);
        })) return null;
    var allowed = new Set([
      "access", "portability", "erasure", "rectification", "restriction",
      "objection", "opt_out"
    ]);
    if (value.payload.rights.length < 1 || value.payload.rights.length > allowed.size ||
        new Set(value.payload.rights).size !== value.payload.rights.length ||
        value.payload.rights.some(function (right) { return !allowed.has(right); })) return null;
    return value;
  }

  function LightworkConsent(options) {
    options = options || {};
    this.endpoint = requireText(options.endpoint, "endpoint").replace(/\/$/, "");
    this.clientCredential = requireText(options.clientCredential, "clientCredential");
    this.storage = options.storage || global.localStorage;
    this.storageNamespace = options.storageNamespace || "lightwork-consent-v1";
    this.autoPrivacySignals = options.autoPrivacySignals !== false;
    this.configuration = null;
    this.profileCredential = null;
    this.profileRevision = null;
    this.preferences = null;
    this.experimentAssignment = null;
    this.experimentExposureReported = false;
    this.profileData = null;
    this.profilePrompt = null;
    this.trustCenter = null;
    this.pendingRightsRequests = {};
    // Set only when the site opts in: then unsigned or badly signed
    // configurations are refused instead of shown.
    this.publicationKeys = trustedPublicationKeys(options.publicationKeys);
    // A short-lived visitor session, used when the consent service asks for one.
    this.sessionToken = null;
    this.sessionRenewAt = 0;
    this._sessionPending = null;
  }

  LightworkConsent.prototype._sessionCall = async function (path, token) {
    var headers = {
      "Authorization": "ConsentPublic " + this.clientCredential,
      "Accept": "application/json"
    };
    if (token) headers[SESSION_HEADER] = token;
    var response = await global.fetch(this.endpoint + path, {
      method: "POST", headers: headers, mode: "cors", credentials: "omit",
      cache: "no-store", redirect: "error"
    });
    var body = {};
    try { body = JSON.parse(await response.text() || "{}"); } catch (_error) { body = {}; }
    if (!response.ok || typeof body.session_token !== "string" ||
        !Number.isInteger(body.ttl_seconds) || body.ttl_seconds < 1) {
      var failure = new Error(body.detail || ("consent session failed: " + response.status));
      failure.status = response.status;
      throw failure;
    }
    this.sessionToken = body.session_token;
    // Renew at four fifths of the lifetime, measured on this device's clock.
    this.sessionRenewAt = Date.now() + body.ttl_seconds * 800;
    return this.sessionToken;
  };

  LightworkConsent.prototype._session = function (renew) {
    var self = this;
    if (!this._sessionPending) {
      var current = this.sessionToken;
      this._sessionPending = (async function () {
        if (renew && current) {
          try { return await self._sessionCall("/sessions/renew", current); } catch (_error) {
            self.sessionToken = null;  // ended or refused: start a new one
          }
        }
        return self._sessionCall("/sessions", null);
      })().finally(function () { self._sessionPending = null; });
    }
    return this._sessionPending;
  };

  LightworkConsent.prototype._withSession = async function (headers) {
    if (this._sessionPending) {
      try { await this._sessionPending; } catch (_error) { /* the request itself reports it */ }
    }
    if (this.sessionToken && Date.now() >= this.sessionRenewAt) await this._session(true);
    if (this.sessionToken) headers[SESSION_HEADER] = this.sessionToken;
    return headers;
  };

  LightworkConsent.prototype._storageKey = async function () {
    return this.storageNamespace + ":" + (await sha256(this.endpoint + "\0" + this.clientCredential)).slice(0, 32);
  };

  LightworkConsent.prototype._request = async function (path, options, retried) {
    options = options || {};
    var headers = Object.assign({
      "Authorization": "ConsentPublic " + this.clientCredential,
      "Accept": "application/json"
    }, options.headers || {});
    if (this.profileCredential) headers["X-Lightwork-Profile-Credential"] = this.profileCredential;
    if (options.body) headers["Content-Type"] = "application/json";
    await this._withSession(headers);
    var response = await global.fetch(this.endpoint + path, {
      method: options.method || "GET",
      headers: headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      redirect: "error"
    });
    var length = Number(response.headers.get("content-length") || "0");
    if (length > MAX_RESPONSE_BYTES) throw new Error("consent response exceeds its bound");
    var text = await response.text();
    if (new TextEncoder().encode(text).length > MAX_RESPONSE_BYTES) {
      throw new Error("consent response exceeds its bound");
    }
    var body = {};
    if (text) {
      try { body = JSON.parse(text); } catch (_error) { throw new Error("invalid consent response"); }
    }
    if (response.status === 401 && !retried && SESSION_REFUSALS.indexOf(body.detail) >= 0) {
      this.sessionToken = null;
      await this._session(false);
      return this._request(path, options, true);
    }
    if (!response.ok) throw new Error(body.detail || ("consent request failed: " + response.status));
    return body;
  };

  LightworkConsent.prototype._download = async function (path, body, reauthenticationReceipt, retried) {
    var headers = await this._withSession({
      "Authorization": "ConsentPublic " + this.clientCredential,
      "Accept": "application/octet-stream",
      "Content-Type": "application/json",
      "X-Lightwork-Profile-Credential": this.profileCredential,
      "X-Lightwork-Reauthentication-Receipt": reauthenticationReceipt
    });
    var response = await global.fetch(this.endpoint + path, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(body),
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      redirect: "error"
    });
    var length = Number(response.headers.get("content-length") || "0");
    if (length > MAX_RIGHTS_PACKAGE_BYTES) throw new Error("rights package exceeds its bound");
    if (!response.ok) {
      var errorText = await response.text();
      if (new TextEncoder().encode(errorText).length > MAX_RESPONSE_BYTES) {
        throw new Error("rights delivery failed");
      }
      var detail = null;
      try { detail = JSON.parse(errorText).detail; } catch (_error) { detail = null; }
      if (response.status === 401 && !retried && SESSION_REFUSALS.indexOf(detail) >= 0) {
        this.sessionToken = null;
        await this._session(false);
        return this._download(path, body, reauthenticationReceipt, true);
      }
      throw new Error(detail || ("rights delivery failed: " + response.status));
    }
    var bytes = await response.arrayBuffer();
    if (bytes.byteLength < 1 || bytes.byteLength > MAX_RIGHTS_PACKAGE_BYTES) {
      throw new Error("rights package exceeds its bound");
    }
    return new global.Blob([bytes], {type: "application/octet-stream"});
  };

  LightworkConsent.prototype._contract = function () {
    if (!this.configuration) throw new Error("consent configuration has not loaded");
    return {
      publication_sha256: this.configuration.publication.publication_sha256,
      bundle_sha256: this.configuration.publication.bundle_sha256,
      configuration_sha256: this.configuration.configuration_sha256,
      policy_version: this.configuration.policy_version,
      policy_sha256: this.configuration.policy_sha256
    };
  };

  LightworkConsent.prototype.loadConfiguration = async function () {
    var configuration = await this._request("/configuration");
    if (this.publicationKeys) await verifySignedConfiguration(configuration, this.publicationKeys);
    this.configuration = configuration;
    return this.configuration;
  };

  LightworkConsent.prototype.bootstrap = async function () {
    if (!this.configuration) await this.loadConfiguration();
    var key = await this._storageKey();
    var saved = null;
    try { saved = JSON.parse(this.storage.getItem(key) || "null"); } catch (_error) { saved = null; }
    if (!saved || typeof saved.profileCredential !== "string" || typeof saved.subject !== "string") {
      saved = {profileCredential: capability("lwpp_"), subject: capability("lwps_")};
      this.storage.setItem(key, JSON.stringify(saved));
    }
    this.profileCredential = saved.profileCredential;
    var result = await this._request("/profiles/bootstrap", {
      method: "POST",
      body: {
        subject_sha256: await sha256(saved.subject),
        profile_credential_sha256: await sha256(saved.profileCredential),
        idempotency_key: "sdk-bootstrap-" + (await sha256(saved.profileCredential)).slice(0, 40)
      }
    });
    this.profileRevision = result.profile_revision;
    if (this.autoPrivacySignals) await this.applyBrowserPrivacySignal();
    return result;
  };

  LightworkConsent.prototype.beginIdentityPairing = async function () {
    if (!this.profileCredential) await this.bootstrap();
    var codeVerifier = capability("");
    var result = await this._request("/identity/pairings", {
      method: "POST",
      body: {code_challenge: await pkceChallenge(codeVerifier)}
    });
    if (!hasExactKeys(result, ["expires_at", "oidc_nonce", "pairing_code"]) ||
        typeof result.pairing_code !== "string" ||
        !/^lwcp1\.[A-Za-z0-9_-]{32,192}$/.test(result.pairing_code) ||
        typeof result.oidc_nonce !== "string" || result.oidc_nonce.length < 32 ||
        !Number.isFinite(result.expires_at) || result.expires_at <= 0) {
      throw new Error("identity pairing response is outside the closed contract");
    }
    return {
      pairingCode: result.pairing_code,
      oidcNonce: result.oidc_nonce,
      codeVerifier: codeVerifier,
      expiresAt: result.expires_at
    };
  };

  LightworkConsent.prototype.authorizeIdentityPairing = async function (
    pairingCode, oidcNonce, oidcToken
  ) {
    if (!this.profileCredential) await this.bootstrap();
    if (typeof pairingCode !== "string" ||
        !/^lwcp1\.[A-Za-z0-9_-]{32,192}$/.test(pairingCode)) {
      throw new Error("pairing capability is invalid");
    }
    if (typeof oidcNonce !== "string" || oidcNonce.length < 32 || oidcNonce.length > 256) {
      throw new Error("pairing nonce is invalid");
    }
    if (typeof oidcToken !== "string" || oidcToken.length < 32 || oidcToken.length > 16384) {
      throw new Error("verified identity token is invalid");
    }
    return this._request("/identity/pairings/authorize", {
      method: "POST",
      body: {
        pairing_code: pairingCode,
        oidc_nonce: oidcNonce,
        oidc_token: oidcToken
      }
    });
  };

  LightworkConsent.prototype.redeemIdentityPairing = async function (
    pairingCode, codeVerifier
  ) {
    if (!this.profileCredential) await this.bootstrap();
    if (typeof pairingCode !== "string" ||
        !/^lwcp1\.[A-Za-z0-9_-]{32,192}$/.test(pairingCode)) {
      throw new Error("pairing capability is invalid");
    }
    if (typeof codeVerifier !== "string" || codeVerifier.length < 43 ||
        codeVerifier.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(codeVerifier)) {
      throw new Error("pairing verifier is invalid");
    }
    var result = await this._request("/identity/pairings/redeem", {
      method: "POST",
      body: {pairing_code: pairingCode, code_verifier: codeVerifier}
    });
    if (!hasExactKeys(result, ["linked", "status"]) ||
        result.status !== "redeemed" || result.linked !== true) {
      throw new Error("identity pairing response is outside the closed contract");
    }
    this.profileRevision = null;
    this.preferences = null;
    return result;
  };

  LightworkConsent.prototype.revokeIdentityPairing = async function (pairingCode, reason) {
    if (!this.profileCredential) await this.bootstrap();
    if (typeof pairingCode !== "string" ||
        !/^lwcp1\.[A-Za-z0-9_-]{32,192}$/.test(pairingCode)) {
      throw new Error("pairing capability is invalid");
    }
    reason = reason || "consumer-cancelled";
    if (typeof reason !== "string" || !reason || reason.length > 256) {
      throw new Error("pairing revocation reason is invalid");
    }
    return this._request("/identity/pairings/revoke", {
      method: "POST",
      body: {pairing_code: pairingCode, reason_sha256: await sha256(reason)}
    });
  };

  LightworkConsent.prototype.getPreferences = async function () {
    if (!this.profileCredential) await this.bootstrap();
    this.preferences = await this._request("/preferences");
    this.profileRevision = this.preferences.profile_revision;
    return this.preferences;
  };

  LightworkConsent.prototype.getExperimentAssignment = async function () {
    if (!this.profileCredential) await this.bootstrap();
    try {
      var assignment = await this._request("/experiments/assignment");
      var render = certifiedExperimentRender(assignment, this.configuration);
      if (!render) throw new Error("experiment assignment is outside the closed contract");
      assignment.render = render;
      this.experimentAssignment = assignment;
      this.experimentExposureReported = false;
      return assignment;
    } catch (_error) {
      this.experimentAssignment = null;
      this.experimentExposureReported = false;
      return null;
    }
  };

  LightworkConsent.prototype._experimentEventKey = async function (kind, suffix) {
    if (!this.experimentAssignment || !this.profileCredential) return null;
    var raw = kind + "\0" + this.experimentAssignment.experiment_id + "\0" +
      this.experimentAssignment.variant_id + "\0" + this.configuration.configuration_sha256 +
      "\0" + this.profileCredential + "\0" + String(suffix || "");
    return "sdk-experiment-" + kind + "-" + (await sha256(raw)).slice(0, 48);
  };

  LightworkConsent.prototype._reportExperimentExposure = async function () {
    var assignment = this.experimentAssignment;
    if (!assignment || assignment.eligible !== true || this.experimentExposureReported) {
      return null;
    }
    try {
      var result = await this._request("/experiments/exposure", {
        method: "POST",
        body: Object.assign({}, this._contract(), {
          idempotency_key: await this._experimentEventKey("exposure", "rendered")
        })
      });
      this.experimentExposureReported = result.recorded === true;
      return result;
    } catch (_error) {
      return null;
    }
  };

  LightworkConsent.prototype.reportExperimentOutcome = async function (success) {
    if (typeof success !== "boolean") throw new Error("experiment outcome must be boolean");
    if (!this.experimentAssignment || this.experimentAssignment.eligible !== true) return null;
    await this._reportExperimentExposure();
    try {
      return await this._request("/experiments/outcome", {
        method: "POST",
        body: Object.assign({}, this._contract(), {
          idempotency_key: await this._experimentEventKey("outcome", String(success)),
          success: success
        })
      });
    } catch (_error) {
      return null;
    }
  };

  LightworkConsent.prototype.updatePreferences = async function (choices) {
    if (!Array.isArray(choices) || !choices.length) throw new Error("choices are required");
    if (this.profileRevision === null) await this.getPreferences();
    var contract = this._contract();
    var key = await sha256(JSON.stringify(choices) + "\0" + String(this.profileRevision) + "\0" + contract.configuration_sha256);
    var result = await this._request("/preferences", {
      method: "PUT",
      body: Object.assign({}, contract, {
        expected_revision: this.profileRevision,
        idempotency_key: "sdk-preferences-" + key.slice(0, 48),
        choices: choices
      })
    });
    this.profileRevision = result.profile_revision;
    global.dispatchEvent(new CustomEvent("lightwork-consent-change", {detail: result}));
    return result;
  };

  LightworkConsent.prototype.getProfileData = async function () {
    if (!this.profileCredential) await this.bootstrap();
    this.profileData = await this._request("/profile-data");
    return this.profileData;
  };

  LightworkConsent.prototype.getProfileValueHistory = async function (preferenceId) {
    if (!validRef(preferenceId)) throw new Error("profile preference identifier is invalid");
    if (!this.profileCredential) await this.bootstrap();
    return this._request("/profile-data/preferences/" + encodeURIComponent(preferenceId) + "/history");
  };

  LightworkConsent.prototype.exportProfileData = async function () {
    if (!this.profileCredential) await this.bootstrap();
    return this._request("/profile-data/export");
  };

  LightworkConsent.prototype.getTrustCenter = async function () {
    if (!this.profileCredential) await this.bootstrap();
    var value = await certifiedTrustCenter(await this._request("/trust-center"));
    if (!value) throw new Error("trust center response is outside the closed contract");
    this.trustCenter = value;
    return value;
  };

  LightworkConsent.prototype.exportTrustCenter = async function () {
    if (!this.profileCredential) await this.bootstrap();
    if (!this.trustCenter) await this.getTrustCenter();
    var material = this.profileCredential + "\0" + this.trustCenter.snapshot_sha256;
    return this._request("/trust-center/exports", {
      method: "POST",
      body: {
        idempotency_key: "sdk-trust-export-" + (await sha256(material)).slice(0, 48)
      }
    });
  };

  LightworkConsent.prototype.createRightsRequest = async function (
    rights, requestReference
  ) {
    var allowed = new Set([
      "access", "portability", "erasure", "rectification", "restriction",
      "objection", "opt_out"
    ]);
    if (!Array.isArray(rights) || rights.length < 1 || rights.length > allowed.size ||
        new Set(rights).size !== rights.length ||
        rights.some(function (right) { return !allowed.has(right); })) {
      throw new Error("privacy-rights selection is invalid");
    }
    if (requestReference !== undefined && !validRef(requestReference)) {
      throw new Error("privacy-rights request reference is invalid");
    }
    if (!this.profileCredential) await this.bootstrap();
    var selection = rights.slice().sort().join(",");
    var pendingId = (await sha256(this.profileCredential + "\0" + selection)).slice(0, 48);
    var pendingStorageKey = (await this._storageKey()) + ":rights-pending";
    var pending = this.pendingRightsRequests;
    try {
      var persisted = JSON.parse(this.storage.getItem(pendingStorageKey) || "null");
      if (persisted && typeof persisted === "object" && !Array.isArray(persisted)) {
        pending = persisted;
      }
    } catch (_error) { pending = this.pendingRightsRequests; }
    var reference = requestReference;
    if (reference === undefined) {
      reference = validRef(pending[pendingId]) ? pending[pendingId] : capability("lwrr_");
      pending[pendingId] = reference;
      this.pendingRightsRequests = pending;
      try { this.storage.setItem(pendingStorageKey, JSON.stringify(pending)); } catch (_error) {}
    }
    var raw = await this._request("/rights-requests", {
      method: "POST",
      body: {
        rights: rights.slice(),
        expected_revision: 0,
        idempotency_key: "sdk-rights-create-" +
          (await sha256(this.profileCredential + "\0" + reference)).slice(0, 48)
      }
    });
    var value = certifiedRightsStatus(raw);
    if (!value) throw new Error("privacy-rights status is outside the closed contract");
    if (requestReference === undefined) {
      delete pending[pendingId];
      this.pendingRightsRequests = pending;
      try { this.storage.setItem(pendingStorageKey, JSON.stringify(pending)); } catch (_error) {}
    }
    global.dispatchEvent(new CustomEvent("lightwork-rights-request", {detail: value}));
    return value;
  };

  LightworkConsent.prototype.getRightsRequestStatus = async function (caseId) {
    if (!validRef(caseId)) throw new Error("privacy-rights case identifier is invalid");
    if (!this.profileCredential) await this.bootstrap();
    var value = certifiedRightsStatus(
      await this._request("/rights-requests/" + encodeURIComponent(caseId))
    );
    if (!value) throw new Error("privacy-rights status is outside the closed contract");
    return value;
  };

  LightworkConsent.prototype.renderTrustCenter = async function (container) {
    if (!(container instanceof global.Element)) throw new Error("container must be a DOM element");
    var snapshot = await this.getTrustCenter();
    var self = this;
    var sections = snapshot.sections;
    var branding = sections.publication && sections.publication.branding ?
      await certifiedBranding(sections.publication.branding) : null;
    var panel = element("section", null, "lightwork-consent lightwork-consent--trust-center");
    applyBranding(panel, branding);
    panel.setAttribute("role", "region");
    panel.setAttribute("aria-label", branding ? branding.heading : "Privacy Trust Center");
    if (branding) panel.appendChild(element("p", branding.display_name, "lightwork-consent__brand"));
    panel.appendChild(element("h2", branding ? branding.heading : "Privacy Trust Center"));
    panel.appendChild(element(
      "p",
      branding ? branding.description : "Review your governed privacy records and request history."
    ));

    if (sections.publication) {
      var publication = element("section", null, "lightwork-consent__trust-section");
      publication.appendChild(element("h3", "Published privacy configuration"));
      var notice = sections.publication.notice || {};
      var noticeLabel = validRef(notice.id) ? notice.id : "published-notice";
      publication.appendChild(element(
        "p",
        "Notice " + noticeLabel + " · version " + String(Number(notice.version) || 0)
      ));
      panel.appendChild(publication);
    }
    if (sections.consent) {
      var consent = element("section", null, "lightwork-consent__trust-section");
      consent.appendChild(element("h3", "Consent history"));
      var receipts = Array.isArray(sections.consent.receipts) ? sections.consent.receipts : [];
      consent.appendChild(element("p", String(receipts.length) + " governed receipt(s) available."));
      panel.appendChild(consent);
    }
    if (sections.profile_data) {
      var profile = element("section", null, "lightwork-consent__trust-section");
      profile.appendChild(element("h3", "Volunteered profile data"));
      var records = Array.isArray(sections.profile_data.current_records) ?
        sections.profile_data.current_records : [];
      var list = element("ul");
      records.slice(0, 100).forEach(function (record) {
        if (!record || !validRef(record.preference_id) || !validRef(record.status)) return;
        list.appendChild(element("li", record.preference_id + " · " + record.status));
      });
      profile.appendChild(list);
      panel.appendChild(profile);
    }
    if (sections.rights) {
      var rights = element("section", null, "lightwork-consent__trust-section");
      rights.appendChild(element("h3", "Privacy rights requests"));
      rights.appendChild(element(
        "p",
        "Only requests explicitly authorized for this portal are shown; completeness is not claimed."
      ));
      var cases = Array.isArray(sections.rights.cases) ? sections.rights.cases : [];
      var caseList = element("ul");
      cases.slice(0, 50).forEach(function (item) {
        if (!item || !validRef(item.case_id) || !validRef(item.status)) return;
        caseList.appendChild(element("li", item.case_id + " · " + item.status));
      });
      rights.appendChild(caseList);
      var requestActions = element("div", null, "lightwork-consent__rights-actions");
      var requestStatus = element("p", "", "lightwork-consent__trust-status");
      requestStatus.setAttribute("aria-live", "polite");
      [
        ["access", "Request access"],
        ["portability", "Request portability"],
        ["rectification", "Request correction"],
        ["restriction", "Request restriction"],
        ["objection", "Submit objection"],
        ["opt_out", "Request opt out"],
        ["erasure", "Request deletion"]
      ].forEach(function (entry) {
        var button = element("button", entry[1]);
        button.type = "button";
        applyBrandingAction(button, branding);
        button.addEventListener("click", async function () {
          button.disabled = true;
          requestStatus.textContent = "Submitting governed request…";
          try {
            var result = await self.createRightsRequest([entry[0]]);
            requestStatus.textContent = "Request created: " + result.payload.case_id;
          } catch (_error) {
            requestStatus.textContent = "Unable to create the request. Try again.";
          } finally {
            button.disabled = false;
          }
        });
        requestActions.appendChild(button);
      });
      rights.appendChild(requestActions);
      rights.appendChild(requestStatus);
      panel.appendChild(rights);
    }

    var status = element("p", "", "lightwork-consent__trust-status");
    status.setAttribute("aria-live", "polite");
    var download = element("button", "Download signed record");
    download.type = "button";
    applyBrandingAction(download, branding);
    download.addEventListener("click", async function () {
      download.disabled = true;
      status.textContent = "";
      try {
        var exported = await self.exportTrustCenter();
        var blob = new global.Blob([JSON.stringify(exported)], {type: "application/json"});
        var href = global.URL.createObjectURL(blob);
        var anchor = element("a");
        anchor.href = href;
        anchor.download = "lightwork-trust-center-export.json";
        anchor.click();
        global.URL.revokeObjectURL(href);
        status.textContent = "Signed record downloaded.";
      } catch (_error) {
        status.textContent = "Unable to download the signed record. Try again.";
      } finally {
        download.disabled = false;
      }
    });
    panel.appendChild(download);
    panel.appendChild(status);
    container.replaceChildren(panel);
    return panel;
  };

  LightworkConsent.prototype.redeemRightsPackage = async function (
    capabilityValue, reauthenticationReceipt
  ) {
    if (typeof capabilityValue !== "string" ||
        !/^lwrcd1\.[A-Za-z0-9_-]{32,192}$/.test(capabilityValue)) {
      throw new Error("rights delivery capability is invalid");
    }
    if (typeof reauthenticationReceipt !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._~-]{23,255}$/.test(reauthenticationReceipt)) {
      throw new Error("reauthentication receipt is invalid");
    }
    if (!this.profileCredential) await this.bootstrap();
    return this._download(
      "/rights-deliveries/redeem",
      {capability: capabilityValue},
      reauthenticationReceipt
    );
  };

  LightworkConsent.prototype.downloadRightsPackage = async function (
    capabilityValue, reauthenticationReceipt
  ) {
    var blob = await this.redeemRightsPackage(capabilityValue, reauthenticationReceipt);
    var href = global.URL.createObjectURL(blob);
    var anchor = element("a");
    anchor.href = href;
    anchor.download = "lightwork-rights-response.bin";
    anchor.click();
    global.URL.revokeObjectURL(href);
    return true;
  };

  LightworkConsent.prototype._profileDefinition = function (preferenceId) {
    if (!validRef(preferenceId)) throw new Error("profile preference identifier is invalid");
    var definitions = publishedProfileDefinitions(this.configuration);
    var definition = definitions ? definitions.get(preferenceId) : null;
    if (!definition) throw new Error("profile preference is not in the published configuration");
    return definition;
  };

  LightworkConsent.prototype._validateProfileValue = function (definition, value) {
    if (definition.value_type === "boolean") {
      if (typeof value !== "boolean") throw new Error("profile preference value is invalid");
      return value;
    }
    if (definition.value_type === "single_select") {
      if (typeof value !== "string" || !definition.option_ids.includes(value)) {
        throw new Error("profile preference value is invalid");
      }
      return value;
    }
    if (!Array.isArray(value) || value.length === 0 || value.length > 64 ||
        value.some(function (item) { return !definition.option_ids.includes(item); }) ||
        new Set(value).size !== value.length) {
      throw new Error("profile preference value is invalid");
    }
    return value.slice().sort();
  };

  LightworkConsent.prototype._currentProfileRevision = async function (preferenceId) {
    if (!this.profileData) await this.getProfileData();
    var current = Array.isArray(this.profileData.current) ? this.profileData.current : [];
    var record = current.find(function (item) { return item.preference_id === preferenceId; });
    return record && Number.isInteger(record.revision) ? record.revision : 0;
  };

  LightworkConsent.prototype.setProfileValue = async function (
    preferenceId, value, expectedRevision
  ) {
    if (!this.profileCredential) await this.bootstrap();
    var definition = this._profileDefinition(preferenceId);
    var closedValue = this._validateProfileValue(definition, value);
    var revision = expectedRevision;
    if (revision === undefined || revision === null) {
      revision = await this._currentProfileRevision(preferenceId);
    }
    if (!Number.isInteger(revision) || revision < 0) {
      throw new Error("profile preference revision is invalid");
    }
    var material = preferenceId + "\0" + JSON.stringify(closedValue) + "\0" +
      String(revision) + "\0" + this.configuration.configuration_sha256;
    var result = await this._request(
      "/profile-data/preferences/" + encodeURIComponent(preferenceId),
      {
        method: "PUT",
        body: {
          value: closedValue,
          expected_revision: revision,
          idempotency_key: "sdk-profile-set-" + (await sha256(material)).slice(0, 48)
        }
      }
    );
    this.profileData = null;
    global.dispatchEvent(new CustomEvent("lightwork-profile-data-change", {detail: result}));
    return result;
  };

  LightworkConsent.prototype._removeProfileValue = async function (
    action, preferenceId, expectedRevision
  ) {
    if (!this.profileCredential) await this.bootstrap();
    this._profileDefinition(preferenceId);
    var revision = expectedRevision;
    if (revision === undefined || revision === null) {
      revision = await this._currentProfileRevision(preferenceId);
    }
    if (!Number.isInteger(revision) || revision < 1) {
      throw new Error("profile preference revision is invalid");
    }
    var material = action + "\0" + preferenceId + "\0" + String(revision) + "\0" +
      this.configuration.configuration_sha256;
    var result = await this._request(
      "/profile-data/preferences/" + encodeURIComponent(preferenceId) + "/" + action,
      {
        method: "POST",
        body: {
          expected_revision: revision,
          idempotency_key: "sdk-profile-" + action + "-" +
            (await sha256(material)).slice(0, 48)
        }
      }
    );
    this.profileData = null;
    global.dispatchEvent(new CustomEvent("lightwork-profile-data-change", {detail: result}));
    return result;
  };

  LightworkConsent.prototype.unsetProfileValue = function (preferenceId, expectedRevision) {
    return this._removeProfileValue("unset", preferenceId, expectedRevision);
  };

  LightworkConsent.prototype.revokeProfileValue = function (preferenceId, expectedRevision) {
    return this._removeProfileValue("revoke", preferenceId, expectedRevision);
  };

  LightworkConsent.prototype.getProgressivePrompt = async function () {
    if (!this.profileCredential) await this.bootstrap();
    try {
      var assignment = await this._request("/profile-data/prompt");
      assignment = certifiedProfilePrompt(assignment, this.configuration);
      if (!assignment || assignment.eligible !== true) {
        this.profilePrompt = null;
        return null;
      }
      this.profilePrompt = assignment;
      return assignment;
    } catch (_error) {
      this.profilePrompt = null;
      return null;
    }
  };

  LightworkConsent.prototype._profilePromptInteraction = async function (outcome, suffix) {
    if (!this.profilePrompt || !["inserted", "completed", "dismissed"].includes(outcome)) {
      throw new Error("progressive prompt assignment is unavailable");
    }
    var assignmentId = this.profilePrompt.assignment_id;
    var material = assignmentId + "\0" + outcome + "\0" + String(suffix || "") + "\0" +
      this.configuration.configuration_sha256 + "\0" + this.profileCredential;
    return this._request("/profile-data/prompt/interactions", {
      method: "POST",
      body: {
        assignment_id: assignmentId,
        outcome: outcome,
        idempotency_key: "sdk-profile-prompt-" + outcome + "-" +
          (await sha256(material)).slice(0, 48)
      }
    });
  };

  LightworkConsent.prototype.renderProgressivePrompt = async function (container) {
    if (!(container instanceof global.Element)) throw new Error("container must be a DOM element");
    var assignment = await this.getProgressivePrompt();
    if (!assignment) return null;
    var definitions = publishedProfileDefinitions(this.configuration);
    if (!definitions) return null;
    var self = this;
    var controls = [];
    var panel = element("section", null, "lightwork-consent lightwork-consent--profile-prompt");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Additional privacy choices");
    panel.appendChild(element("h2", "Additional privacy choices"));
    panel.appendChild(element("p", "Choose whether to volunteer these optional profile values."));
    var form = element("form");
    assignment.prompts.forEach(function (prompt) {
      var definition = definitions.get(prompt.preference_id);
      var fieldset = element("fieldset", null, "lightwork-consent__profile-choice");
      fieldset.appendChild(element("legend", definition.title));
      fieldset.appendChild(element("p", definition.description));
      if (prompt.required) fieldset.setAttribute("aria-required", "true");
      var entry = {definition: definition, inputs: []};
      if (prompt.value_type === "boolean") {
        var booleanLabel = element("label");
        var booleanInput = element("input");
        booleanInput.type = "checkbox";
        booleanInput.name = prompt.preference_id;
        booleanLabel.appendChild(booleanInput);
        booleanLabel.appendChild(element("span", definition.title));
        fieldset.appendChild(booleanLabel);
        entry.inputs.push(booleanInput);
      } else {
        prompt.options.forEach(function (option) {
          var optionLabel = element("label");
          var optionInput = element("input");
          optionInput.type = prompt.value_type === "single_select" ? "radio" : "checkbox";
          optionInput.name = prompt.preference_id;
          optionInput.value = option.value_id;
          optionLabel.appendChild(optionInput);
          optionLabel.appendChild(element("span", option.label_ref));
          fieldset.appendChild(optionLabel);
          entry.inputs.push(optionInput);
        });
      }
      controls.push(entry);
      form.appendChild(fieldset);
    });
    var status = element("p", "", "lightwork-consent__profile-status");
    status.setAttribute("aria-live", "polite");
    form.appendChild(status);
    var actions = element("div", null, "lightwork-consent__actions");
    var saveButton = element("button", "Save profile choices");
    saveButton.type = "button";
    var dismissButton = element("button", "Not now");
    dismissButton.type = "button";
    actions.appendChild(saveButton);
    actions.appendChild(dismissButton);
    form.appendChild(actions);
    panel.appendChild(form);
    container.appendChild(panel);
    try {
      await this._profilePromptInteraction("inserted", "dom-inserted");
    } catch (_error) {
      panel.remove();
      this.profilePrompt = null;
      return null;
    }

    async function savePrompt() {
      saveButton.disabled = true;
      dismissButton.disabled = true;
      status.textContent = "";
      try {
        var view = await self.getProfileData();
        var revisions = new Map((view.current || []).map(function (record) {
          return [record.preference_id, record.revision];
        }));
        for (var index = 0; index < controls.length; index += 1) {
          var entry = controls[index];
          var value;
          if (entry.definition.value_type === "boolean") {
            value = entry.inputs[0].checked;
          } else {
            var selected = entry.inputs.filter(function (input) { return input.checked; })
              .map(function (input) { return input.value; });
            if (selected.length === 0) throw new Error("a closed option is required");
            value = entry.definition.value_type === "single_select" ? selected[0] : selected;
          }
          await self.setProfileValue(
            entry.definition.id,
            value,
            revisions.has(entry.definition.id) ? revisions.get(entry.definition.id) : 0
          );
        }
        await self._profilePromptInteraction("completed", "values-saved");
        container.dispatchEvent(new CustomEvent("lightwork-profile-prompt-completed", {
          detail: {assignment_id: assignment.assignment_id}
        }));
        panel.remove();
        self.profilePrompt = null;
      } catch (_error) {
        status.textContent = "Unable to save these choices. Review each option and try again.";
        saveButton.disabled = false;
        dismissButton.disabled = false;
      }
    }

    async function dismissPrompt() {
      saveButton.disabled = true;
      dismissButton.disabled = true;
      status.textContent = "";
      try {
        await self._profilePromptInteraction("dismissed", "person-dismissed");
        container.dispatchEvent(new CustomEvent("lightwork-profile-prompt-dismissed", {
          detail: {assignment_id: assignment.assignment_id}
        }));
        panel.remove();
        self.profilePrompt = null;
      } catch (_error) {
        status.textContent = "Unable to dismiss this prompt. Try again.";
        saveButton.disabled = false;
        dismissButton.disabled = false;
      }
    }
    saveButton.addEventListener("click", function () { savePrompt(); });
    dismissButton.addEventListener("click", function () { dismissPrompt(); });
    return panel;
  };

  LightworkConsent.prototype.applyBrowserPrivacySignal = async function () {
    var signal = global.navigator.globalPrivacyControl === true ? "gpc" :
      (String(global.navigator.doNotTrack || "") === "1" ? "dnt" : null);
    if (!signal) return null;
    if (this.profileRevision === null) await this.getPreferences();
    var contract = this._contract();
    var key = await sha256(signal + "\0" + String(this.profileRevision) + "\0" + contract.configuration_sha256);
    var result = await this._request("/privacy-signals", {
      method: "POST",
      body: Object.assign({}, contract, {
        signal: signal,
        expected_revision: this.profileRevision,
        idempotency_key: "sdk-signal-" + key.slice(0, 48)
      })
    });
    this.profileRevision = result.profile_revision;
    global.dispatchEvent(new CustomEvent("lightwork-consent-signal", {detail: result}));
    return result;
  };

  LightworkConsent.prototype._grantedPurposeIds = async function () {
    if (!this.preferences) await this.getPreferences();
    return new Set(this.preferences.preferences.filter(function (item) {
      return item.granted === true;
    }).map(function (item) { return item.purpose_id; }));
  };

  LightworkConsent.prototype.activateTaggedContent = async function (root) {
    root = root || global.document;
    if (!root.querySelectorAll) throw new Error("tagged-content root is invalid");
    var granted = await this._grantedPurposeIds();
    var published = new Set(this.configuration.configuration.purposes.map(function (item) {
      return item.id;
    }));
    var activated = 0;
    var blocked = 0;
    Array.from(root.querySelectorAll("[data-lightwork-purpose]")).forEach(function (node) {
      var purpose = node.getAttribute("data-lightwork-purpose") || "";
      var allowed = published.has(purpose) && granted.has(purpose);
      node.setAttribute("data-lightwork-consent-state", allowed ? "granted" : "blocked");
      if (!allowed) {
        blocked += 1;
        return;
      }
      if (node.tagName === "SCRIPT" && !node.getAttribute("data-lightwork-activated")) {
        var source = node.getAttribute("data-lightwork-src") || "";
        var parsed;
        try { parsed = new URL(source, global.location.href); } catch (_error) { parsed = null; }
        if (!parsed || parsed.protocol !== "https:") {
          node.setAttribute("data-lightwork-consent-state", "invalid-source");
          blocked += 1;
          return;
        }
        var script = element("script");
        script.src = parsed.href;
        script.async = node.hasAttribute("async");
        script.defer = node.hasAttribute("defer");
        script.setAttribute("data-lightwork-purpose", purpose);
        script.setAttribute("data-lightwork-activated", "true");
        node.after(script);
        node.setAttribute("data-lightwork-activated", "true");
        activated += 1;
      } else if ((node.tagName === "IMG" || node.tagName === "IFRAME") &&
                 !node.getAttribute("data-lightwork-activated")) {
        var deferred = node.getAttribute("data-lightwork-src") || "";
        var target;
        try { target = new URL(deferred, global.location.href); } catch (_error2) { target = null; }
        if (!target || !["https:", "data:"].includes(target.protocol)) {
          node.setAttribute("data-lightwork-consent-state", "invalid-source");
          blocked += 1;
          return;
        }
        node.setAttribute("src", target.href);
        node.setAttribute("data-lightwork-activated", "true");
        activated += 1;
      } else {
        node.dispatchEvent(new CustomEvent("lightwork-consent-granted", {
          detail: {purpose_id: purpose}
        }));
      }
    });
    return {activated: activated, blocked: blocked, reviewed: activated + blocked};
  };

  LightworkConsent.prototype.installAutoBlocker = async function (root) {
    root = root || global.document;
    var self = this;
    await this.activateTaggedContent(root);
    var observer = new MutationObserver(function (records) {
      records.forEach(function (record) {
        record.addedNodes.forEach(function (node) {
          if (node.nodeType === 1) self.activateTaggedContent(node.parentNode || root);
        });
      });
    });
    observer.observe(root === global.document ? global.document.documentElement : root, {
      childList: true,
      subtree: true
    });
    return function () { observer.disconnect(); };
  };

  LightworkConsent.prototype.updateGoogleConsentMode = async function (mapping) {
    if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) {
      throw new Error("Google Consent Mode mapping is required");
    }
    var allowedKeys = new Set([
      "ad_personalization", "ad_storage", "ad_user_data",
      "analytics_storage", "functionality_storage",
      "personalization_storage", "security_storage"
    ]);
    var granted = await this._grantedPurposeIds();
    var update = {};
    Object.keys(mapping).forEach(function (key) {
      if (!allowedKeys.has(key) || typeof mapping[key] !== "string") {
        throw new Error("Google Consent Mode mapping is outside the closed contract");
      }
      update[key] = granted.has(mapping[key]) ? "granted" : "denied";
    });
    if (typeof global.gtag === "function") global.gtag("consent", "update", update);
    global.dispatchEvent(new CustomEvent("lightwork-google-consent-mode", {detail: update}));
    return update;
  };

  LightworkConsent.prototype.pushTagManagerEvent = async function (eventName) {
    if (typeof eventName !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(eventName)) {
      throw new Error("tag-manager event name is invalid");
    }
    var granted = await this._grantedPurposeIds();
    var event = {event: eventName, lightwork_consent_purposes: Array.from(granted).sort()};
    global.dataLayer = global.dataLayer || [];
    global.dataLayer.push(event);
    return event;
  };

  LightworkConsent.prototype._render = async function (container, surface) {
    if (!(container instanceof global.Element)) throw new Error("container must be a DOM element");
    await this.getPreferences();
    var assignment = await this.getExperimentAssignment();
    var self = this;
    var content = this.configuration.configuration;
    var branding = content.branding === undefined ? null : await certifiedBranding(content.branding);
    if (content.branding !== undefined && !branding) {
      throw new Error("published branding is outside the closed contract");
    }
    var experimentRender = assignment ? assignment.render : null;
    var template = experimentRender ? experimentRender.template : content.template;
    var layout = experimentRender ? experimentRender.layout : "stacked";
    container.replaceChildren();
    var panel = element("section", null, "lightwork-consent lightwork-consent--" + surface +
      " lightwork-consent--layout-" + layout);
    applyBranding(panel, branding);
    panel.lang = experimentRender ? experimentRender.language : this.configuration.rule.locale;
    panel.setAttribute("role", surface === "banner" ? "dialog" : "region");
    panel.setAttribute("aria-label", template.title);
    panel.appendChild(element("h2", template.title));
    panel.appendChild(element("p", template.body));
    var notice = element("details");
    notice.appendChild(element("summary", content.notice.title));
    notice.appendChild(element("p", content.notice.body));
    panel.appendChild(notice);
    var form = element("form");
    var consentPurposes = content.purposes.filter(function (item) { return item.lawful_basis === "consent"; });
    consentPurposes.forEach(function (purpose) {
      var label = element("label", null, "lightwork-consent__choice");
      var input = element("input");
      input.type = "checkbox";
      input.name = purpose.id;
      var current = self.preferences.preferences.find(function (item) { return item.purpose_id === purpose.id; });
      input.checked = Boolean(current && current.granted);
      label.appendChild(input);
      label.appendChild(element("span", purpose.title + " — " + purpose.description));
      form.appendChild(label);
    });
    var actions = element("div", null, "lightwork-consent__actions");
    var saveStatus = element("p", "", "lightwork-consent__status");
    saveStatus.setAttribute("role", "status");
    var saveButtons = [], saving = false;
    function button(label, action) {
      var node = element("button", label);
      node.type = "button";
      applyBrandingAction(node, branding);
      node.addEventListener("click", action);
      actions.appendChild(node);
      saveButtons.push(node);
    }
    async function save(mode) {
      if (saving) return;
      saving = true;
      var choices = consentPurposes.map(function (purpose) {
        var input = form.elements[purpose.id], checked = input.checked;
        if (mode === "grant") checked = true;
        if (mode === "deny") checked = false;
        input.checked = checked;
        input.disabled = true;
        return {purpose_id: purpose.id, action: checked ? "grant" : "deny", expires_at: null};
      });
      saveButtons.forEach(function (node) { node.disabled = true; });
      saveStatus.textContent = "Saving choices…";
      try {
        await self.updatePreferences(choices);
        await self.getPreferences();
        consentPurposes.forEach(function (purpose) {
          var current = self.preferences.preferences.find(function (item) { return item.purpose_id === purpose.id; });
          form.elements[purpose.id].checked = Boolean(current && current.granted);
        });
        saveStatus.textContent = "Your choices are saved.";
        container.dispatchEvent(new CustomEvent("lightwork-consent-saved", {detail: self.preferences}));
        if (surface === "banner") container.replaceChildren();
        // Reporting an experiment must not turn a confirmed preference save into a failure.
        self.reportExperimentOutcome(true).catch(function () { /* Preferences remain saved. */ });
      } catch (error) {
        saveStatus.textContent = "Your choices could not be confirmed. " + error.message + " Review them and retry Save choices.";
      } finally {
        saving = false;
        consentPurposes.forEach(function (purpose) { form.elements[purpose.id].disabled = false; });
        saveButtons.forEach(function (node) { node.disabled = false; });
      }
    }
    button(template.actions.accept_all || "Accept all", function () { save("grant"); });
    button(template.actions.reject_all || "Reject all", function () { save("deny"); });
    button(template.actions.save_preferences || "Save choices", function () { save("current"); });
    form.appendChild(actions);
    form.appendChild(saveStatus);
    panel.appendChild(form);
    container.appendChild(panel);
    await this._reportExperimentExposure();
    return panel;
  };

  LightworkConsent.prototype.renderBanner = function (container) {
    return this._render(container, "banner");
  };

  LightworkConsent.prototype.renderPreferenceCenter = function (container) {
    return this._render(container, "preferences_center");
  };

  global.LightworkConsent = LightworkConsent;
})(window);
