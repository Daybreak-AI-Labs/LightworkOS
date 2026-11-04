/* Guard the Plugins page against ambiguous, duplicate changes.
   Every action is confirmed (mvConfirm) against its exact target, runs
   single-flight, and restores its controls after server or network failures so
   the administrator can correct the problem and retry. */
(function (global) {
  "use strict";

  function lines(value) {
    return String(value || "")
      .split(/[\s,]+/)
      .map(function (item) { return item.trim(); })
      .filter(Boolean);
  }

  // The approved list the admin is about to save: ticked boxes plus the one
  // new name typed in. Falls back to a single field's value (tests, old markup).
  function approvedFrom(form) {
    if (form && typeof form.querySelectorAll === "function") {
      var kept = Array.prototype.slice.call(form.querySelectorAll("[data-plugin-approved]"))
        .filter(function (box) { return box.checked; })
        .map(function (box) { return box.value; });
      var extra = form.querySelector("[data-plugin-new]");
      return kept.concat(lines(extra && extra.value)).filter(function (name, i, all) {
        return all.indexOf(name) === i;
      });
    }
    var field = form && form.elements && form.elements.names;
    return lines(field && field.value);
  }

  function confirmationFor(form, submitter) {
    var action = submitter && submitter.getAttribute("data-plugin-action");
    var target = submitter && (submitter.getAttribute("data-plugin-label") ||
      submitter.getAttribute("data-plugin-target"));
    target = String(target || "this plugin");
    if (action === "enable") {
      return "Turn on \u201c" + target + "\u201d? Lightwork will start running this plugin from the next task.";
    }
    if (action === "disable") {
      return "Turn off \u201c" + target + "\u201d? Its tools and connections stop working from the next task.";
    }
    if (action === "reset") {
      return "Use your organization's default for \u201c" + target + "\u201d? The choice made on this page will be removed.";
    }
    if (action === "install") {
      return "Install \u201c" + target + "\u201d? This runs the plugin's own setup on this computer and adds it to Lightwork.";
    }
    if (action === "replace-approvals") {
      var packages = approvedFrom(form);
      var exact = packages.length ? packages.join(", ") : "nothing";
      return "Save the approved list as " + exact + "? " +
        (packages.length
          ? "Only these " + packages.length + " plugin(s) can be installed from this page."
          : "This empties the list, so no new plugins can be installed from this page.");
    }
    if (action === "install-switch-on") {
      return "Turn installing on? Administrators will be able to install any plugin on the approved list.";
    }
    if (action === "install-switch-off") {
      return "Turn installing off? No new plugins can be installed from this page until it is turned back on.";
    }
    return "Save this plugin change?";
  }

  function setStatus(node, message, failed) {
    if (!node) return;
    node.textContent = message;
    node.setAttribute("role", failed ? "alert" : "status");
    node.setAttribute("data-tone", failed ? "danger" : "info");
  }

  // A plain sentence for a refused change; never the server's raw wording or
  // status number.
  async function failureDetail(response) {
    var status = response && typeof response.status === "number" ? response.status : 0;
    if (status === 400 || status === 422) {
      return "That plugin name can't be used. Use only letters, numbers, dots and dashes, then try again.";
    }
    if (status === 403) {
      return "This isn't allowed right now: you may need administrator rights, or installing may be switched off.";
    }
    if (global.mvErrorText) return global.mvErrorText(response, "save the plugin change");
    return "Something went wrong. Try again.";
  }

  function defaultPayload(form, submitter) {
    var payload;
    try {
      payload = new global.FormData(form, submitter);
    } catch (_error) {
      payload = new global.FormData(form);
    }
    if (submitter && submitter.name && !payload.has(submitter.name)) {
      payload.append(submitter.name, submitter.value);
    }
    return payload;
  }

  function createController(options) {
    var fetchRequest = options.fetchRequest;
    var confirmChange = options.confirmChange;
    var controls = options.controls;
    var statusNode = options.statusNode;
    var payloadFor = options.payloadFor || defaultPayload;
    var reload = options.reload;
    var inFlight = false;

    async function submit(form, submitter) {
      if (inFlight || (form.dataset && form.dataset.inFlight === "true")) {
        return { ok: false, reason: "in_flight" };
      }
      var prompt = confirmationFor(form, submitter);
      var okText = (submitter && submitter.textContent && submitter.textContent.trim()) || "Continue";
      // Hold the single-flight guard while the confirmation is open so a
      // second click can't queue a duplicate change.
      inFlight = true;
      if (form.dataset) form.dataset.inFlight = "true";
      function release() {
        if (form.dataset) delete form.dataset.inFlight;
        inFlight = false;
      }
      var confirmed = false;
      try {
        confirmed = Boolean(await confirmChange(prompt, okText));
      } catch (_error) {
        confirmed = false;
      }
      if (!confirmed) {
        release();
        setStatus(statusNode, "Nothing was changed.", false);
        return { ok: false, reason: "cancelled" };
      }

      // Snapshot the submitted values before disabling controls; disabled form
      // fields are intentionally omitted by FormData.
      var payload;
      try {
        payload = payloadFor(form, submitter);
      } catch (_error) {
        release();
        setStatus(
          statusNode,
          "The change couldn't be sent. Reload the page and try again.",
          true
        );
        return { ok: false, reason: "invalid_payload" };
      }
      var allControls = controls();
      var disabledBefore = allControls.map(function (control) {
        return { control: control, disabled: Boolean(control.disabled) };
      });
      allControls.forEach(function (control) { control.disabled = true; });
      if (submitter) submitter.setAttribute("aria-busy", "true");
      setStatus(statusNode, "Saving\u2026", false);

      var responseReceived = false;
      try {
        var response = await fetchRequest(form.action, {
          method: "POST",
          body: payload,
          credentials: "same-origin",
          redirect: "follow",
          headers: { "Accept": "application/json" },
        });
        responseReceived = true;
        if (!response.ok) {
          throw new Error(await failureDetail(response));
        }
        setStatus(statusNode, "Saved. Showing the latest\u2026", false);
        reload();
        return { ok: true };
      } catch (error) {
        var detail = responseReceived && error && error.message
          ? error.message
          : "Lightwork could not be reached. Check your connection and try again.";
        setStatus(statusNode, "Not saved. " + detail, true);
        return { ok: false, reason: "failed", detail: detail };
      } finally {
        disabledBefore.forEach(function (entry) {
          entry.control.disabled = entry.disabled;
        });
        if (submitter) submitter.removeAttribute("aria-busy");
        release();
      }
    }

    return { submit: submit, isInFlight: function () { return inFlight; } };
  }

  function init(documentRef) {
    var doc = documentRef || global.document;
    if (!doc) return null;
    var forms = Array.prototype.slice.call(
      doc.querySelectorAll("form[data-plugin-mutation]")
    );
    if (!forms.length) return null;
    var statusNode = doc.getElementById("plugin-mutation-status");
    var controller = createController({
      fetchRequest: global.fetch.bind(global),
      confirmChange: function (message, okText) {
        return global.mvConfirm ? global.mvConfirm(message, { okText: okText }) : Promise.resolve(false);
      },
      controls: function () {
        return forms.reduce(function (items, form) {
          return items.concat(Array.prototype.slice.call(
            form.querySelectorAll("button, input, textarea, select")
          ));
        }, []);
      },
      statusNode: statusNode,
      payloadFor: defaultPayload,
      reload: function () { global.location.reload(); },
    });
    forms.forEach(function (form) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var submitter = event.submitter || doc.activeElement;
        if (!submitter || !submitter.getAttribute("data-plugin-action")) {
          submitter = form.querySelector("[data-plugin-action]");
        }
        controller.submit(form, submitter);
      });
    });
    return controller;
  }

  var api = {
    confirmationFor: confirmationFor,
    createController: createController,
    failureDetail: failureDetail,
    init: init,
    lines: lines,
    approvedFrom: approvedFrom,
  };
  global.LightworkPluginMutations = api;
  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", function () { init(); });
    } else {
      init();
    }
  }
})(typeof window !== "undefined" ? window : globalThis);
