/* Response meaning and request epochs shared by private customer workbenches.
   Rendering, capability policy and schema validation stay in each workbench. */
(function () {
  "use strict";
  if (window.LightworkAccessState) return;
  function classify(response, payload, policy) {
    policy = policy || {};
    var detail = payload && payload.detail;
    var code = detail && typeof detail === "object" ? detail.code : "";
    var message = typeof detail === "string" ? detail : detail && detail.message;
    var kind = "ok";
    if (response.status === 401) kind = "session";
    else if (code === "workspace_context_changed" || code === "context_changed" ||
        (policy.contextMessage && typeof message === "string" && policy.contextMessage.test(message))) kind = "context";
    else if (response.status === 403) kind = policy.forbiddenScope ? "scope" : "capability";
    else if (response.status === 409) kind = "conflict";
    else if (response.status >= 500 || response.status === 429) kind = "transient";
    else if (!response.ok) kind = "rejected";
    return {kind: kind, code: code || "", status: response.status};
  }
  function staleError() {
    var error = new Error("The account or workspace changed. Reload this page before continuing.");
    error.code = "context_changed";
    return error;
  }
  function create(readContext, onInvalidate) {
    var epoch = 0, blocked = false;
    function invalidate(kind) {
      epoch += 1;
      if (!blocked) { blocked = true; onInvalidate(kind); }
    }
    function assertCurrent(token) {
      if (token.epoch !== epoch && !blocked) throw staleError();
      if (blocked || token.context !== readContext()) {
        invalidate("context");
        throw staleError();
      }
    }
    return {
      get blocked() { return blocked; },
      capture: function () {
        if (blocked) throw staleError();
        return {epoch: epoch, context: readContext()};
      },
      assertCurrent: assertCurrent,
      invalidate: invalidate,
      // A deliberate local selector change discards previous responses but
      // does not grant a new session or lift an access-loss lock.
      advance: function () { epoch += 1; },
      observe: function (response, payload, policy) {
        var result = classify(response, payload, policy);
        if (["session", "context", "scope"].includes(result.kind)) invalidate(result.kind);
        return result;
      }
    };
  }
  window.LightworkAccessState = {classify: classify, create: create};
})();
