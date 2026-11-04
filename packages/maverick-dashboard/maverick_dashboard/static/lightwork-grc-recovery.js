/* Human review of held GRC deliveries. All upstream comparisons are read-only. */
(() => {
  "use strict";
  const form = document.getElementById("gov-grc-recovery");
  if (!form) return;
  const delivery = form.elements.delivery, remote = form.elements.remote_id;
  const note = form.elements.note, status = document.getElementById("gov-grc-recovery-status");
  const comparison = document.getElementById("gov-grc-comparison");
  const inspect = document.getElementById("gov-grc-inspect");
  const confirm = document.getElementById("gov-grc-confirm");
  const keep = document.getElementById("gov-grc-keep-held");
  let evidence = null, busy = false, accessLost = false;
  const invalidate = () => { evidence = null; confirm.disabled = true; comparison.replaceChildren(); };
  delivery.addEventListener("change", () => { invalidate(); status.textContent = ""; });
  remote.addEventListener("input", invalidate);
  form.addEventListener("submit", event => event.preventDefault());
  const pending = value => {
    busy = value;
    form.setAttribute("aria-busy", String(value));
    [delivery, remote, note, inspect, keep].forEach(el => { el.disabled = value || accessLost; });
    confirm.disabled = value || accessLost || !evidence;
  };
  async function request(action, body) {
    const response = await fetch(`/api/v1/security/governance/grc-sync/outbound/${encodeURIComponent(delivery.value)}/${action}`, {
      method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    // Authentication failures may return an HTML sign-in page. Clear stale
    // private content before parsing, and require a fresh page after sign-in.
    if ([401, 403].includes(response.status)) {
      accessLost = true; invalidate();
      delivery.replaceChildren(new Option("Reload to review available deliveries", ""));
      remote.value = ""; note.value = "";
      throw new Error("Your session or permissions changed. Reload this page to review the deliveries you can currently access.");
    }
    let data;
    try { data = await response.json(); } catch (_) { throw new Error("The review result could not be read. Reload the delivery before trying again; your note is retained here."); }
    if (!response.ok) {
      if ([404, 409].includes(response.status)) invalidate();
      throw new Error(response.status === 409
        ? "This delivery changed while you were looking at it. Reload the page and compare again; your note is kept here."
        : response.status === 404
          ? "This delivery is no longer held. Reload the page to see the latest list."
          : response.status === 422
            ? "Check the record number and note, then try again."
            : "The review could not be saved. Reload the delivery and try again; your note is kept here.");
    }
    delivery.selectedOptions[0].dataset.revision = String(data.revision);
    return data;
  }
  function render(result) {
    comparison.replaceChildren();
    const title = document.createElement("p"); title.textContent = (window.mvPlainDetail && window.mvPlainDetail(result.detail)) || "Here is how this record compares with the other system."; comparison.append(title);
    if (result.remote_id) {
      const identity = document.createElement("p"); identity.textContent = `Record in the other system: ${result.remote_id}`; comparison.append(identity);
    }
    const list = document.createElement("ul");
    (result.fields || []).forEach(field => {
      const item = document.createElement("li");
      const label = String(field.name || "").replace(/[_-]+/g, " ");
      item.textContent = `${label.charAt(0).toUpperCase() + label.slice(1)}: ${field.matches ? "matches" : "differs"}. Lightwork sent: ${String(field.expected)}. The other system has: ${String(field.actual)}.`;
      list.append(item);
    });
    comparison.append(list); comparison.focus();
  }
  async function act(action) {
    if (busy || accessLost) return;
    if (!delivery.reportValidity()) return;
    if (action === "inspect" && !remote.reportValidity()) return;
    if (action !== "inspect" && !note.reportValidity()) return;
    if (action === "confirm" && !evidence) return;
    const body = {expected_revision: Number(delivery.selectedOptions[0].dataset.revision)};
    if (action === "inspect") body.remote_id = remote.value.trim() || null;
    else {
      body.note = note.value.trim();
      if (action === "confirm") body.evidence_sha256 = evidence;
    }
    pending(true);
    status.textContent = action === "inspect" ? "Checking the other system…" : "Saving your review…";
    try {
      const result = await request(action === "inspect" ? "inspect" : "resolve", body);
      if (action === "inspect") {
        evidence = result.inspection.matched ? result.inspection.evidence_sha256 : null;
        render(result.inspection); status.textContent = result.inspection.detail;
      } else {
        invalidate();
        if (result.status === "delivered") {
          delivery.selectedOptions[0].remove(); delivery.value = "";
          status.textContent = "Delivery verified and recorded. No content was resent.";
        } else status.textContent = "Review note saved. This delivery remains held.";
      }
    } catch (error) {
      // A lost acknowledgement can leave a newer revision on the server.
      // Never retry a decision automatically or reuse an uncertain comparison.
      invalidate(); status.textContent = error.message || "Could not complete the review. Your note is retained. Try again.";
    } finally { pending(false); }
  }
  inspect.addEventListener("click", () => act("inspect"));
  confirm.addEventListener("click", () => act("confirm"));
  keep.addEventListener("click", () => act("keep"));
})();
