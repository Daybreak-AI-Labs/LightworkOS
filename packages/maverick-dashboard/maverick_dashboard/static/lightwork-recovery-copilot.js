(function () {
  "use strict";
  // Recovery stays local: this guide hosts the very same authorized form.
  // It cannot supply evidence, check consent, invoke a model or run other work.
  var section = document.getElementById("wrec-assistant");
  var controller = window.LightworkChannelReview;
  if (!section || !controller) return;
  var select = document.getElementById("wrec-assistant-item");
  var open = document.getElementById("wrec-assistant-open");
  var close = document.getElementById("wrec-assistant-close");
  var host = document.getElementById("wrec-assistant-review");
  var status = document.getElementById("wrec-assistant-status");
  var mounted = null, submitting = false, denied = false;

  function choices() {
    if (denied) return;
    var busy = submitting || (controller.isBusy && controller.isBusy());
    var previous = select.value;
    var rows = controller.list();
    select.replaceChildren();
    var empty = document.createElement("option");
    empty.value = ""; empty.textContent = "Choose a connection"; select.append(empty);
    rows.forEach(function (row) {
      var option = document.createElement("option");
      option.value = row.item_id; option.textContent = row.title;
      select.append(option);
    });
    if (rows.some(function (row) { return row.item_id === previous; })) select.value = previous;
    else mounted = null;
    if (!host.children.length) mounted = null;
    section.hidden = !rows.length && !status.textContent;
    select.disabled = busy || !rows.length;
    open.disabled = busy || !select.value;
    close.disabled = busy || !mounted;
  }

  function guidance() {
    var stage = controller.prepare(select.value).status;
    status.textContent = stage === "needs_refresh"
      ? "Refresh this review to check the latest saved information before continuing."
      : stage === "needs_confirmation" || stage === "ready"
        ? "Review the details below, then use the confirmation and record button when you are satisfied."
        : "Check the connected service, complete the details below, and confirm only what you can establish. You can leave an uncertain outcome unresolved.";
  }

  select.addEventListener("change", function () {
    controller.unmount(); mounted = null;
    status.textContent = select.value ? "Open the selected review to continue here." : "Choose the restored connection you want to review.";
    choices();
  });
  open.addEventListener("click", function () {
    if (submitting || !select.value) return;
    if (!controller.mount(select.value, host)) {
      status.textContent = "The review is unavailable or another step is in progress. Refresh recovery and try again.";
      choices(); return;
    }
    mounted = select.value; guidance(); choices();
  });
  close.addEventListener("click", function () {
    if (submitting) return;
    controller.unmount(); mounted = null;
    status.textContent = "Your entries are still in the recovery list. You can continue there or bring the review back here.";
    choices(); open.focus();
  });
  window.addEventListener("lightwork:channel-review", function (event) {
    var detail = event.detail || {};
    if (detail.status === "controls") { choices(); return; }
    if (detail.status === "denied") {
      controller.unmount(); mounted = null; submitting = false; denied = true;
      select.replaceChildren(); host.replaceChildren(); status.textContent = ""; section.hidden = true;
      open.disabled = true; close.disabled = true; select.disabled = true; return;
    }
    if (detail.status === "refreshed") denied = false;
    if (detail.status === "submitting") submitting = true;
    else if (["recorded", "unconfirmed", "refreshed", "unavailable"].includes(detail.status)) submitting = false;
    if (detail.status === "recorded") {
      status.textContent = "The review is recorded. No old action was repeated. The recovery list shows what remains to review.";
    } else if (detail.status === "unconfirmed") {
      status.textContent = "The result is not yet confirmed. Use Refresh status in the review before taking another action.";
    } else if (detail.status === "unavailable") {
      status.textContent = "Current recovery details are unavailable. Refresh recovery to check them before continuing.";
    } else if (detail.status === "refreshed" && mounted && !host.children.length) {
      status.textContent = "Recovery details changed or were refreshed. Reopen the current review and confirm its details again.";
    }
    choices();
  });
  choices();
})();
