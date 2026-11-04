"use strict";
// Saving on All settings goes through the complete protected review
// (lightwork-settings-review.js), and the reviewed plan is sent with its
// sealed token by lightwork-settings-catalog-requests.js. These stand-ins show
// the review's warnings (recorded in ``confirms``, as the person reads them),
// accept the review (or keep editing with ``decline``), and send the reviewed
// plan exactly as the real pair does.
// ``refuse`` returns the server's refusal of the review (its JSON body), which
// is raised as LightworkSettingsCatalog.review raises it.
function reviewedSaving(w, { confirms = [], warnings, decline = false, refuse } = {}) {
  w.mvReviewSettings = async (changes, revision) => {
    const refused = refuse && refuse(changes);
    if (refused) {
      const failure = new Error(refused.message || refused.detail);
      failure.status = refused.status || 409; failure.data = refused;
      throw failure;
    }
    (warnings ? warnings(changes) : []).forEach((item) => confirms.push(item.label + ": " + item.warning));
    if (decline) return null;
    return { changes, revision, token: "sealed-review", operation: "0".repeat(32), context: "c".repeat(64) };
  };
  w.LightworkSettingsCatalog = {
    save: async (plan) => {
      const response = await w.fetch("/api/v1/settings/catalog", { method: "POST", body: JSON.stringify({
        changes: plan.changes, expected_revision: plan.revision, reviewed_token: plan.token, confirm: true }) });
      return { response, data: await response.json() };
    },
  };
  return w;
}
module.exports = { reviewedSaving };
