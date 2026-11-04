# Help and diagnostics

Open **Help** from the app's top bar. An installation administrator can select
**Prepare support report**, review its readiness summary and expanded contents,
then confirm **Download reviewed report**. The downloaded bytes match that exact
preview. Nothing is sent to a provider or support service automatically.

The report contains all eight package versions, readiness, redacted settings and
recent failure information. Missing packages remain explicitly labelled. Secret
configuration values and recognized credential shapes are scrubbed, but workspace
labels and error descriptions may remain. Review the report before sharing it.
The full installation report requires current global administrator permission;
ordinary workspace members can inspect their own task status instead.

## Task reports and failure references

**Report a problem with a task** searches accessible failed or blocked tasks by
name and UTC date. **Find older tasks** continues through older history. A
stopped task also links directly to its authorized selection in Help.

Task report drafts are reviewed and edited inside Lightwork. They are held only
in the page's memory. They include the installed dashboard version and a short
recorded failure reason when the task has one, even when no separate error
event was saved. The reason is bounded and recognized secrets are removed, but
business details can remain and should be reviewed. Confirming the exact fields
checks access and secret scrubbing; if scrubbing changes an edited draft, review
the updated text again. The enabled **Copy reviewed draft** and
**Download reviewed draft** buttons keep the page open and make a local copy.
Send that copy through the
support channel your organization gave you. This installation has no configured
task-report support inbox, and Help does not send the draft to GitHub or another
service. A blocked clipboard write leaves the draft visible for download or
manual selection and copying.

Unexpected dashboard failures return a unique reference and UTC time. The same
reference identifies the exception in restricted server logs. It contains no
request URL, query string, customer name or stack trace. Following **Help** from
the failure page includes that reference in an authorized installation report.
Uncertain changes are checked before retrying; loading a failed read is safe to
retry. An independent minimal failure page remains available if normal template
rendering fails.

The support journey in an installed browser is not qualified.

Previews are encrypted, account/workspace-bound, valid for ten minutes, and
bounded to sixteen retained copies per context. Downloads recheck current
permission, context, feature availability, expiry and the reviewed digest. Access
denial clears the report from the page. The audit event records the reference and
digest, not the report contents. A denied or expired download requires a new
review.

**Settings → Features → Support center** controls collection. Deployment
configuration can set `[features] support_center = false`; the installer wizard
offers the same opt-out. Invalid configuration blocks collection.

If the dashboard cannot start, the desktop startup screen offers **Prepare a
startup support report**. This deliberately smaller report contains only the
desktop version, platform, a correlation reference, runtime availability and
owned-process state. It excludes configuration, account content, paths and logs,
and is available only to the bundled startup screen. Review it and choose its
download button explicitly. Full diagnostics remain available from Help after
sign-in.

## Draft storage

Editor recovery panels include **Manage recovery storage**. It displays saved,
discarded and available spaces. **Free discarded recovery space** requires
confirmation of the current inventory and retires only already discarded copies.
It never removes a saved draft or changes the open editor.

A durable encrypted revision floor is written before retirement deletes any
discarded record. Old tabs cannot recreate those copies with stale revisions,
including after interrupted cleanup. They must reload and review the current
copy before saving. Saved drafts retain their own revisions and exact retries.
Workspace and installation restore guards refuse to rewind this retention
authority or changed owner, named OAuth, and provider reconciliation state.
