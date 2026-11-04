# Model choices and bounded samples

Settings > Models retains the existing provider-grouped pickers, approved-model policy,
role overrides and advanced exact-name entry. Reported tool/image support, context and
output limits are evidence, not inferred promises. Missing values remain unknown;
pricing includes its source and date, with stale or expired evidence labelled.

Enable **Allow bounded model generation tests** in All settings or the installer to
make the separate test available. It defaults off. The administrator chooses a model
and either short text generation or recognition of a generated solid-color PNG, then
reviews and explicitly confirms the possible cost. The image and prompt are synthetic;
no tasks, personal memory, files or business content are supplied. This does not save a
model choice, refresh discovery automatically, or change provider credentials.

Each test narrows the configured Budget to at most USD 0.05, 2,048 input tokens,
64 output tokens and 30 seconds, with no tool calls. Normal model approval, enterprise
egress, kill switch, personal quota, workspace/provider admission, pricing and durable
accounting still apply. The selected provider configuration is fingerprinted at review
and checked at client construction and dispatch. SDK read/connect timeouts are narrowed
for this test's private client snapshot to at most 15/5 seconds; saved configuration is
unchanged. The client waits up to the test's wall cap and requests cancellation afterward.
Cancellation cannot retract an already transmitted request or prove the provider stopped
billing. A smaller configured cap wins; unknown billable pricing is never invented.

One physical attempt is admitted through the ordinary LLM facade. Automatic retries,
hedging and model failover are disabled. The tool-free boundary is deliberate: tool
compatibility resends are not individually observed by every provider adapter.
Tool support remains **provider-reported and untested**. A text or image match is evidence
for that one synthetic sample, not a tool qualification, model quality assessment,
context-size measurement, reliable latency forecast or customer acceptance.

The test is reserved durably before dispatch. Repeat confirmations recover the original
receipt. Stop before dispatch prevents generation; stop or transport loss after a possible
send remains an unknown outcome. A queued/executing receipt with no terminal result by
the test window is shown as unconfirmed and is never resumed automatically after restart.
Open the original spending/provider receipt before deliberately choosing another test.
Private per-account, per-workspace history stores metadata, result hashes and observed
outcomes rather than provider response bodies. Older receipts are accessible through
**Show earlier receipts**. Existing history stays available if tests are later disabled.

With the existing **Models** Copilot action family enabled, Copilot can compare current
reported metadata, prepare the same paid-test review, read original receipts and stop
pending tests. Native controls remain usable when AI conversation is unavailable. Copilot
cannot choose execution arguments or confirmation on the user's behalf; the shared typed
operation requires the same current authority, review and receipt recovery.

Real provider suitability and rendered customer acceptance are not qualified.
