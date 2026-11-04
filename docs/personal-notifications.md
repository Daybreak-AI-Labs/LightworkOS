# Personal in-product notifications

Your preferences links to **Your notifications**. In-app alerts (the bell) are
on by default: `[notifications] personal_alerts` is treated as on unless an
administrator sets it to `false`, and an explicit `false` always stays off.
Out of the box a named account hears when its tasks finish (or do not finish),
need an answer or need attention, and when an approval waits on it. When a
risky step has waited 10 minutes on the Approvals page with no decision, each
person who could decide it in Lightwork gets one reminder in the bell, and the
approval card says "Reminder sent" (`maverick_dashboard.approval_reminders`;
in-app only, never email, Slack or Teams). With
personal preferences on (the default), people can choose immediate alerts, a
daily digest, event subscriptions, a time zone, quiet hours, project watches
and temporary task mutes. Installation administrators can turn in-app alerts
off in All settings; the installer asks the same question. Email, Slack and
Teams delivery stays off until it is set up (`personal_background`,
`personal_external`).

The in-product inbox refreshes every 30 seconds while visible. Administrators
can also enable `personal_background` in All settings or the installer. The
dashboard then observes enrolled accounts while their pages are
closed, releasing eligible digests at the next observation. Creating work for
a current named account or opening its inbox enrolls that account in an
encrypted tenant-local registry. A first observation delivers a task completed
after enrollment while suppressing older completed-task history. The UI shows
the last completed background observation; enabled is not described as delivered.
The worker shares the dashboard shutdown supervisor, active-tenant checks,
current named-account authority, and the complete source projection (including
budget warnings). Revoked membership stops observation and removes that
account's enrollment and inbox state. At most 100 recipients are observed per
cycle with a rotating cursor and 20-second work budget; busy deployments may
observe less frequently than 30 seconds. Organization webhook alerts, including
ntfy, keep their separate policy and do not carry private task updates.

Administrators can additionally enable `personal_external` and save an HTTPS
dashboard origin in `personal_dashboard_url`. The installer exposes both. A
person first proves and confirms a messaging identity in My Data, then selects
that verified identity in personal notification preferences. Slack and Telegram
private delivery reuse the configured channel bot and current sender allowlist;
public room IDs and organization webhook destinations are refused. Delivery
checks the bot account digest against the authenticated receipt that proved the
link, and rechecks current identity/link/policy under the authority fence.

Messages carry a count and exact authenticated task/approval links, without task
titles, results or decision content. Opening links uses ordinary dashboard
authentication. Slack opens a one-person conversation and checks its returned
recipient before posting; Telegram accepts positive private sender IDs only.
The provider mechanisms follow [Slack conversations.open](https://docs.slack.dev/reference/methods/conversations.open/)
and [Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage).

Encrypted per-person/per-verified-link delivery records atomically claim semantic
item IDs before sending. Accepted, refused, interrupted and uncertain sends are
not automatically replayed. The inbox shows private delivery failures and service
acceptance separately from its explicit Mark seen action. One provider send is
attempted per recipient observation, oldest-attempted destination first. Daily
digests claim all currently eligible unseen delivery IDs once per local day;
critical exceptions still require both administrator policy and user opt-in.
Records keep up to 1,000 consumed item IDs for seven days; capacity pauses new
sends rather than evicting duplicate protection. Revoking a link stops its use.

The projection walks owner/tenant-scoped keyset pages of all unresolved work,
plus completed or cancelled tasks changed during the last seven days. Older
unresolved work and all open questions/assigned approvals remain eligible;
newer completed work cannot consume their page slots. Empty owned projects can
be watched before their first task exists. Muted-task validation checks current
ownership directly even after that task leaves the recent-activity window.

Migration44 adds semantic status/result generations to the existing goal row.
Database triggers advance them in the same native mutation transaction, including
raw receipt/CAS writes; rollback also rolls back the generation. A blocked task
that runs and becomes blocked again between observations therefore receives a
new identity. Heartbeats and repeated streaming states do not. Saved-result
changes count only after completion, and the decrypted content digest prevents
identical result rewrites from generating a new alert. Intermediate states that
resolve before observation are coalesced into current actionable state, as the
UI explains; the inbox is not a historical event audit.

Current authorization is checked before projection/publication; revoked sources
are removed and labels are hydrated anew, never stored in alert history. The
inbox does not silently truncate eligible sources or dedupe state at 1,000.
Deep links open ordinary authenticated pages. Fetching an alert does not mark it
seen; the person uses **Mark seen**. Native and Copilot preference changes use the
same current-source checks, exact revision and recoverable operation receipts.

Digest release uses the person's IANA wall-clock time and remembers the local
delivery date. A skipped DST clock time releases at the first eligible later
refresh; a repeated hour does not produce a second daily digest. Quiet hours
continue to apply. Approval/deadline timing exceptions require both the admin
`personal_critical_bypass` policy and the person's explicit opt-in. Mandatory
organization operational alerts are not controlled by these preferences.

Preferences use the shared account store's revision and account/workspace
binding. Background reads retain unsaved form edits; conflicts require an
explicit reload before editing the latest values. Muting one task does not
mute other tasks. Unsubscribed/off periods do not queue a later replay.

Native PostgreSQL and installed delivery to live messaging services are not
qualified.
