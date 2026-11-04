# Personal companion pairing (preview)

Enable **Allow personal companion pairing** in All settings or the installer.
Named members can then enter their dashboard address in the mobile companion's
Settings and choose **Start device pairing**. A twelve-character code lasts five
minutes. On the signed-in dashboard, **Your account → Your paired devices** shows
the exact device name, code, account and workspace before explicit approval.
Return to the device and check approval within one minute. Its own credential
is saved with the address in secure storage. No broad bearer is copied through
chat or a URL. Advanced administrator token setup remains available.

The credential admits only the enumerated own-task list/search/detail/events,
questions, active-work summary, personal costs, glance summary, goal tree and
offline bundle routes. Even an administrator's device has the own-task ceiling.
General dashboard pages, attachment downloads, streams, approvals, settings and
ordinary mutation endpoints are denied. A device cannot choose another tenant.
Each request checks current workspace membership, SCIM lifecycle, organization
policy and the account's log-out-everywhere epoch.

Credentials expire after 24 hours by default; All settings permits 1–168 hours
with workspace limits only narrowing the organization policy. **Renew paired
connection** rotates the secret before expiry. A failed local save can repeat
the exact generation for up to 60 seconds; the old secret can only recover this
renewal, never read work. The full enrollment expires after 30 days and needs
another browser approval. Renewal does not expand approved scopes.

**Your paired devices** and the authorized Copilot connections controls show
current devices and remove a selected one. Removal denies the next request;
native access-denial handling clears private views and eligible cache copies.
A disconnected device cannot learn about revocation until it reconnects: its
previous offline-retention ceiling remains the bound for copies already saved.
The separately default-off action policy requires explicit action enrollment at
browser approval. Renewal cannot add this scope. On a fresh online mobile task,
**Load current task actions** offers only **Review answer** and **Review Stop request**.
The server binds a three-minute sealed review to the exact account, workspace,
device, current role/policy, task revision, arguments and native operation receipt.
Nothing changes until the person confirms that review. Each application checks
current authority again, including device removal and session revocation.

An answer uses the same clarification submission and budget admission as the
full dashboard. Stop compares the reviewed owner and task revision atomically,
preserves partial results, and records a Stop request rather than claiming worker
cleanup or reversal of an external effect. A duplicate confirmed request recovers
its native receipt before checking the now-changed task. A lost response offers
an explicit check/retry of that same review; there are no automatic retries.
Backgrounding or loss of fresh online data discards the review authority. The
unsent answer remains in memory while the task screen stays mounted. Leaving the
screen discards that unsent draft; mobile never persists or queues an approval.

The installation registry is encrypted with the deployment at-rest key, uses
atomic writes and a cross-process authority lock, and contains at most 1,000
short-lived requests and 2,000 enrollments. Ten pending requests per actual
network peer are admitted per five-minute window. Records include device labels,
exact account/workspace binding and credential lifecycle metadata. Secrets and
pairing proofs are excluded from audit events. Multi-node dashboards must share
the same protected registry/key and authority fence; node-local registries are
not a distributed enrollment service.

Device pairing is a preview: real keychain, native transport, accessibility,
signing and installed-host behavior are not qualified.
