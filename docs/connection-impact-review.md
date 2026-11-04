# Connection impact and qualification review

Connections > Used by shows only records the caller may inspect. Saved flows,
active runs and approvals, durable schedules, discovery sources, and active tasks
are evaluated separately. Exact references and possible dynamic connector use
are labelled separately; unavailable or administrator-only coverage stays visible.
Private employee flow definitions remain private even from administrators.

Every named credential update or local removal requires its revision, the
current account/workspace context, and a fresh impact digest. API clients should
GET `/api/v1/connections/{name}/impact` and submit the reviewed values. An unknown
network result is not permission to retry. Review current state first.

For a staged API key, save another owned account with the same adapter/service,
verify authentication, then review **Switch to staged API key**. Both records and
the fresh authentication receipt are checked under one store lock. The target's
sharing is preserved. Dynamic active tasks must finish or be cancelled before a
rotation because their tool choice is not pinned. Historical test receipts remain
bound to the old revision. Provider consent is handled by its dedicated flow.

The repair panel shows pinned discovery sources that need review and can rebind
one exact source to a reviewed current credential under global-admin authority.
It preserves that source's resource and evidence settings, uses the source revision
and operation ID, and starts no scan. Saved flows and approvals link to their own
review journey. Unknown external effects remain unknown; nothing is replayed.
Local removal never claims upstream revocation. Provider consent-management links
are a separate handoff and must not be used to revoke another application's access.

Read-capability checks use a fixed manifest: Drive file metadata, GCS bucket
metadata, Jira issue metadata, or GitHub repository metadata. Each is a bounded
public-provider HTTPS GET against an explicit resource; no arbitrary method/path,
external write, or write-access qualification is supported. Response identity
must match the selected resource. Only an outcome and resource digest are retained,
not response content. General authentication and exact resource access have
separate receipts. Reconnecting never automatically resumes or duplicates a task;
follow its exact saved-work link and operation-recovery review before proceeding.

The account inventory appears in Connections and Automations. Named accounts and
provider-wide automation credentials keep distinct usage domains and grants. Missing
identity, grant, and dependent-work evidence is disclosed instead of inferred.
The OAuth qualification matrix labels every unobserved installed Windows/provider
combination as unqualified and distinguishes synthetic, native and live evidence.

Installed and native hosts, sandbox jobs and live providers are not qualified.
OAuth acceptance requires a signed build, a registered provider application and
a test account. These UI and read-probe extensions use the Connections feature
gate. Mutation and rebind operations are not offered through Copilot; use their
governed in-product review.
