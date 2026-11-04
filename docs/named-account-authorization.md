# Renewable named accounts

In **Connections**, a signed-in installation administrator can explicitly enable
saved account authorization and save a provider app registration for the selected
workspace. A workspace administrator can then authorize their own named account
using that registration. Workspace administration alone does not grant access to
enablement or application registration controls. Both registration
secrets and access/refresh tokens are encrypted with that workspace's tenant
key. Password fields are excluded from draft recovery; secrets are not returned
by the listing APIs. The existing manually supplied token form remains available.

Supported account profiles are:

| Profile | Granted use | Provider hosts used by the flow |
| --- | --- | --- |
| Google Drive evidence | Read Drive documents | Browser consent: `accounts.google.com`; token exchange: `oauth2.googleapis.com`; account identity: `openidconnect.googleapis.com`; Drive API: `www.googleapis.com` |
| Google Cloud Storage discovery | Read storage objects and metadata | Browser consent: `accounts.google.com`; token exchange: `oauth2.googleapis.com`; account identity: `openidconnect.googleapis.com`; Storage API: `storage.googleapis.com` |
| Jira Cloud reviewed delivery | Read Jira work and create the reviewed task | Browser consent and token exchange: `auth.atlassian.com`; account identity, site discovery and site-bound API: `api.atlassian.com`, with the selected site's returned cloud ID |

Enterprise egress allowlists must include every backend host in the selected
row. Browser-consent hosts are opened by the user's system browser; the token,
identity, site-discovery and product API hosts are contacted by Lightwork and
remain subject to both deployment and workspace egress policy. Omitting an
identity or site-discovery host makes connection completion fail closed rather
than saving an account whose identity or Jira site was not verified.

The installation operator creates the provider application in the provider's
administration console, using the return addresses displayed by Lightwork, then
enters its client ID and secret in Connections. Lightwork does not include a
preregistered application for Google or Atlassian. Workspace members see which
providers are configured and review their own consent;
normal account setup does not require them to visit a developer console, create
an OAuth application, or handle registration secrets.
Only an installation administrator who can administer the current workspace
can inspect or edit its shared registration metadata. No listing returns the
client secret. Application registration, provider approval requirements and the
account holder's consent screen remain external provider steps. Lightwork does
not create a provider application or claim that a locally saved token has passed
a live acceptance test. Google scopes are documented in Google's
[OAuth scope catalog](https://developers.google.com/identity/protocols/oauth2/scopes).
Jira's site-bound API and rotating refresh tokens follow Atlassian's
[OAuth 2.0 application contract](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/).

Shared registrations live under a distinct key in the existing workspace-sealed
store. They are not shared across tenants. Existing personal registrations remain
private to their original owner and are not automatically promoted or copied.
New consent uses the workspace registration when present, with an explicit
owner-only legacy fallback otherwise. Legacy availability is labelled separately
and does not prefill the shared registration editor. Existing consent and saved
credentials without an application-key field continue to resolve only their
owner's legacy registration. Every new consent and credential pins the exact
selected registration key and revision; adding or removing another registration
cannot silently switch that binding.

Review the named connection, requested access and Jira site before opening
consent. On return, finish the connection in the same browser tab, signed-in
account and workspace that started it. A vendor request opened through its
connection detour can be returned to after cancellation or completion. Non-secret
connection input is retained separately from the single-use callback.
The server holds the PKCE verifier and a ten-minute, single-use state bound to
the account, workspace, app registration, original connection version and exact
return address. A changed account, workspace, configuration or credential refuses
the old return. The browser does not retain a verifier or client secret.

The browser return matches the returned state against the initiating tab's
session storage before offering the explicit finish action. The optional
desktop return opens consent in the system browser, receives a one-shot result
through a loopback listener owned by the current desktop shell, and delivers it
only to the initiating signed-in Lightwork page. Both paths require the same
explicit finish action. Moving a browser return into a different tab does not
transfer its state or signed-in session. Automated browser and Rust checks do
not qualify installed desktop return, native provider interoperability, or
restart recovery of an in-progress authorization. Those require installed-target
and provider-sandbox tests.

Google Drive and Jira vendor adapters, the Google Cloud Storage discovery
adapter, and named-connection resolution consume these actual saved records.
Normal token renewal retains the connection's reviewed generation. Replacing
the credential, changing sharing, or reconnecting creates a new generation so
enrolled source references and pending approvals must be reviewed again. Changing
an app registration requires reconnecting its accounts, even if old access bytes
have not expired. Public status checks the current registration binding rather
than displaying a stale ready state; changed registrations show reconnect
guidance, and unreadable authorization settings show unavailability. Authenticated
disconnect must include the reviewed connection revision. A concurrent reconnect
or rotation causes a stale disconnect to fail without deleting the replacement.
Ordinary edits cannot move an OAuth credential to another
provider or origin. Jira uses the selected site's ID returned by the provider;
it does not send OAuth credentials directly to a user-entered site.

Token exchange must report every required scope when the provider supplies a
scope list. Lightwork records requested and provider-reported scopes separately,
fetches the Google or Atlassian account identity before saving, and displays the
account, Lightwork owner and Jira workspace in Connections. Renewal fetches the
identity again and fails closed if the stable Google subject or Atlassian account
ID changes. If a provider omits the optional token scope response, the UI says
that no separate granted-access list was returned instead of presenting the
request as independently confirmed.

Renewal is serialized through the existing strict connection-store lock. The
application records a pending renewal before sending a rotating refresh token.
A lost response or interrupted process requires an explicit reconnect; it cannot
safely replay an old refresh token automatically. All calls retain the deployment
and workspace egress policy, public-address pinning, no-redirect token transport,
and bounded token responses. The app cannot waive a deployment-disabled
Connections or OAuth vault setting. The installer exposes these existing knobs
as **Named connections** and **OAuth token vault**.

Live provider registration, consent interoperability, account/scope verification
and acceptance testing remain deployment-specific work.
