# Desktop account sign-in return

The desktop shell has a narrow, opt-in return path for the Google and Atlassian
account connections offered on the Connections page. It opens the selected
provider's consent page in the system browser and receives the result back in
the already signed-in Lightwork page. Saving that result still requires the
user to select **Finish connection**. It does not run a workflow.

## Configuration and provider prerequisites

The normal dashboard remains at `http://127.0.0.1:8765`. The separate native
receiver uses exactly `http://127.0.0.1:8766/connections`. An installation
administrator must enable account connections and desktop returns in
Connections, then register and explicitly confirm this additional address on
each provider application. Registration credentials remain sealed within the
selected workspace; other users do not receive the application's secret or
registration-management authority.

The installer offers desktop returns as a separate default-off choice after
the OAuth vault choice. The corresponding configuration is:

```toml
[connections]
enable = true
[oauth]
vault = true
desktop_return = true
```

`MAVERICK_OAUTH_DESKTOP_RETURN` and `LIGHTWORK_OAUTH_DESKTOP_RETURN` are deployment
overrides, with the former taking precedence for the effective value. An
explicit false value in either prevents the in-app enablement action. The
reviewed authorization context includes both overrides. Enabling this switch
does not establish that Google or Atlassian has accepted the registered
application, redirect address, requested scopes, or customer account.

The native profile requires the exact local dashboard address, the main Tauri
window, the `/connections` page without a query or fragment, and the dashboard
process started by that exact desktop-shell instance. Other
deployments retain the existing browser return flow. This implementation does
not register a custom operating-system URL scheme and does not start a closed
Lightwork process when a callback arrives.

## Transaction boundaries

The shell creates a fresh 256-bit process-only ticket key before it starts its
dashboard child. The key is supplied only to that child, removed from the
desktop process environment, and never returned by an HTTP or native command,
written to disk, or included in diagnostics. System-browser and other desktop
children therefore cannot inherit it. A service that was already listening on
the dashboard port does not have the new key and cannot mint native authority
for this shell.

The API first issues a signed, short-lived preflight ticket bound to hashed
tenant, principal, provider client ID, connection choice and destination, plus
the exact context, profile, provider, scopes, callback and desktop instance.
The receiver verifies that ticket before binding IPv4 loopback, so an occupied
port or another pending attempt still fails before provider consent is created.
After consent is created, the API issues a separate launch ticket bound to the
preflight, native handle, consent/state, PKCE challenge and full authorization
URL. Rust verifies the HMAC and every binding before launch and verifies the
same single attempt ticket on every consume. A launch or result cannot be
replayed into another receiver or later attempt. The commands provide no
general URL opener, shell, filesystem, maintenance, or broadcast-event access
to the remote dashboard page. The OS opener receives an argument directly;
queries are never interpreted as shell commands.

One memory-only handle binds the page context, provider state, and a ten-minute
deadline. The listener accepts only a bounded GET request with the exact path,
Host and single matching state. Duplicate or malformed parameters, a different
origin header, and combined code/error results are rejected. A valid result
closes the listening socket immediately. The code is returned once to its
originating page; an unconsumed result is dropped at the deadline. Loading a
different main-window document or closing the application also drops the attempt. No code is written to
session storage, a native log, a diagnostic, or a navigated desktop URL.

The system browser receives a fixed response with no-store/no-referrer headers
and a CSP-hashed script that replaces the callback query in its current history
entry. This does not control the provider's own browser or network records.
The dashboard's existing callback access-log redaction remains in force for
the normal browser flow.

Explicit cancellation retains its native handle until the shell confirms the
listener closed, then retires only the exact matching backend consent. A close
failure keeps a working **Cancel sign-in** control so the same handle can be
retried. A verified denial or expiry also retires the exact backend consent,
refreshes current status, and exposes **Retry account sign-in** and the
same-workspace return to the original task. None of these paths alters a
previously saved credential record. If server retirement cannot be confirmed,
the UI says so and requires a refresh. Page exit always drops native state;
backend consent may remain sealed until expiry if cancellation could not be
sent. Denial, expiry and uncertain exchange preserve the non-secret connection
choice. They never resend an exchange automatically. Finish rechecks current actor/workspace/policy,
provider registration revision and named connection revision before any token
request, with existing cross-process mutation locking and single-use consent.

## Verification and remaining qualification

Python tests exercise the actual API, local sealed stores, operator/customer
authority, cancellation, old browser compatibility, and current revision and
context checks. DOM tests cover native success, occupied port, denial,
expiration, cancellation, late results and explicit Finish. Chromium tests
serve the actual page/CSP/API at port 8765, with synthetic Tauri invokes and
synthetic provider tokens; they cover desktop and 320-pixel layouts without
outbound provider requests. Those tests do not run native code.

`apps/desktop-oauth-return` is a dependency-free Rust broker. Its checked tests
include HMAC/SHA-256 vectors, ticket tamper/instance/expiry rejection, real TCP
one-shot return, URL/state/client/PKCE/scope binding, cancellation confirmation,
and a late callback against a new attempt; CI runs them with `cargo test`.
Native command capability evaluation, OS browser launch, WebView2 IPC and the
installed callback listener still require qualification on a Windows host. The
live provider consent/renewal and revocation matrix also remains external
qualification.

Before saving, Lightwork validates the provider-reported granted scopes,
retrieves the account identity from the provider's fixed identity endpoint and,
for Jira, validates the selected cloud resource. It stores the stable provider
subject, display name/email, requested and granted scopes, and the selected Jira
workspace in the sealed connection record. Connections shows those fields next
to the Lightwork owner. Renewal repeats the checks and requires reconnection if
the stable provider subject changes. These paths are covered with bounded
synthetic provider responses; they must not be reported as installed or
live-provider acceptance until the external matrix passes.

The exact provider-host matrix is:

| Provider | System-browser consent | Backend token exchange | Backend identity and workspace discovery | Product API |
| --- | --- | --- | --- | --- |
| Google | `accounts.google.com` | `oauth2.googleapis.com` | `openidconnect.googleapis.com` | `www.googleapis.com` for Drive or `storage.googleapis.com` for Cloud Storage |
| Atlassian | `auth.atlassian.com` | `auth.atlassian.com` | `api.atlassian.com` (`/me` and `/oauth/token/accessible-resources`) | `api.atlassian.com`, bound to the selected returned cloud ID |

An enterprise deployment must allow every backend host required by its enabled
profile. The system browser performs the consent navigation; Lightwork still
validates the returned URL and state. Backend token, identity, discovery and API
calls remain subject to the deployment and workspace egress gates. A missing
host permission produces an unavailable connection and a retry path; it never
skips identity, scope or Jira-site verification.

Provider prerequisites: [Google native application OAuth](https://developers.google.com/identity/protocols/oauth2/native-app),
[Google web application redirect requirements](https://developers.google.com/identity/protocols/oauth2/web-server),
and [Atlassian OAuth application setup](https://developer.atlassian.com/cloud/oauth/getting-started/enabling-oauth-3lo/).
Atlassian connections use the OAuth 2.0 (3LO) application that the
installation administrator registers in Connections; personal API tokens are
not used for this flow.
