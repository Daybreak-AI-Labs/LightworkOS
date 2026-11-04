# Inviting people and signing in

How the people in an organization get into a Lightwork deployment: single
sign-on for organizations with an identity provider, single-use invite links
for everyone else, and how the desktop app fits in. For release updates and
support bundles, see [product-operations.md](product-operations.md).

---

## 1. Sign-in options

**Organizations with an identity provider** (Microsoft Entra ID, Okta, Google,
an AWS-fronted proxy): Lightwork has built-in OIDC browser login
(`[auth.oidc]`), SAML, reverse-proxy SSO, and SCIM provisioning. Invite links
let an administrator add people without typing `user:<sub>` principals into the
RBAC roster by hand.

**Invite links.** `[dashboard] invites` (or `MAVERICK_DASHBOARD_INVITES`)
turns them on or off explicitly. When it is unset, invites become available
once a local owner has been set up.

- An administrator on `/users` enters an email address and a role and gets a
  **single-use, revocable link that expires after 7 days**. Only its hash is
  stored, and the link is shown once; copy it into an email or chat.
- **With SSO configured:** the invitee opens the link, signs in with the
  identity provider, and accepting binds their verified principal to the
  invited role. No principal strings and no identity-provider admin round trip.
- **Without an identity provider:** accepting the link **is** the sign-in. It
  mints a signed `mvk_session` cookie for `user:<email>` (30 days by default,
  `[dashboard] invite_session_days`), signed with a locally held secret
  (`~/.maverick/dashboard-session.key`, or `[dashboard] session_secret`). The
  link is the credential, with the same trust shape as a password-reset email.
  Re-invite to renew, or use "log out everywhere" to revoke; revocation epochs
  apply to these sessions exactly as to SSO sessions.
- Links are scanner-proof: a GET shows a confirmation page, and only the
  same-origin-gated POST consumes the link, single-use under a cross-process
  lock. `[dashboard] require_auth = true` makes the deployment fail closed:
  only invite sessions, SSO, a bearer token or a trusted proxy get in.

**Invite emails.** When a sending account is configured, Lightwork emails the
link itself. The platform mailer (`maverick.mailer`, standard-library SMTP)
reuses the `[email]` / `EMAIL_USER` + `EMAIL_APP_PASSWORD` account that the
email tool and the setup wizard already use, so there is one sending identity
to set up. Sending is fail-soft: a broken SMTP account falls back to the
copyable link. `[dashboard] invite_email = false` opts out, and
`MAVERICK_EMAIL_DISABLE=1` is the global kill switch. There is no self-serve
"email me a new link" page; re-inviting covers that case.

## 2. Where the desktop app fits

The desktop app is a window onto a Lightwork server, not a separate copy of
it. `apps/desktop` is a Tauri window that starts or attaches to the local
dashboard, and `apps/installer-desktop` is a one-button engineering installer
that bootstraps a source install.

- **One person:** run everything locally, with no accounts at all.
- **A small team without IT staff:** one machine or a small VPS runs the
  dashboard, and teammates join through **invite links** (§1). They can use a
  browser, or the desktop app pointed at the team server; the session cookie
  works identically. Giving each person their own local instance is not a
  sharing model: each laptop would have its own world model and audit trail.
  The server is the unit; the app is a way to look at it.
- **Larger organizations:** a platform team deploys with the Helm, VPS or
  container recipes in `deploy/`, SSO and SCIM own identity, and invites are
  still useful for the first administrators. The desktop app is optional.
- Desktop **updates** are meant to use the signed-release machinery in
  `release_update` (see [product-operations.md](product-operations.md) §1); a
  Tauri updater wired to `release_update.apply_bundle` is not built yet.

## Configuration quick reference

```toml
[dashboard]                                 # people onboarding (§1)
invites = true
require_auth = true                         # fail-closed team server
# invite_session_days = 30
# session_secret = "..."                    # else auto-generated, 0600
# invite_email = false                      # copy links instead of emailing them

[auth.oidc]                                 # SSO: see docs/configuration
# enabled/client_id/issuer/session_secret…
```
