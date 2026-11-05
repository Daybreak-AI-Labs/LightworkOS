# Security hardening (operator guide)

When a capability restricts workspace paths, tools that cannot enforce those
restrictions—including shell execution, workspace-wide searches and language
servers—are refused. Use a dedicated sandbox or an appropriately scoped tool
instead. Path checks alone do not establish an OS isolation boundary.

When a capability restricts hosts, only reviewed local tools and network tools
that enforce the grant are admitted. Unclassified/custom tools and built-ins
with unscoped network paths are refused, even if some of their operations are
local. Additions require an explicit security review before they are available
under a host-restricted grant.

The deferred `find_tools` discovery tool is also unavailable with restricted
host or path grants until its registry identity can be authenticated. Configure
the required reviewed tools directly for those agents.

Lightwork ships **defense in depth**. The protective controls that don't break
the happy path are now **on by default** ([Secure by default](#secure-by-default)
— at-rest encryption, audit signing, fail-closed consent for high/critical
actions, a sane tool-risk ceiling); the rest (OIDC, egress lock, Postgres RLS,
...) stay **opt-in** so a personal install isn't forced into operational burden.
Either way the controls are easy to miss, so this guide is the single place that
lists every one — what it does, the exact `~/.maverick/config.toml` block, the
environment-variable equivalent, the installer-wizard toggle (if any), gotchas,
and how to confirm it's actually on.

> **Precedence.** For every toggle below: a mandatory compliance floor wins over
> an explicit code arg, which wins over an environment variable, which wins over
> `~/.maverick/config.toml`, which wins over the secure-by-default posture. A few
> controls (capabilities, encryption-at-rest) are additionally **implied by
> enterprise mode** — see [Enterprise mode](#enterprise-mode-the-umbrella-switch).

> **Verify what's on.** `maverick soc2` prints a JSON posture snapshot of the
> main toggles (capabilities, tenant isolation, quotas, OIDC, encryption-at-rest,
> DSAR) plus audit-log verification. Use it after any change. See
> [Verifying your posture](#verifying-your-posture).

## Contents

- [Always-on safety (not opt-in)](#always-on-safety-not-opt-in)
- [Secure by default](#secure-by-default)
- [Enterprise mode (the umbrella switch)](#enterprise-mode-the-umbrella-switch)
- [Capability enforcement](#capability-enforcement)
- [Role-based access control (RBAC)](#role-based-access-control-rbac)
- [Multi-tenancy (per-user isolation)](#multi-tenancy-per-user-isolation)
- [Usage quotas](#usage-quotas)
- [Owner sign-in: authenticator app and recovery codes](#owner-sign-in-authenticator-app-and-recovery-codes)
- [OIDC SSO authentication](#oidc-sso-authentication)
- [OIDC browser login (built-in)](#oidc-browser-login-built-in)
- [Reverse-proxy SSO](#reverse-proxy-sso)
- [SAML SSO](#saml-sso)
- [Encryption at rest](#encryption-at-rest)
- [Risk-proportional verification](#risk-proportional-verification)
- [Audit-log signing (tamper-evidence)](#audit-log-signing-tamper-evidence)
- [WORM audit export (immutable retention)](#worm-audit-export-immutable-retention)
- [Two-person approval (N-of-M dual control)](#two-person-approval-n-of-m-dual-control)
- [Compliance commands](#compliance-commands)
- [Verifying your posture](#verifying-your-posture)
- [Recommended enterprise baseline](#recommended-enterprise-baseline)

---

## Always-on safety (not opt-in)

These are on by default and need no configuration. They are the floor the
opt-in controls build on:

- **Agent Shield** — the safety detection layer (`packages/maverick-shield/`).
  Fail-open with a warning if not installed; it's a chokepoint, not a hard
  dependency. All three scan surfaces — **input, tool-call arguments, and tool
  output** — run through a **decode/defang pre-pass** (`deobfuscate.py`):
  base64/hex/percent-encoded and Unicode-homoglyph payloads are decoded and the
  detectors re-run over each variant, so an encoded `rm -rf /` is caught even
  though the literal surface form hid it. The pre-pass is monotonic (it can only
  turn an allowed scan into a block, never the reverse) and bounded against
  decode bombs; escape hatch `MAVERICK_SHIELD_NO_DECODE=1`.
- **Sandbox-mediated shell** — all tool shell execution goes through
  `sandbox.exec()` (local/Firecracker backends), never raw `subprocess`.
- **Explicit task limits and organization allowances** — configured task caps
  are enforced at execution and metering boundaries. Ordinary tasks have no
  generated dollar, time, token, tool or step cap. Organization spend controls,
  provider accounting, cancellation and HALT remain separate authorities. See
  [task limits](task-limits.md) before choosing an allowance policy.
- **Append-only audit log** — every notable action is written to an
  append-only NDJSON audit log; when [signing](#audit-log-signing-tamper-evidence)
  is enabled it becomes an Ed25519 Merkle-chained, tamper-evident log.
- **Tool ACLs / risk ceilings** — allow/deny tool lists and a per-deployment
  max-risk ceiling (`maverick.safety.tool_acl`).
- **Consent / HITL** — human-in-the-loop confirmation gates for sensitive or
  destructive actions.

Most of the sections below are now **on by default** (next section); the rest you
**explicitly turn on**.

---

## Secure by default

The protective controls that don't break the happy path ship **on by default**.
No configuration is needed for a hardened baseline; you opt *out* if you want the
old behaviour. On by default:

| Control | Default-on behaviour | Opt out |
|---|---|---|
| [Encryption at rest](#encryption-at-rest) | seals sensitive stores; key auto-generates | `[encryption] at_rest = false` |
| [Audit-log signing](#audit-log-signing-tamper-evidence) | Ed25519 tamper-evidence; key auto-generates | `[audit] sign = false` |
| Fail-closed consent | high/critical-risk actions require confirmation (not auto-approved) | per-action consent config |
| Tool-risk ceiling | caps at `high` (CRITICAL tools need an explicit raise) | set `[security] max_risk` |

Still **opt-in** (operational burden / can break a working deployment): OIDC,
the egress lock (enterprise mode), and [Postgres RLS](multi-tenancy.md#enabling-rls-safely-guided-opt-in).
The Shield stays **fail-open** (the kernel runs without it).

**Master switch.** Turn the whole posture off with:

```toml
[security]
secure_defaults = false
```

- env: `MAVERICK_SECURE_DEFAULT=0`
- **Precedence** (per control): a mandatory compliance floor > explicit code arg >
  env var > config > `secure_defaults`. So an explicit `[encryption] at_rest = true`
  always wins, and HIPAA-mode at-rest can't be turned off by `secure_defaults = false`.

**Existing installs are safe.** Sealed reads are plaintext-tolerant, so data
written before the flip is returned unchanged until rewritten; run
`maverick encryption migrate` to seal it eagerly (and **back up the auto-generated
key** — `maverick encryption backup-key --to <dir>` — losing it loses the data).

---

## Deployment profile (one named switch)

If you only remember one knob, remember this one. `profile` picks the whole
security posture by name:

- `standard` (default) — the personal / dev posture. The always-on hardened
  controls (audit signing, at-rest encryption, fail-closed consent, tool-risk
  ceiling — see [Secure by default](#secure-by-default)) stay on, but the
  egress lock and the rest of enterprise mode stay off. Right for a single user
  running against a cloud LLM on their own machine.
- `enterprise` — the regulated posture. Turns [enterprise mode](#enterprise-mode-the-umbrella-switch)
  on by default (egress lock, consent fail-closed, capabilities enforced) on top
  of the always-on controls. It also flips three deployment-specific secure
  defaults (each still overridable by its own explicit knob):
  - **Sandbox = container.** A `local`/unset sandbox backend is upgraded to an
    available container backend (docker → podman) instead of running
    `shell=True` on the host; if no container runtime is installed it fails
    closed rather than running unsandboxed (`[sandbox] backend` / `require_container`).
  - **Plugin tool calls = subprocess.** The configured proxy can move tool
    calls out-of-process, but plugin discovery, import, and factories still
    run in the host process; install only trusted plugins (`[plugins] isolation`).
  - **Plugin lock = enforce.** The version/content lockfile is enforced (a no-op
    until you run `maverick plugin lock`, then drifted/unpinned plugins are
    refused) (`[plugins] lock_policy`).

  This is what the Helm chart and the reference server deployments set.

```toml
[profile]
name = "enterprise"     # or "standard"
```

```bash
export MAVERICK_PROFILE=enterprise    # env wins over config
```

Precedence is preserved: this only sets the *default* an unset control falls
back to. Any explicit knob (e.g. `[enterprise] mode = false`) and any compliance
floor still win over the profile. Because `enterprise` engages the egress lock,
make sure a local/self-hosted (or allow-listed) provider is configured, or runs
fail closed by design.

## Enterprise mode (the umbrella switch)

The fastest way to a hardened application posture. Enterprise mode pins every
governed LLM call to a local/self-hosted provider and checks supported Python
HTTP clients per request. It also **implies two of the controls below**: it
forces [capability enforcement](#capability-enforcement) on and turns on
[encryption at rest](#encryption-at-rest).

**config.toml**

```toml
[enterprise]
mode = true
```

**Environment variable**

```bash
export MAVERICK_ENTERPRISE=1          # set to a falsey value to force-disable
```

**Wizard toggle:** yes — "Enterprise mode (private/sensitive data)?"

**Gotchas**

- The egress lock pins LLM calls to `ollama` / `vllm` / `tgi`, or endpoints you
  allow-list under `[enterprise] local_providers`. A call routed to a known
  cloud provider raises `EgressBlocked` *before any prompt is sent*, and the
  denial is audited. Make sure you actually have a local provider configured,
  or runs will fail closed.
- This is an application-layer control, not a packet firewall. A hard
  no-egress boundary also requires sandbox network isolation and host/OS/VPC
  default-deny egress policy; raw sockets, subprocess clients, and unwrapped
  libraries are outside the application guard.
- `MAVERICK_ENTERPRISE` (when set to a non-empty value) wins over
  `[enterprise] mode`.
- Enterprise mode is documented in depth in
  [`docs/security/`](security/) and the enterprise module
  (`maverick.enterprise`). This guide only covers its security side effects.

> If you only want the individual controls (not the egress lock), skip this and
> turn on each control directly below.

---

## Capability enforcement

**What it does.** Gives every agent a *scoped, signed, attenuating* capability:
a grant over which tools (up to what risk), which filesystem paths, and which
network hosts it may touch. Child/sub-agents can only ever be **narrowed**
(attenuated) relative to their parent — least privilege by construction, so a
sub-agent can never exceed what its parent was granted. Off → enforcement is a
no-op and behaviour is unchanged.

**config.toml**

```toml
[capabilities]
enforce = true
```

**Environment variable**

```bash
export MAVERICK_ENFORCE_CAPABILITIES=1
```

**Scopes** (the grant is built from your existing `[security]` tool-ACL config —
the same allow/deny/max-risk knobs `maverick.safety.tool_acl` reads). The
`Capability` fields are:

| Field | Meaning | "empty" convention |
| --- | --- | --- |
| `allow_tools` | tool whitelist | empty set = **all** tools |
| `deny_tools` | subtractive deny — **deny wins over allow** | — |
| `max_risk` | risk ceiling: `"low"` / `"medium"` / `"high"` | `None` = no cap |
| `allow_paths` | fnmatch globs of filesystem paths the principal may touch | empty = **all** paths |
| `allow_hosts` | fnmatch globs of network hosts the principal may reach | empty = **all** hosts |

**Attenuation.** As a grant propagates to children: `allow_tools` intersects
(only shrinks), `deny_tools` unions (only grows), `max_risk` only tightens,
`allow_paths`/`allow_hosts` intersect, and `expires_at` is inherited (a child
never outlives its parent).

**Ed25519 signing.** Grants can be Ed25519-signed (`sign_capability` /
`verify_capability`, reusing the audit-signing key primitives) so they are
independently verifiable. Signing/verification requires the `cryptography`
package; verification returns `False` (never raises) if it's absent, so callers
that *require* verification must check for crypto first.

**Gotchas**

- A denied tool call emits a **`capability_denied`** audit event
  (`tool`, `principal`, `channel`, `user_id`) — grep your audit log for it to
  see what got blocked.
- With no `[security]` ACL configured, the root grant is all-permissive but
  still gives identity + least-privilege-on-spawn (children still attenuate).
- **Enterprise mode forces this on** regardless of `[capabilities] enforce`.

**Verify it's on:** `maverick soc2` →
`controls.capability_enforcement.status == "enabled"`.

---

## Role-based access control (RBAC)

**What it does.** Binds principals to *named roles*, where each role is a
capability scope. A principal's grant is the deployment ACL (the
[capability](#capability-enforcement) ceiling) **narrowed** by their role — so a
role can only ever *restrict*, never escalate past `[security]`. Roles fold into
the grant wherever capabilities are built, so they bite under capability
enforcement; with enforcement off they are inert.

**config.toml**

```toml
# Roles are capability scopes (same fields as a capability).
[roles.analyst]
allow_tools = ["read_file", "search", "memory"]
max_risk = "low"

[roles.operator]
deny_tools = ["shell"]
allow_paths = ["/srv/work/*"]

# Bind principals to roles. Keys are principal ids (an OIDC user maps to
# `user:<sub>`); `default` is the fallback for unassigned principals.
[role_assignments]
"user:alice" = "analyst"
"user:bob" = "operator"
default = "analyst"
```

**How it narrows.** A role routes through capability *attenuation*: `allow_tools`
intersects the ceiling, `deny_tools` unions it, `max_risk` only tightens, and
`allow_paths`/`allow_hosts` intersect. A role that lists *broader* tools than
`[security]` permits still cannot grant them — the ceiling wins, by construction.

**Gotchas**

- RBAC is opt-in: with no `[role_assignments]` the grant is exactly the ACL
  (behaviour unchanged). An unknown role name (no matching `[roles.<name>]`) is a
  no-op.
- It is a *subset* model, not additive: an "admin" role is simply one with no
  extra restrictions (it inherits the full ACL ceiling); narrower roles carve out
  less.

**Verify it's on:** roles fold into the capability grant, so the same
`maverick soc2` → `controls.capability_enforcement` signal applies; grep the
audit log for `capability_denied` to see a role's restrictions bite.

---

## Multi-tenancy (per-user isolation)

**What it does.** Namespaces Lightwork's on-disk state per *tenant* so one
tenant's data cannot leak to another. When enabled, each channel user is
isolated into their own tenant. Tenant `t`'s data lives under
`~/.maverick/tenants/<t>/...` instead of the legacy `~/.maverick/...` root.

The **cross-session memory** store, the **usage ledger** (quotas), the world
model, the audit log and other tenant-aware stores resolve their paths through
the tenant-aware path resolver.

**config.toml**

```toml
[tenancy]
by_user = true
```

**Environment variables**

```bash
export MAVERICK_TENANT_BY_USER=1      # isolate each channel user into its own tenant
# or pin a single explicit tenant for the whole process:
export MAVERICK_TENANT=acme-corp
```

**Wizard toggle:** yes — "Per-user tenant isolation?"

**Tenant derivation.** With `by_user` on, a request's tenant is
**`"<channel>:<user_id>"`** (e.g. `telegram:12345`), sanitized for safe use as
a path segment. The active tenant is resolved in order:

1. an explicit `set_tenant(...)` / `tenant_scope(...)` scope (a `ContextVar`, so
   concurrent async runs each pin their own tenant safely);
2. the `MAVERICK_TENANT` environment variable;
3. none → the shared/legacy `~/.maverick/...` root.

**Gotchas**

- With **no** tenant active, paths resolve to the legacy locations, so
  single-tenant installs are completely unchanged.
- Tenant ids become path segments: non-`[A-Za-z0-9._-]` bytes are
  percent-encoded, and an over-long id (> 200 chars after encoding) raises
  `InvalidTenantError`. Distinct ids can never collapse onto the same on-disk
  namespace.
- Per the module docstring this is an *incremental* migration: the
  most leak-sensitive store (cross-session memory) is isolated first. Confirm in
  your version which stores are routed through `maverick.paths.data_dir` before
  relying on isolation for a specific store.

**Verify it's on:** `maverick soc2` →
`controls.tenant_isolation.status == "enabled"`.

---

## Usage quotas

**What it does.** Where `Budget` caps a *single run*, quotas cap a *principal*
across runs over a rolling **UTC calendar day** — so you can do chargeback /
rate-limit spend per user or team. A persistent ledger records cumulative
dollars + input/output tokens per `(principal, day)` under the tenant-aware data
dir (`<data>/usage/ledger.json`, so it's already tenant-isolated). The module is
**fail-soft**: a ledger error logs a warning and never crashes a run; quotas
only ever *refuse*, never crash.

**config.toml**

```toml
[quotas]
enforce = true
max_dollars_per_day = 25.0       # 0 or unset = no limit on this dimension
max_tokens_per_day = 5000000     # counts input + output tokens
```

**Environment variables**

```bash
export MAVERICK_QUOTA_ENFORCE=1
export MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY=25
export MAVERICK_QUOTA_MAX_TOKENS_PER_DAY=5000000
```

**Wizard toggle:** yes — "Enforce per-principal usage quotas?" (the wizard
writes starter caps of `25.0` dollars and `5000000` tokens).

**Gotchas**

- Env vars override config per field. A cap of `0` (or unset) means "no limit on
  *this* dimension"; if **both** caps are `0`/unset, nothing is enforced even
  with `enforce = true`.
- Usage is **always recorded** (even when enforcement is off) so the ledger
  accrues chargeback data — turning enforcement on later acts on history already
  collected.
- The day window is **UTC**, so it doesn't shift with the host timezone/DST.

**Verify it's on:** `maverick soc2` →
`controls.usage_quotas.status == "enabled"`.

---

## Owner sign-in: authenticator app and recovery codes

Without company sign-in, the owner signs in on this computer with an email and
passphrase. An authenticator app can add a six-digit code to that sign-in.
Invited colleagues sign in with their passphrase only. Company sign-in keeps
its own second factor (`[auth.mfa]`, described in the enterprise security overview).

```toml
[auth.local_owner]
totp = "optional"   # "optional" (default) | "required" | "off"
```

| Value | What the owner sees |
|---|---|
| `optional` | Account > Authenticator app offers set-up. Nothing changes until the owner turns it on. |
| `required` | The owner must set up the app before reaching anything else: at first owner set-up, and at the next passphrase sign-in for an owner who has none. |
| `off` | The option is hidden and changes are refused. An owner who already has the app on is still asked for a code. |

The rule, in full: an owner who already has the app on is asked for a code at
every sign-in, whatever `totp` says, so an unreadable or invalid value never
turns that second factor off. An unreadable or unrecognised `totp` value reads
as `optional`; the log warns about it, and `maverick config-lint` reports it.
`required` only forces set-up on an owner who has not set one up, and `required`
refuses turning the app off.

How it works:

- **Set-up** re-asks for the passphrase, then shows a new secret as text and as
  an `otpauth://` address for manual entry. The app turns on only after a valid
  code from it. Codes are RFC 6238 (HMAC-SHA1, six digits, 30-second steps). A
  code from the current or the neighbouring step is accepted, and each step opens
  a sign-in once.
- **Recovery codes**: ten, shown once, from an alphabet without look-alike
  characters. Each works once. Only salted scrypt digests are stored. Making new
  codes needs a valid code and stops the old ones working.
- **Turning off** needs the passphrase and a current code or a recovery code.
- **Storage**: the secret is sealed with the deployment at-rest key (see
  [Encryption at rest](#encryption-at-rest)). The owner record never holds it in
  plain text.
- **Sign-in throttling**: the code step is limited per client address, like the
  passphrase step. A code step token lasts five minutes and takes five wrong codes
  before it is discarded. Wrong codes count toward the same one-minute lock as
  five wrong passphrases.
- **Sessions**: a session finished with a code records a second factor at that
  time, so the step-up checks for `[auth.mfa]` accept it. A session opened with
  the passphrase alone does not count.
- **Activity log**: set-up, turning off, new recovery codes and each use of a
  recovery code are recorded as control-plane actions. If the log refuses a
  record, the change is not made.

Lost your phone? Sign in with a recovery code, then make new codes on the
Authenticator app page. The page is `/account/owner-authenticator`.

Making new recovery codes, and turning the app off, are refused while `totp` is
`off`. To make new codes in that case, an administrator sets `totp = "optional"`,
the owner signs in with a code from the app (or a recovery code) and makes new
codes, and the administrator then sets `off` again. Keep the recovery codes
somewhere safe while the phone is still at hand.

If the phone is lost and every recovery code has been used, someone at this
computer can reset the app from its command line:

```
maverick owner reset-authenticator
```

The command asks for the owner's email to confirm. It then turns the app off,
deletes its recovery codes, and removes any set-up under way and any pending
sign-in or recovery steps. The change is recorded in the activity log first; if
the log refuses it, nothing changes. The command prints that the owner must set
the app up again. With `totp = "required"`, the owner's next passphrase sign-in
forces that set-up before anything else. No dashboard route can do this, and it
does not change the passphrase. Until the owner sets the app up again, the
passphrase alone opens the restricted company sign-in and single sign-on steps
below, as it does for any owner without the app. Under `totp = "required"` the
window lasts until the owner's next passphrase sign-in completes set-up. While
company sign-in is on, local sign-in is off, so set-up waits until it is off.

Company sign-in changes and their recovery also check the owner's passphrase.
An owner with an authenticator app must give a current code, or an unused
recovery code, on the first step of each restricted flow: the company sign-in
activation review, the company sign-in recovery form, the single-sign-on
activation review and the single-sign-on recovery form. The code issues a
recovery proof for that flow only. The proof is a random token, valid for ten
minutes. The owner record keeps only a SHA-256 digest of it, bound to the owner
and the flow name, and the browser receives it as an HttpOnly, SameSite=Strict
cookie on that flow's own path. Later steps of the same flow accept the proof
instead of a code, still check the passphrase, and refuse a proof issued to any
other flow. The proof is spent when the flow completes, or when the owner
cancels the flow from the same browser; a cancel from any other request changes
nothing. A wrong code counts toward the same one-minute lock as a wrong
passphrase. A step sent with no code is refused and counts nothing. A correct
passphrase does not clear that lock while a code is due. Issuing, using and
ending a proof are recorded in the activity log without any code or token. If
the log refuses the record of an ending, the proof is still ended. The recovery
routes are reachable only from this computer's loopback address and carry no
session; the activation reviews need the owner's session. An owner without an
authenticator app sees no change.

## OIDC SSO authentication

**What it does.** Verifies an OpenID-Connect **ID token** (a JWT) for the
`maverick serve` / dashboard HTTP surface against a configured issuer and
audience, mapping a verified subject to the principal `user:<sub>` (which slots
straight into the capability/tenant model). When enabled, **every gated request
must carry a valid `Authorization: Bearer <jwt>` header**; a missing/invalid
token gets an opaque `401`. Off → no token is required and behaviour is
unchanged (fail-open only when disabled).

**config.toml**

```toml
[auth.oidc]
enabled = true
issuer = "https://login.example.com/"
audience = "maverick"
jwks_uri = "https://login.example.com/.well-known/jwks.json"
algorithms = ["RS256", "ES256"]   # optional; asymmetric-only, default RS256/ES256
```

**Environment variables**

```bash
export MAVERICK_OIDC_ENABLED=1
export MAVERICK_OIDC_ISSUER="https://login.example.com/"
export MAVERICK_OIDC_AUDIENCE="maverick"
export MAVERICK_OIDC_JWKS_URI="https://login.example.com/.well-known/jwks.json"
export MAVERICK_OIDC_ALGORITHMS="RS256,ES256"   # comma-separated
```

**Wizard toggle:** yes — "Enable OIDC SSO token verification?" (prompts for
issuer / audience / jwks_uri and writes the `[auth.oidc]` table).

**Exempt paths** (answer without a bearer even when OIDC is on, for load
balancers / k8s probes / OpenAPI docs):
`/healthz`, `/livez`, `/readyz`, `/openapi.json`, `/docs`, `/redoc`,
`/docs/oauth2-redirect`, `/.well-known/agent-card.json`,
`/.well-known/agent.json`. **HMAC-signed webhooks** (`/webhook/...`) are also
exempt — they carry their own shared-secret signature and are gated separately,
so OIDC does not 401 inbound webhooks.

**Gotchas**

- **Needs the optional extra.** OIDC verification requires PyJWT. From the
  reviewed Lightwork checkout, run
  `python -m pip install -e './packages/maverick-core[oidc]'` (equivalently `pip install
  'pyjwt[crypto]>=2.13.0'`). The kernel imports fine without it; you'll only hit
  the error when a token is actually verified.
- **Asymmetric-only by design.** `algorithms` is filtered to asymmetric
  algorithms (`RS*`/`ES*`/`PS*`/`EdDSA`); `none` and every HMAC alg
  (`HS256/384/512`) are hard-rejected regardless of config — this defeats the
  alg-confusion attack. A config that lists only `HS256`/`none` falls back to
  the default `["RS256","ES256"]`.
- `exp`, `iat`, `aud`, `iss`, `sub` are all **required and verified**. Signing
  keys are fetched from `jwks_uri` keyed by the token's `kid`; an unknown `kid`
  is a rejection (no fallback key). There is **no fail-open-to-authenticated**
  path — any failure raises and yields a `401`.

**Verify it's on:** `maverick soc2` → `controls.oidc_auth.status == "enabled"`
(reports `absent` if the optional module/extra isn't installed).

**Session/token revocation + SCIM deprovisioning.** A leaked session cookie or a
still-valid bearer is force-invalidated by a per-principal **revocation epoch**
(`session-revocations.json`): "log out everywhere" and SCIM deprovision
(`active=false` / DELETE) bump it, and any credential whose `iat` predates it is
rejected — across processes. The revocation check fails **closed**: a damaged
revocation store is treated as "revoked", never silently un-revoked.

Some IdPs (notably Entra/Azure AD) issue a **pairwise/per-app** OIDC `sub` that
appears in no SCIM attribute. To still end such a user's live session on
deprovision, a **subject directory** (`oidc-subjects.json`, private/DACL-aware)
records, at each login, the `sub` against stable IdP identifiers. SCIM
deprovision resolves and revokes the pairwise subject before acknowledging the
lifecycle change. Privacy: lookup keys are `sha256(identifier)`; raw
emails/usernames do not enter the binding index.

A hard SCIM DELETE also writes a strict, bounded, atomic **retirement ledger**
before deleting the tenant or visible SCIM record. It stores hashed stable
identifiers and known subjects so a still-active IdP cannot restore access by
minting a fresh token after deletion. A new pairwise `sub` inherits retirement
when it presents the retired immutable IdP identifier. Only explicit successful
reprovisioning clears that retirement, and only after the tenant and active SCIM
record are durable. Corrupt binding/retirement state fails closed.

---

## OIDC browser login (built-in)

**What it does.** The [OIDC SSO](#oidc-sso-authentication) gate above verifies a
bearer **ID token** that *something else* obtained — great for API clients, but a
plain browser has no way to get one. The usual answer for browsers is to put an
auth proxy in front of the dashboard (oauth2-proxy, an ALB OAuth listener, your
IdP's proxy) and let it run the login. **If you can't run a proxy**, this
built-in flow has the dashboard itself drive the OAuth2 / OpenID-Connect
**authorization-code flow** (with PKCE): it redirects the browser to your IdP,
exchanges the returned code for tokens server-side, verifies the ID token (reusing
the same verifier as the bearer gate), and sets a signed session cookie. After
that, the browser is authenticated by the cookie — no bearer header needed.

> **Prefer the proxy.** The [reverse-proxy SSO](#reverse-proxy-sso) path below is
> the simpler, lower-surface option: it keeps the OAuth client secret and the
> login flow out of Lightwork entirely. Reach for this built-in flow only when
> running a proxy isn't practical.

**Off by default, fail-closed.** The `/auth/login` and `/auth/callback` routes
are inert (they return `404`) unless the flow is **fully configured**; an
unconfigured deployment behaves exactly as before, and the
bearer gate is untouched. "Fully configured" means OIDC is enabled **and**
`client_id` **and** `session_secret` are set **and** the authorization/token
endpoints are reachable (either an `issuer` for discovery, or both endpoints set
explicitly).

`GET /auth/logout` shows a confirmation; only a same-origin `POST` ends the
browser session or, with `?all=1`, revokes all sessions. Local and SAML sessions
also use this sign-out route. Behind a TLS proxy, configure the public HTTPS
origin with `MAVERICK_PUBLIC_URL` or `[dashboard] public_url` so the origin
check matches the browser's address. Open the dashboard at that canonical
origin; other host aliases cannot submit the sign-out form.

**config.toml** (extends the same `[auth.oidc]` table)

```toml
[auth.oidc]
enabled = true
issuer = "https://login.example.com/"     # used for discovery + ID-token verify
audience = "maverick"                       # your client_id / API audience
jwks_uri = "https://login.example.com/.well-known/jwks.json"

# --- browser-login (authorization-code) flow ---
client_id = "maverick-dashboard"            # the OAuth client registered for this app
client_secret = "..."                       # the OAuth client secret
redirect_uri = "https://dash.example.com/auth/callback"  # MUST match the IdP registration
session_secret = "a-long-random-string"  # pragma: allowlist secret

# Optional: skip discovery by pinning the endpoints explicitly.
# authorization_endpoint = "https://login.example.com/authorize"
# token_endpoint = "https://login.example.com/token"
```

**Environment variables**

```bash
export MAVERICK_OIDC_CLIENT_ID="maverick-dashboard"
export MAVERICK_OIDC_CLIENT_SECRET="..."
export MAVERICK_OIDC_REDIRECT_URI="https://dash.example.com/auth/callback"
export MAVERICK_OIDC_SESSION_SECRET="a-long-random-string"  # pragma: allowlist secret
# Optional explicit endpoints (otherwise discovered from the issuer):
export MAVERICK_OIDC_AUTHORIZATION_ENDPOINT="https://login.example.com/authorize"
export MAVERICK_OIDC_TOKEN_ENDPOINT="https://login.example.com/token"
```

**Wizard toggle:** yes — under "Enable OIDC SSO token verification?", a follow-up
"Also enable the built-in browser login flow?" prompts for the client_id/secret,
redirect URI, and session secret.

**Security model** (these are the load-bearing controls):

- **CSRF on the callback.** Each login mints an opaque `state` and stashes it in
  a short-TTL (~10 min) signed transaction cookie; the callback rejects (HTTP
  `400`) unless the returned `state` matches — *before* any token exchange.
- **PKCE (S256).** A per-login `code_verifier` is generated; its S256
  `code_challenge` is sent on the authorization request and the verifier on the
  token exchange, so an intercepted authorization code can't be redeemed.
- **HTTPS-only token exchange.** The token endpoint must be `https://` (the
  client secret is POSTed to it); a non-https endpoint is refused. Discovery is
  https-only too.
- **ID token still fully verified.** The `id_token` from the exchange is verified
  by the same `maverick.oidc.verify_oidc_token` as the bearer gate (asymmetric-
  only, `exp`/`iat`/`aud`/`iss`/`sub` required, JWKS-by-`kid`). No second,
  weaker verifier.
- **Signed session cookie.** The session cookie is HMAC-SHA256 signed with
  `session_secret` (stdlib only — no new dependency), carries `{sub, exp}`, and
  is verified in constant time with expiry enforced. It is `HttpOnly`,
  `SameSite=Lax`, and `Secure` (except on loopback for local dev). Tampered /
  expired / wrong-secret cookies are simply not authenticated.
- **Open-redirect defence.** A post-login `return_to` is honored only if it is a
  safe *local* path (starts with a single `/`, no `//`, no backslash, no control
  chars); anything else falls back to `/`.
- **No secrets in logs.** Failures log a generic reason only — never the token,
  the authorization code, the client secret, or the session value.

**Identity precedence.** When login is on, a valid `mvk_session` cookie is
accepted as the request identity (mapped to `user:<sub>`, recording
`claims.via = "session"`), sitting between any reverse-proxy header and the OIDC
bearer. Invalid/absent → falls through to the bearer path unchanged.

**Gotchas**

- The `redirect_uri` must **exactly** match what you registered at the IdP, and
  must be the dashboard's public `…/auth/callback` URL.
- Keep `session_secret` secret and stable: rotating it invalidates every live
  session (users re-login); leaking it lets an attacker forge sessions.
- This is **identity**, not network access — the dashboard's existing token /
  loopback gate still governs who may connect. The `/auth/*` routes are exempt
  from that gate (they bootstrap the session) but self-gate on full
  configuration.

---

## Reverse-proxy SSO

**What it does.** Lets a standard auth proxy in front of the dashboard
(oauth2-proxy, your IdP's proxy, an ALB OAuth listener, ...) own the browser
login, then forward the authenticated user's identity in a request header.
Lightwork maps that header to a `user:<id>` principal that flows into the
[capability](#capability-enforcement) and tenant model — browser SSO without
Lightwork hand-rolling an OAuth flow. The [OIDC](#oidc-sso-authentication) bearer
gate still serves API clients; this adds the browser path.

**config.toml**

```toml
[auth.proxy]
enabled = true
header = "X-Forwarded-User"          # the identity header your proxy sets
trusted_proxies = ["127.0.0.1"]      # peers allowed to assert it (default: loopback)
```

**Environment variables**

```bash
export MAVERICK_PROXY_AUTH=1
export MAVERICK_PROXY_AUTH_HEADER="X-Forwarded-User"
```

**Security — read this.** A forwarded header is trivially spoofable by a direct
client, so Lightwork honors it **only when the request's network peer is a
trusted upstream** (`trusted_proxies`; default loopback, since the proxy usually
runs on the same host). For this to be safe you **must**:

1. Make the proxy the **only** ingress to the dashboard (bind the dashboard to a
   loopback/private interface the proxy reaches) so nobody can connect directly.
2. Configure the proxy to **strip any client-supplied copy** of the identity
   header before it sets its own.

An explicit `trusted_proxies` list is exact — it *replaces* the loopback
default, so include loopback if you still want it. An unknown/empty peer is
never trusted (fail-closed).

**Gotchas**

- This sets *identity*, not network access — the dashboard's existing token /
  loopback gate still governs who may connect.
- The principal is `user:<header-value>`, so it lines up with `[role_assignments]`
  keys for role-based access control; the verified principal records
  `claims.via = "proxy"` so proxy-asserted identities are distinguishable from
  signed ID tokens.

**Verify it's on:** request a gated dashboard route through the proxy and confirm
access matches the forwarded user (grep the audit log for `capability_denied` to
see a role biting). Direct (non-proxy) requests must not carry a honored header.

---

## SAML SSO

**What it does.** A SAML 2.0 SP browser-login front-end alongside
[OIDC](#oidc-browser-login-built-in), for enterprises whose IdP (Okta,
Entra/Azure AD, OneLogin, ADFS) mandates SAML. The IdP POSTs a **signed
assertion** to the ACS; **pysaml2** verifies the XML signature (never hand-rolled
XML-dsig), and the same hardened `mvk_session` cookie the OIDC login issues is
minted — so a SAML user flows through [RBAC](#role-based-access-control-rbac) and
every `require_principal` gate exactly like an OIDC user (principal
`user:<NameID>`). Opt-in; off by default (the `/saml/*` routes 404 until configured).

**config.toml**

```toml
[auth.saml]
sp_entity_id = "https://YOUR-HOST/saml/metadata"
acs_url = "https://YOUR-HOST/saml/acs"
idp_metadata_url = "https://IDP/app/metadata"   # or idp_metadata_file = "/path/idp.xml"
want_assertions_signed = true
# sp_cert_file / sp_key_file  — to sign AuthnRequests / decrypt assertions

[auth.oidc]
session_secret = "<32+ random bytes>"   # SAML reuses the browser-login session secret
```

Setting `want_assertions_signed = false` still refuses any sign-in whose response is unsigned: the SP then requires a signed response instead. An assertion without its own signature is accepted only inside a signed response.

**Needs the extra:** from the reviewed Lightwork checkout, run
`python -m pip install -e './packages/maverick-core[saml]'` (pysaml2). The
routes 503 with a hint if it's absent.

**Wizard toggle:** yes — "Enable SAML 2.0 SSO?" (writes the `[auth.saml]` template).

**Endpoints** (mounted on the dashboard app, exempt from the dashboard-token gate
because the IdP POST carries no bearer):

- `GET /saml/metadata` — SP metadata XML; register this with the IdP.
- `GET /saml/login` — start SSO (redirects to the IdP). `?return_to=/path` sets a
  same-site post-login redirect (open redirects are rejected).
- `POST /saml/acs` — Assertion Consumer Service: verifies + sets the session.

**Gotchas**

- **Shares the session secret.** SAML mints the *same* `mvk_session` cookie as
  OIDC, so `[auth.oidc] session_secret` must be set or the ACS can't issue a session.
- **Not certified against a live IdP** — the pysaml2 calls are isolated and
  unit-tested with the library mocked; do an Okta/Entra round-trip in staging
  before production. Single-logout (SLO) is not implemented (local session clear
  only).
- Failures are opaque (`401 SAML assertion did not verify`) and never log the
  assertion — like the OIDC callback.

**Verify it's on:** `GET /saml/metadata` returns SP XML (not 404); a full IdP
login lands you authenticated with `user:<NameID>` as the principal.

---

## Encryption at rest

**What it does.** AES-256-GCM authenticated encryption for Lightwork's sensitive
local stores, so anyone who can read `~/.maverick` can't read its contents.
**On by default** ([Secure by default](#secure-by-default)); the key
auto-generates on first use.

**config.toml** (to **disable** on a personal box)

```toml
[encryption]
at_rest = false
```

**Environment variable**

```bash
export MAVERICK_ENCRYPT_AT_REST=0     # 1 to force-enable; 0 to force-disable
```

**Wizard toggle:** yes — "Encrypt sensitive local stores at rest?"

**Key management** (first match wins):

1. **`MAVERICK_ENCRYPTION_KEY`** — a 32-byte key as **hex or base64**, so you
   can inject a KMS-derived key without it ever touching disk.
   ```bash
   export MAVERICK_ENCRYPTION_KEY="$(openssl rand -hex 32)"   # 64 hex chars
   ```
2. Otherwise **`~/.maverick/keys/at_rest.key`** — generated on first use,
   `chmod 600`, directory `chmod 700`.

**Gotchas**

- **Scope.** Sealed: the **memory store**, the sensitive **world-DB content
  columns** (goal title/description/result, facts, turns/messages, questions,
  goal events, episode summaries/outcomes, parked approvals), and the
  **semantic-recall documents** on the chroma/pgvector backends. Run
  `maverick encryption migrate` to seal rows written before it was on. Not sealed:
  the live audit day-file (seal closed ones with `maverick audit seal`) and the
  qdrant/weaviate vector backends — see [encryption.md](encryption.md) for the
  full map.
- **Back up the key.** The auto-generated `~/.maverick/keys/at_rest.key` is the
  only way to read sealed data — escrow it with `maverick encryption backup-key
  --to <dir>`; if it's lost, the data is unrecoverable.
- **Requires `cryptography`.** With at-rest enabled but the package missing,
  `seal()` **fails closed** (raises `EncryptionUnavailable`) rather than writing
  plaintext. From the reviewed checkout, run
  `python -m pip install -e './packages/maverick-core[audit-signing]'`.
- **Transparent migration.** Sealed blobs carry a magic header; data written
  *before* you enabled encryption is read back transparently (no flag-day
  re-encrypt). New writes are sealed.
- **Don't lose the key.** If you rely on the generated `at_rest.key`, back it up
  — losing it means losing access to sealed data. Prefer
  `MAVERICK_ENCRYPTION_KEY` from your KMS for production.
- Precedence: `MAVERICK_ENCRYPT_AT_REST` (non-empty) wins over `[encryption]
  at_rest`, which wins over enterprise mode (which **implies** at-rest on).

**Verify it's on:** `maverick soc2` →
`controls.encryption_at_rest.status == "enabled"` (enterprise mode implies it).

---

## Risk-proportional verification

**What it does.** When on, the orchestrator may **skip** the LLM self-verifier
on clearly low-risk answers (a short, prose-only reply reached without touching
any tools), spending verification only where it matters. Any coding task, any
tool use, an embedded code block/diff/edit, or a long multi-part answer falls
through to full verification. This is a *cost/latency* optimization, not a safety
control — it never weakens verification on anything non-trivial.

**config.toml**

```toml
[verification]
risk_proportional = true
```

**Environment variable**

```bash
export MAVERICK_RISK_PROPORTIONAL_VERIFY=1
```

**Wizard toggle:** yes — risk-proportional verification prompt under advanced
options.

---

## Chat answers: streamed, and verified in proportion to risk

**What it does.** A chat turn (any run that answers inside a conversation:
the dashboard chat or a channel thread) shows its answer while the model is
still writing it. The root agent streams the model's text into the goal's
result as it arrives, throttled, secret-redacted, and replaced by the final
result when the turn ends, and the chat page renders it live. Streaming needs
the Anthropic provider; other providers still deliver the answer when the
turn completes. The evidence gateway, when enabled, withholds the preview
exactly as it withholds every other model-derived excerpt.

The preview shows only whole words that ended at least 96 characters before
the text received so far. A line that opens a quoted value for a named secret
(`API_TOKEN="...`) is held until the quote closes. Every update also passes
the Shield output scan: if a later part is blocked, the preview is withdrawn
and the chat page clears it. When the model stops at its output limit, the
cut-off tail is never shown, because it may end partway through a credential.
In scripts that do not separate words with spaces (Chinese, Japanese,
Korean), each character counts as a complete token.

A plain chat answer, reached with no tool use, no code block, and no edit
block, is handed to the person without the self-verifier's second model round
trip. Tool use, code, edit blocks, and long-form answers are always verified,
and standalone goals (REST, MCP, CLI) keep full verification.

**config.toml**

```toml
[chat]
stream_answers = true          # default; false disables the live preview

[verification]
verify_chat_answers = false    # default; true runs the verifier on every chat answer
```

**Environment variables**

```bash
export MAVERICK_STREAM_ANSWERS=0        # disable the live preview
export MAVERICK_VERIFY_CHAT_ANSWERS=1   # verify every chat answer
```

**Wizard toggle:** no; both are runtime defaults edited in config.toml.

**Gotcha.** Off by default; with it off, the orchestrator's FINAL is always
verified (subject to budget). Leave it off if you want maximal verification
regardless of cost.

---

## Audit-log signing (tamper-evidence)

**What it does.** Turns the append-only audit log into an **Ed25519
Merkle-chained, tamper-evident** log: each row is hash-chained and signed, and a
cross-file tip-ledger (`anchors.ndjson`) catches deletion/truncation of a whole
day-file. This is what makes [`maverick audit verify`](#compliance-commands)
and the `soc2` audit-chain probe meaningful. **On by default**
([Secure by default](#secure-by-default)); the signing key auto-generates. With
it off the log is append-only NDJSON but not cryptographically tamper-evident
(the probe reports `unsigned`).

**config.toml** (to **disable**)

```toml
[audit]
sign = false
```

**Environment variable**

```bash
export MAVERICK_AUDIT_SIGN=0     # 1 to force-enable; 0 to force-disable
```

**Gotchas**

- Precedence: explicit code arg > `MAVERICK_AUDIT_SIGN` env > `[audit] sign` in
  config > the secure-by-default posture (on).
- Requires `cryptography` (from the reviewed checkout, run
  `python -m pip install -e './packages/maverick-core[audit-signing]'`).
- The signing key lives under `~/.maverick/keys/`; `maverick soc2`'s
  `audit_signing_key` probe reports whether a key is present.

**Verify it's on:** `maverick audit verify` (see below) and `maverick soc2` →
`audit_log.status == "ok"` (vs `unsigned` when signing is off).

---

## WORM audit export (immutable retention)

**What it does.** Signing makes the log tamper-**evident** (you can *prove* an
alteration). WORM makes the historical records **un-alterable**: each closed
day-file is shipped to a write-once target with a retention lock, so neither a
privileged insider nor an attacker with filesystem/root access can rewrite or
delete the trail — the "immutable audit" a regulator (SEC 17a-4, HIPAA, SOX)
actually means. Opt-in (default off).

**config.toml**

```toml
[audit.worm]
provider = "s3"            # s3 (Object-Lock) | local (read-only mirror)
retention_days = 2555      # lock duration (~7y)
bucket = "my-audit-worm"   # s3: bucket with Object-Lock + versioning enabled
prefix = "maverick/audit/"
mode = "COMPLIANCE"        # COMPLIANCE (even root can't delete) | GOVERNANCE
region = "us-east-1"
# local provider: dir = "/mnt/worm/audit"
```

- env: `MAVERICK_AUDIT_WORM=1` (uses the `[audit.worm]` block).
- **Wizard toggle:** yes — "Export closed audit day-files to a write-once store?"

**Run it** (idempotent; cron it, e.g. nightly):

```
maverick audit worm push              # ship closed day-files to the WORM target
maverick audit worm push --dry-run    # show what would ship
maverick audit worm verify            # closed files all durably shipped? (non-zero if not)
```

**Gotchas**

- Only **closed** day-files (date < today) ship — today's file is still being
  appended. A file changed afterwards by `audit seal` / GDPR erase is re-shipped
  as a new locked version on the next push (push *after* sealing so the locked
  copy is the sealed one).
- **S3 setup is one-time, operator-side:** the bucket must be created with
  Object-Lock enabled (implies versioning); `boto3` is required (`pip install boto3`).
- **`local` is best-effort** (mode `0444`; an owner can chmod it back) — it gives
  on-box tamper-*evidence* via the manifest hash, not true WORM. Use `s3` +
  `COMPLIANCE` for regulator-grade immutability.
- GDPR erasure vs. WORM is a genuine tension: under COMPLIANCE lock a record
  can't be deleted before expiry. Crypto-shred (revoke the at-rest key) rather
  than expecting to rewrite a locked object.

**Verify it's on:** `maverick audit worm verify` (exits non-zero if any closed
day-file isn't in the WORM store).

---

## Two-person approval (N-of-M dual control)

**What it does.** Requires **N distinct approvers** to release a parked
high-/critical-risk action, and (by default) **bars the requester from approving
their own request** — the segregation-of-duties / "two-person rule" auditors test
under SOX, SOC 2 CC, and HIPAA. The [consent](#always-on-safety-not-opt-in) gate
already parks risky actions in the dashboard approvals queue; this sets how many
sign-offs that queue needs before the action proceeds. Opt-in (default
`approvals_required = 1` → the legacy single approver).

**config.toml**

```toml
[security]
approvals_required = 2          # 2 distinct approvers for every parked action
allow_self_approval = false     # default: the requester can't approve their own

# ...or vary N by risk band instead of a flat number:
[security.approvals_required]
high = 2
critical = 3
default = 1
```

- env: `MAVERICK_APPROVALS_REQUIRED=2` (global), `MAVERICK_ALLOW_SELF_APPROVAL=1`.
- **Wizard toggle:** yes — "Require two-person approval for risky actions?"

**How it works.** Each dashboard approve is a **vote** by the approver's verified
principal (`POST /api/v1/approvals/{id}/approve`); the action flips to `approved`
only once N *distinct* principals approve. A single `deny` rejects immediately. A
repeat vote from the same approver counts once (enforced by the
`approval_signoffs` primary key). `GET /api/v1/approvals/{id}/state` shows quorum
progress (`approved_count` vs `approvals_required`). A barred self-approval
returns **403** (vs **404** for an unknown approval).

**Gotchas**

- **Needs attributed approvers.** Distinctness requires each approver to have an
  identity, so run the dashboard with [OIDC](#oidc-sso-authentication) /
  [SAML](#oidc-browser-login-built-in) / reverse-proxy SSO; an unauthenticated
  (single-user) dashboard can't supply two distinct principals.
- The self-approval bar only bites when the approval records a `requested_by`
  principal; the quorum (N distinct approvers) is enforced regardless.

### A second person for high-risk actions (one approver)

With one approver (the default), `[approval] separate_approver` decides whether
the person who asked for a **high or critical** risk action may approve it
themselves:

```toml
[approval]
separate_approver = "when_available"   # default | "always" | "never"
```

- `when_available` (default): someone else must approve it whenever at least
  one other person could decide that request; where the requester is the only
  one who can, they may approve it, and the record marks it as a self-approval.
- `always`: someone else must approve it. If nobody else can, the request waits
  until it expires and the action is refused (nothing ever runs by default).
- `never`: the requester may approve it (still recorded as a self-approval).
- env: `MAVERICK_SEPARATE_APPROVER`. A value Lightwork does not know is treated
  as `always`. Settings > All settings (Safety > Approvals) and the setup wizard's
  Approvals step offer the same choice.

"Could decide that request" uses the existing permission model, nothing new:
the person holds `operate` in the workspace, is not deprovisioned, and can open
the request — on the Approvals page that is its owner or someone holding a
current, reviewed Content access grant for exactly that card; in Slack or Teams,
when approval cards are posted there, a linked account. So with Content access
requests off, an employee's private request can only be opened by that employee,
and the rule lets them approve it. Low and medium risk are unaffected; with two
or more approvers, distinct people approve anyway and `allow_self_approval`
alone decides whether the requester counts. The rule is enforced in the one
shared decision path, so the Approvals page, the API (403 with the plain
reason), Slack and Teams all obey it; the requester's Approve button is
disabled with the reason.

**Verify it's on:** park a high-risk action, then confirm one approval leaves it
`pending` and a second *distinct* approver flips it to `approved` (watch
`/approvals/{id}/state`).

---

## Compliance commands

| Command | Purpose |
| --- | --- |
| `maverick soc2` | Print a SOC 2 technical-posture snapshot as JSON (which controls are ON + whether the audit log verifies). Add `--json` for compact single-line output. Fail-soft: always emits JSON, but exits 1 unless the required controls are on, the audit log verifies and a signing key is present. |
| `maverick audit verify` | Verify the Ed25519 hash-chain (+ cross-file tip-ledger) of a signed audit log. Exits non-zero if the chain is not intact, so it can gate CI/cron. |
| `maverick dsar export --user <id>` | GDPR Art. 15/20 (access / portability): export everything Lightwork holds for a subject as a JSON bundle. |
| `maverick erase --channel <c> --user <id>` | GDPR Art. 17 (right to erasure): erase everything Lightwork knows about a `(channel, user_id)` pair. |

**`maverick audit verify` flags:**

```bash
maverick audit verify --day 2026-06-07           # default: today (UTC)
maverick audit verify --all                      # sweep every day-file in the audit dir
maverick audit verify --tenant acme              # verify a specific tenant's audit dir
maverick audit verify --file path/to/log.ndjson  # one file (overrides --day/--all)
maverick audit verify --pubkey <ed25519-hex>     # trusted external key for real
                                                 # third-party tamper-evidence
```

> **Flags.** `audit verify` accepts `--day`, `--all`, `--tenant`, `--file`, and
> `--pubkey`. `--all` sweeps every `YYYY-MM-DD.ndjson` day-file in the audit dir
> (the anchor ledger is verified separately as the cross-file tip-ledger).
> `--tenant <t>` resolves that tenant's audit dir the same way the writer/signer
> wrote it (`~/.maverick/tenants/<t>/audit/`); the default follows the active
> tenant. `--file` pins a single file and overrides `--day`/`--all`. Without
> `--pubkey` it trusts a locally-held key and prints a warning; pass the
> externally-held pubkey for genuine third-party tamper-evidence. Exits 1 on any
> break, 0 when clean. If `cryptography` is missing the chain can't be verified
> at all, which is treated as a verification break and exits 1 — so automation
> can't pass unverifiable evidence as clean.

**`maverick dsar export` flags:**

```bash
maverick dsar export --user <user_id> \
    [--tenant <t>] \         # default: active tenant
    [--output bundle.json] \ # -o; default stdout. Written 0o600.
    [--json]                 # compact single-line JSON
```

**`maverick erase` flags:**

```bash
maverick erase --channel telegram --user <user_id> [--yes]
```

> Note: `erase` requires **both** `--channel` and `--user`; it scopes erasure to
> that one `(channel, user_id)` pair (conversations, turns, on-disk
> attachments, the conversation row, related facts/episodes, and an audit
> re-anchor). `--yes` skips the confirmation prompt.

**SOC 2 controls mapping.** The mapping of these technical controls to the SOC 2
Trust Services Criteria lives in
[`docs/compliance/soc2-controls.md`](compliance/soc2-controls.md). The
machine-readable evidence collector behind `maverick soc2` is
`maverick.soc2.collect_soc2_evidence()`.

---

## Verifying your posture

After enabling anything, run:

```bash
maverick soc2
```

It reports each main control's `status` (`enabled` / `disabled` / `absent` /
`unknown`) and the audit-chain state. The relevant keys:

| `soc2` key | Backing control |
| --- | --- |
| `controls.capability_enforcement` | [Capability enforcement](#capability-enforcement) |
| `controls.tenant_isolation` | [Multi-tenancy](#multi-tenancy-per-user-isolation) |
| `controls.usage_quotas` | [Usage quotas](#usage-quotas) |
| `controls.oidc_auth` | [OIDC SSO](#oidc-sso-authentication) (`absent` if the extra isn't installed) |
| `controls.encryption_at_rest` | [Encryption at rest](#encryption-at-rest) |
| `controls.data_subject_export` | DSAR export (`maverick dsar export`) is implemented |
| `audit_log` | audit-chain verification: `ok` / `unsigned` / `broken` / `empty` / `no_crypto` / `unknown` |
| `audit_signing_key` | whether an audit signing key is present |

Then confirm tamper-evidence end-to-end with `maverick audit verify`.

> Encryption-at-rest and risk-proportional verification have no dedicated
> `soc2` field; confirm those via your config/env (and remember enterprise mode
> implies at-rest).

---

## Recommended enterprise baseline

A sensible default for a deployment handling sensitive data. Adjust the quota
caps, OIDC endpoints, and key source to your environment.

```toml
# ~/.maverick/config.toml

# Umbrella: egress lock + implies capability enforcement + at-rest encryption.
[enterprise]
mode = true

# Least privilege per agent, with attenuating propagation to sub-agents.
# (Redundant under enterprise mode, but explicit is clearer and survives
# turning enterprise mode off.)
[capabilities]
enforce = true

# Isolate each channel user into their own on-disk tenant.
[tenancy]
by_user = true

# Per-principal daily chargeback/rate-limit caps (0 disables a dimension).
[quotas]
enforce = true
max_dollars_per_day = 25.0
max_tokens_per_day = 5000000

# Tamper-evident, Ed25519 Merkle-chained audit log.
[audit]
sign = true

# AES-256-GCM at rest for sensitive local stores (memory store today).
[encryption]
at_rest = true

# SSO for `maverick serve` / dashboard. From the reviewed checkout, install:
# python -m pip install -e './packages/maverick-core[oidc]'
[auth.oidc]
enabled = true
issuer = "https://login.example.com/"
audience = "maverick"
jwks_uri = "https://login.example.com/.well-known/jwks.json"
# algorithms defaults to ["RS256","ES256"]; asymmetric-only is enforced.

# Optional cost/latency optimization (NOT a safety control): skip the LLM
# verifier on clearly low-risk, tool-free answers. Omit for maximal verification.
# [verification]
# risk_proportional = true
```

For production, prefer injecting the at-rest key from your KMS rather than the
generated keyfile:

```bash
export MAVERICK_ENCRYPTION_KEY="$(your-kms-fetch | xxd -p -c 32)"   # 32 bytes, hex
```

Then verify:

```bash
maverick soc2
maverick audit verify
```

**Further reading:** [`docs/compliance/soc2-controls.md`](compliance/soc2-controls.md)
(SOC 2 TSC → control mapping), the enterprise-mode docs under
[`docs/security/`](security/), and [`docs/env-vars.md`](env-vars.md) for the
full environment-variable reference.

Evidence PDF extraction runs in a child process with a 30-second timeout and a
per-process concurrency limit. On supported POSIX systems it also sets CPU,
address-space and file-size limits; their enforcement depends on the operating
system and process privileges. The parent discards stderr and reads at most
16 MiB of child output. Evidence PDF extraction fails closed on non-POSIX systems
or when resource limits cannot be set. These controls do not
isolate filesystem or network access, contain subprocess descendants, or
coordinate limits across workers. Deployments accepting untrusted PDFs still
need operating-system process and network isolation around the service.

Spreadsheet XLSX `read`, `info`, and edits to existing workbooks run archive
validation and workbook parsing in a resource-limited child, with a 30-second
timeout and two concurrent parser slots per service process. Edited workbooks
are limited to 11 MiB and are published atomically only after the worker
succeeds. These operations fail closed where the POSIX resource controls are
unavailable. Recalculation has a separate parsing path and does not share
this isolation; the same filesystem, network, descendant and cross-worker
limits above apply.

Direct flow and workflow tool actions are unavailable when capability
enforcement is enabled, including in enterprise mode, or when they inherit an
active agent grant during tool dispatch. These runners do not carry or enforce
the originating agent's attenuated tool, path and host grant. Direct registry
calls and independently started jobs need their own authorization. Use governed
agent steps when an agent grant must apply.

Teams sends require a fresh human decision in the live registry, including when
the default operation is omitted.
Teams destinations must be configured by the operator in `TEAMS_WEBHOOK_URL`;
the tool refuses caller-supplied webhook URLs.
WebSocket message sending is unavailable until its asynchronous effect can be
bound to a human decision. HTTP requests and WebSocket handshakes can transmit
information to destinations; direct calls to raw tool functions do not pass
through the registry's connector wrapper. Use destination controls and process
isolation where untrusted content can influence outgoing requests.

MCP catalog entries are available for discovery, but installing or probing a
registry-provided server is unavailable, because the complete server
configuration is not authenticated against trusted publisher keys.
Administrators can independently configure servers. Servers already present in
the configuration are not removed; review those configurations and their
destinations.

The interactive browser connects through the same DNS-pinning proxy used by the
consent scanner. It refuses private addresses and permits outbound TCP only on
ports 80 and 443, even when `MAVERICK_FETCH_ALLOW_PRIVATE` is enabled. The proxy
is not an operating-system sandbox; deployments handling untrusted pages should
also restrict the browser process's network access at the operating-system or
container boundary. Long-idle browser connections may be closed by the proxy.

For interactive-browser proxy connections, the enterprise and originating
workspace hostname policies are checked before DNS resolution, including for
WebSocket connections. Chromium is configured to disable HTTP/2 and QUIC to
reduce cross-origin connection coalescing; actual browser enforcement must be
validated for the deployed version. This remains a connection-level check,
and existing connections are not revoked
immediately when a policy changes. Route-level checks and network isolation
remain necessary for stronger enforcement.

Earned-autonomy predictions are recorded by action type, so qualification is
advisory and does not grant consent. Shadow execution still invokes its human
approval callback. Historical unscoped standing-consent records cannot be
attributed reliably to an operator or to earned autonomy and do not grant
authority. Operators must explicitly reauthorize any unscoped standing consent
they still need. Existing scoped records retain their prior authority binding;
clearing prediction qualification does not revoke an explicit consent grant.
