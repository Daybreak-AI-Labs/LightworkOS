# Lightwork — Security & Compliance Overview

Lightwork is a **governed, self-hostable AI agent runtime** built for private
and regulated data (PHI / PCI / PII / EU / classified). This page summarizes
the security architecture for technical and security reviewers. It describes
the product as built; capabilities are cited to the modules that enforce them.

## Application egress controls (Enterprise mode)

The kernel ships fail-open and cloud-capable by design — the right default for a
personal agent, the wrong one for sensitive data. **Enterprise mode is one opt-in
switch** (`MAVERICK_ENTERPRISE=1`, `[enterprise] mode = true`, or the installer) —
or, simplest, the named **deployment profile** `MAVERICK_PROFILE=enterprise`
(`maverick/profile.py`), which composes enterprise mode *and* the
deployment-specific secure defaults below in one knob — that flips the defaults
fail-closed (`maverick/enterprise.py`):

- **Egress lock.** Every governed LLM call is pinned to a local / self-hosted provider
  (Ollama / vLLM / TGI, or an allow-listed endpoint). A call routed to a cloud
  provider raises `EgressBlocked` **before any prompt is sent**, and the denial is
  audited. Supported `httpx`, `requests`, and `urllib` paths are also checked
  per request, including each HTTPX redirect hop.
- **Consent fail-closed.** Destructive-action consent defaults to *ask* (and
  therefore *deny* in non-interactive contexts) instead of auto-approve.
- **Capabilities enforced.** Per-agent capability scoping with attenuating
  propagation — a sub-agent can never exceed its parent's grant.
- **Encryption at rest.** The world model and cross-session memory are sealed with
  AES-256-GCM (`crypto_at_rest.py`); `maverick encryption migrate` seals
  pre-existing plaintext.
- **Container-default sandbox.** A `local`/unset sandbox backend is upgraded to an
  available container runtime (docker → podman) instead of running `shell=True` on
  the host; if no container runtime is installed it fails closed rather than
  running agent-generated commands unsandboxed (`sandbox/__init__.py`).
- **Plugin supply-chain checks.** Plugin tool calls can be proxied through the
  configured isolation backend, and plugin distributions can be checked against
  a **content-hash lockfile** when lock enforcement is enabled. Plugin discovery,
  imports, tool factories, channel plugins, skill plugins, and persona plugins
  still run in the Lightwork process; install only trusted plugins, and generate a
  lockfile before relying on drift enforcement (`plugins.py`,
  `plugin_isolation.py`, `plugin_lock.py`).

> **Application control, not a packet firewall.** Enterprise mode protects the
> governed model-dispatch path and supported Python HTTP clients. It cannot
> prevent a raw socket, a subprocess such as `curl`, or an unwrapped network
> library from sending traffic. A deployment that requires a hard no-egress
> boundary must additionally enforce sandbox network isolation and
> host/OS/VPC default-deny egress policy. Treat untrusted in-process plugins as
> able to bypass application-layer controls.

**Prove it, don't trust the flag.** `maverick enterprise verify`
(`deployment.py`) *actively exercises* the application controls — it confirms
the governed LLM path refuses a cloud provider and that at-rest sealing
round-trips on the host. It does not test host firewall, VPC, or packet-level
sandbox policy.

**Governance invariants proven across the whole roster.** Beyond per-deployment checks, a roster-wide invariant test suite verifies six safety invariants across **all 2,031 built-in specialist packs**, each fault-injected with a non-vacuous control: (1) **tool-reachability** — no drafting/non-builder agent can reach a state-mutating tool; (2) **autonomy dial** — an onboarding agent is never autonomous and a high-risk action is never autonomous even when graduated; (3) **capability attenuation** — a spawned child can never exceed its parent's grant; (4) **compartment isolation** — a quarantine seal never bleeds across compartments/suites; (5) **hard refusals** — the universal refusal floor is unstrippable; (6) **budget caps** — no cap is ever silently exceeded. Hostile-argument fuzzing covers all connectors and tools.

## Identity & access

- **SSO via OIDC.** Inbound requests are authenticated by verifying an OIDC ID
  token (`oidc.py`, PyJWT); when enabled, the channel-provided identity is never
  trusted and verification is fail-closed.
- **Reverse-proxy identity.** A trusted forwarded-identity header is supported for
  gateway deployments (`proxy_auth.py`) — an unverifiable source can't assert
  identity (fail-closed).
- **RBAC + capability tokens.** Role-based access control over capabilities, plus
  unforgeable, attenuating capability grants (`capability.py`).
- **Per-tool ACLs & consent.** Tool-level allow-lists and a consent primitive gate
  risky actions (`safety/tool_acl.py`, `safety/consent.py`).
- **Per-user tenancy.** Each principal's goals, cross-session memory, and audit
  land in an isolated, co-located per-tenant store (`tenant_scope` in
  `server.py`); single-tenant is the default and is unchanged. The isolation
  mechanism differs by store and is test-backed, not merely documented:
  - **World model & governed records (shared Postgres).** Database-enforced
    Row-Level Security. The runtime binds the active tenant on every
    transaction via the transaction-local `maverick.tenant` GUC
    (`set_config(..., is_local=true)` in `PostgresWorldModel._tx` and
    `PostgresGovernedRecordBackend._transaction`), and the tables carry a
    `FORCE`d fail-closed policy (`tenant_id = nullif(current_setting(
    'maverick.tenant', true), '')`). An unset/empty GUC matches no rows.
    Proven at the DB layer through a non-superuser NOBYPASSRLS role in
    `test_postgres_world.py::test_rls_enforces_tenant_isolation_at_db_level`
    and `test_governed_records_rls_pg.py`. On SQLite the world model is a
    distinct per-tenant `world.db` file instead.
  - **Knowledge, skills, self-harness lessons (files / per-tenant SQLite).**
    Directory/namespace-scoped: each resolves under the tenant's
    `data_dir`, so two tenants never share a store. The pgvector knowledge
    store keys rows by collection namespace.
  - **Shared learning store (`[self_harness] store = "world"` on Postgres).**
    The fleet-learning tables (`harness_*`) share a single DSN, so each row
    carries a `tenant_id` and every read/write scopes to the active tenant
    (`learning_store.py`) — a fleet of hosts learns as one *within* a tenant,
    never across tenants (`test_learning_store_tenant_isolation.py`).

## Audit & evidence

- **Tamper-evident audit log.** Append-only, Ed25519 hash-chained, with
  anti-deletion anchors; `maverick audit verify` validates the chain
  (`audit/signing.py`).
- **SIEM export.** `maverick audit export` emits date-windowed events for SIEM
  ingestion.
- **Data subject rights.** DSAR export (`dsar.py`) and data-retention enforcement
  (`audit/retention.py`, GDPR Art. 5(1)(e) storage limitation).
- **Supply chain.** A CycloneDX SBOM is produced in CI; dependencies are scanned
  (`pip-audit`). Plugin tool calls can be isolation-proxied and plugin distributions can be
  lockfile-checked under the enterprise profile, but plugin import/discovery code
  still runs in-process; treat plugins as trusted code (see the data-boundary
  guarantees above).

## Compliance posture

- **Regulated-deployment profile.** One reference profile
  (`REGULATED_PROFILE` in `deployment.py`) composes Enterprise mode + audit
  signing + retention; `maverick compliance --strict` gates on it.
- **Framework mapping.** `maverick compliance` maps configured controls to
  regulation articles; an EU AI Act risk-classification helper ships (`ai_act.py`).
- **SOC 2 readiness.** A readiness probe (`soc2.py`) checks the load-bearing
  controls (encryption-at-rest, capability enforcement, audit signing). *This is
  self-assessment tooling, not a certification.*

## Reference architecture (self-host / air-gap)

```
        ┌─────────────────────── your boundary ───────────────────────┐
  user →│  channel / OIDC ──→ maverick serve ──→ orchestrator + swarm  │
        │                          │                  │                │
        │                    tenant_scope        sandbox (local/       │
        │                    per-tenant world.db  docker/k8s)          │
        │                          │                  │                │
        │   self-hosted LLM ←──────┘   signed audit ──┴─→ SIEM export  │
        │   (Ollama/vLLM/TGI)          (encrypted at rest)             │
        └──────────────────────────────────────────────────────────────┘
   App egress lock + deployment network policy. No product telemetry.
```

Deployable on a laptop, a VPC, Kubernetes, or a disconnected/air-gapped network.
No hyperscaler dependency; Lightwork emits no telemetry of its own. Use an
air gap or OS/VPC deny policy when network-level non-egress is required.

## SSO and provisioning status

OIDC SSO, **SAML SSO** (via pysaml2, off by default), and **SCIM 2.0**
provisioning + deprovisioning all ship; SCIM deprovision force-revokes live
sessions, including pairwise-`sub` IdPs (Entra) via a login-time subject directory.
SAML and SCIM are tested against the protocol test suites in this repository and
are not certified against a live identity provider.

## Sign-in security: second factor, step-up, sessions, allowed addresses

All four are off by default and configured under `[auth]` in `config.toml`,
by the installer's **Sign-in security** step, or in Settings > All settings >
People & access > Sign-in security. None of them applies without a named
sign-in: the auth-off local mode and the static server token have no principal
to hold a second factor.

- **Require a second factor** (`[auth.mfa] require`, `MAVERICK_MFA_REQUIRE`).
  An OIDC session is issued only when the ID token's `amr` (RFC 8176) names a
  second-factor method (`mfa`, `mca`, `otp`, `hwk`, `swk`, `fido`, `pop`, `sms`,
  `tel`, `sc` by default; `amr_values` extends it) or its `acr` is one of
  `acr_values`, which are also sent as `acr_values` on the authorization
  request. A SAML session is issued only when the assertion's
  `AuthnContextClassRef` is one of `saml_authn_contexts` (Microsoft
  `multipleauthn`, the OASIS two-factor classes and Okta's `2fa:any` by
  default), and the AuthnRequest asks for them. A refused sign-in shows one
  sentence: "Your sign-in didn't include a second factor. Sign in again with
  your authenticator." Sessions record whether a second factor was proved and
  when. Reverse-proxy identities and passphrase (invitation) sessions carry no
  such proof, so with the requirement on they are refused. Turning the
  requirement on from a session without a second factor is refused, so an
  administrator cannot lock themselves out.
- **Step-up** (`[auth.mfa] step_up_minutes`, default 15). While the
  requirement is on, the sensitive operations listed in
  `maverick_dashboard/step_up.py` (changing or removing a role, removing a
  spending limit, turning off the emergency stop, rotating signing or
  workspace keys, changing sign-in/administrator/key-service settings,
  deleting a workspace, signing others out) need a second factor no older than
  that. Otherwise the API answers 403 with a plain sentence and a
  `reauthenticate` link (`/auth/login?fresh=1`, which sends `prompt=login`, or
  `/saml/login?fresh=1`, which sends `ForceAuthn`, so the provider asks again),
  and the page shows a "Sign in again" button. The second factor is dated by
  the provider's `auth_time` or `AuthnInstant`; a step-up sign-in that cannot
  show a recent one does not count, so a provider that ignores the request and
  reuses its own session gets a refusal, not a new session.
- **Sessions** (`/settings/sessions`, `/api/v1/sessions`). Every browser
  session is recorded server-side (`dashboard-sessions.sqlite3`: person,
  sign-in method, second factor, issued, last seen, address, device summary)
  and kept `[auth.sessions] retention_days` after it ends. People see and end
  their own sessions; administrators anyone's. "Sign out this device" ends one
  session; "Sign out everywhere" ends every recorded session and bumps the
  person's revocation epoch, which also ends untracked sessions and API bearers
  issued before now. Every revoke writes a control-plane audit row.
- **Allowed addresses** (`[auth.ip_allowlist] cidrs`, `MAVERICK_IP_ALLOWLIST`;
  `workspace_cidrs` per workspace, which a workspace's own `config.toml` can
  narrow). The installation list is enforced before sign-in for every request
  except the liveness/readiness probes; the workspace list once the caller's
  workspace is pinned. The client address is the socket peer; `X-Forwarded-For`
  counts only from a peer pinned in `[auth.proxy] trusted_proxies`, walked from
  the right past trusted hops. A blocked address sees one sentence. Saving a
  list that does not contain the address the request came from is refused, so
  an administrator cannot lock themselves out; entries that do not parse are
  refused rather than skipped. Changes are audited like every other setting.

> Licensing: Lightwork is licensed under the Apache License 2.0
> ([`LICENSE`](https://daybreak-ai-labs.github.io/LightworkOS/license/)).
