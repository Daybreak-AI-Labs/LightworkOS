# Single-client deployment — one Lightwork instance per client

**Deployment model: one Lightwork instance per client.** This runbook uses
separate instances, hosts and storage.
Application authorization and workspace isolation remain required within each
instance. Client binding does not provision or prove physical isolation.

On top of that physical isolation, every instance is **bound to exactly one
client**. Tenant-aware stores use that binding as their default scope. Global
configuration, account administration and some keys live outside the tenant
root; include them in installation recovery and offboarding planning.

This document covers (1) the isolation guarantee, (2) the controls that support
it, and (3) the per-client deployment runbook.

---

## 1. The isolation guarantee

| Layer | How a single client is isolated |
|---|---|
| **Deployment** | One Lightwork process/host/volume per client. Two clients never share a host. |
| **Client binding** | `[client] id` / `MAVERICK_CLIENT_ID` binds the instance. `[client] enforce = true` (auto-on under enterprise mode) makes serving **fail closed** if unbound. |
| **Tenant floor** (`maverick.client` + `maverick.paths`) | The client id supplies the default tenant for `data_dir()`, including the world DB, audit and memory. Explicit workspace scopes remain distinct. Global administration/configuration and operator-configured external stores require separate inventory. |
| **At-rest encryption** | Per-tenant DEK wrapped by a KEK, with the client id bound into the AEAD context (`tenant/kms.py`), so a key cannot decrypt another scope's data. Enable with `[encryption] at_rest = true` + `per_tenant = true`. |
| **Audit** | Signed, hash-chained, per-client audit dir + signing key; `maverick doctor` shows the bound client + data root. |

Client binding provides the tenant floor, dashboard routing through the client
world DB, fail-closed `serve()` guards, a `doctor` check, and a config knob with
a wizard step.

---

## 2. Supporting controls

### Client binding and scoped state
- `[client] id` + `enforce`; client id as tenant floor; dashboard world DB
  scoped to the client; fail-closed guards on the gRPC/federation servers;
  `doctor` binding check; wizard step.

### Transport encryption (TLS/mTLS)
- `maverick/grpc_tls.py` builds gRPC server + channel credentials from config;
  the gRPC goal API and federation servers bind TLS via `bind_port()` and the
  federation client dials `secure_channel`. `[grpc]`/`[federation]` `tls`,
  `tls_cert`, `tls_key`, `tls_client_ca` (mTLS), and client-side `tls_ca` /
  `tls_client_cert` / `tls_client_key`.
- **Fail-closed**: when the deployment is client-bound/enterprise (or
  `tls_required = true`), a server that can't build credentials refuses to
  start and the federation client refuses to dial in the clear — sensitive data
  never silently falls back to plaintext.
- Still document TLS termination for the dashboard + MCP HTTP surfaces (reverse
  proxy or native). The federation shared token never crosses in plaintext.

### Trust-plane and key administration (`maverick trust` CLI)
- `maverick trust status / list / show / add / rm / revoke / unrevoke / verify`
  and `maverick trust pubkey` (print this deployment's pinned key to hand to
  peers). Write-ops manage a per-client JSON overlay (`agent_trust.json`, under
  the client's data dir) that `load_registry` merges over the hand-edited
  `[agent_trust] agents` — so peers/keys are managed without editing TOML.
- `revoke` flips `revoked` (denied immediately via `is_active`); rotation is
  `add --pubkey <new>` (overlay overrides config), with `expires_at` /
  `not_before` available for zero-downtime overlap.
- The dashboard has no view of the trust registry; use the CLI.

### Backup, restore and failover (single node)
- `maverick backup create` snapshots the **client-scoped data root** — world DB
  (via the SQLite **online backup API**, consistent under WAL), signed **audit
  chain + public verification material**, memory, fleet, and the managed trust registry — into
  a portable `.tgz` with a HMAC-authenticated manifest (client id, time, schema,
  exact size and SHA-256 per file). Set a separately custodied, 32-byte
  `MAVERICK_BACKUP_SIGNING_KEY` on both the active and standby nodes; the key is
  never included in the archive. Raw encryption and audit signing `.key` files
  are excluded by default and need separate custody and restoration.
  `maverick backup info` authenticates and
  inspects it; `maverick backup restore` authenticates, verifies, and applies it.
- **Fail-closed restore**: refuses an unsigned, forged, oversized, structurally
  unsafe, wrong-client, or forward-schema archive. `--force` does not bypass
  forward-schema checks, manifest authentication or archive validation. Restore uses private
  staging plus a durable transaction journal and rolls every file and SQLite
  sidecar back if publication is interrupted.
- **Warm standby**: cron `backup create`, ship the `.tgz` offsite + to a standby
  host, `backup restore` + start on failover (see runbook §3.6).

### Security hardening
- **Mandatory shield**: `maverick/shield_policy.py` — `[safety] require_shield`
  / `MAVERICK_REQUIRE_SHIELD` / enterprise mode make the shield required;
  `scan_block` fails toward the gate (a *missing* shield blocks external traffic
  when required, a scan error always blocks). Federation inbound + A2A route
  through it; `doctor` goes RED when the shield is required but absent.
- **Loopback-trust disabled** when client-bound/enterprise — the dashboard's
  no-token mode is refused; a token (or OIDC) is required.
- **Secrets hygiene**: `doctor` warns when `config.toml` is group/world-
  accessible; use `${ENV}` refs for tokens (the systemd unit injects them).
- **BYOK**: real cloud-KMS backends (`maverick/kms_backends.py`) behind the
  `tenant/kms.py` `KMS` Protocol — AWS KMS, GCP KMS, Vault transit, and Azure
  Key Vault / Managed HSM (`azure-kms` extra). `[kms] provider =
  aws|gcp|vault|azure` keeps the KEK in the client's own HSM (the tenant context
  binds as the KMS EncryptionContext / AAD; Azure binds it locally, since its RSA
  wrap takes no context, and the vault signs each envelope so a holder of the
  public key alone cannot forge one. An Azure key must allow the wrapKey, unwrapKey,
  sign and verify operations; the identity needs wrapKey, unwrapKey and sign, plus
  verify or get); a missing SDK or unknown provider fails closed (never
  downgrades to in-process keys). Env-injected keys (`MAVERICK_ENCRYPTION_KEY` /
  `MAVERICK_KMS_KEK`) remain for self-managed.

### Packaging and headless provisioning (VM and image)
- **Build-time gRPC stubs**: `maverick gen-stubs` pre-generates every
  `*_pb2.py`; set `MAVERICK_NO_RUNTIME_PROTOC=1` in the runtime so a missing stub
  **fails fast** instead of invoking `protoc` (immutable/read-only FS; SBOM).
  Both loaders honour the guard.
- **Declarative install**: `maverick init --from-file client.toml` validates
  and installs the config (0600) with no prompts — bake it into the image/VM.
- Hardened `systemd` unit + install script and baked image: see the runbook (the
  image just runs `gen-stubs` + `init --from-file` at build).

### Compliance and data-subject operations
- **Per-client export + erasure**: `maverick client export` (full data
  portability / DSAR — a consistent snapshot of the client's data root) and
  `maverick client erase --confirm [--keep-audit]` (right-to-erasure /
  offboarding). Erase refuses unless a client is bound and targets that client's
  tenant root. It does not erase global account/configuration records, separate
  workspaces, workspace files outside that root, offsite archives, or remote
  Postgres/Qdrant/Redis data. Inventory and handle those locations separately;
  keeping audit records also retains the selected audit data. Stop all writers
  before erasing. The signed local activity receipt records intent, inventory
  and whether deletion completed; a failed or partial erase is not success.
- Residual-plaintext (`[privacy] anonymous = true`) and `[audit] retention`
  remain config knobs as before.
- **Certifications** are organizational, not code: SOC 2 Type II, a HIPAA BAA
  and a third-party penetration test are engagements for the operating
  organization. The control machinery they rely on (signed audit, compliance
  profiles, egress lock, erasure) is in place.

---

## 3. Per-client deployment runbook (VM / systemd)

> One VM (or image) per client. Nothing on it is shared with another client.

### 3.1 Provision

```bash
# 1. Dedicated host, dedicated user, locked-down home.
useradd -r -m -d /var/lib/maverick maverick
install -d -o maverick -g maverick -m 0700 /var/lib/maverick/.maverick

# 2. Install (per-package wheels; pre-built, no build-time network).
python3 -m pip install --no-index --find-links /opt/maverick/wheels \
  'maverick-agent[release-runtime,grpc]' maverick-shield maverick-channels \
  maverick-evolve maverick-dashboard maverick-mcp-server \
  maverick-knowledge maverick-installer

# 3. Pre-generate gRPC stubs (so the runtime never compiles on a read-only FS),
#    then provision config non-interactively.
maverick gen-stubs
sudo -u maverick env MAVERICK_HOME=/var/lib/maverick/.maverick \
  maverick init --from-file /opt/maverick/<client>.toml
```

Set `MAVERICK_NO_RUNTIME_PROTOC=1` in the service unit so a missing stub fails
fast at boot rather than invoking `protoc` at request time.
Use one reviewed, complete wheelhouse with the eight versions from
`release-cohort.toml` and their dependencies. Include the `oidc`, `postgres`,
`saml` or other provider extras if that deployment uses them. The optional
external Agent Shield SDK has its own supply and acceptance requirements;
installing the in-repo `maverick-shield` distribution does not qualify that SDK.

### 3.2 Bind the client (the critical step)

`/var/lib/maverick/.maverick/config.toml`:

```toml
[client]
id = "acme-corp"          # this deployment serves ONLY acme-corp.
                          # MUST be lowercase letters/digits/._- (it is a
                          # directory name; a case-insensitive filesystem would
                          # otherwise collide "Acme" with "acme"). A non-canonical
                          # id fails closed at startup rather than serving unbound.
enforce = true            # refuse to start unbound — data can't hit the shared root

[enterprise]
mode = true               # egress lock + fail-closed consent + capabilities + mandatory shield

[encryption]
at_rest = true
per_tenant = true         # DEK bound to the client id

# BYOK: keep the KEK in the client's HSM (omit for the in-process/env key).
[kms]
provider = "aws"          # aws | gcp | vault | azure | local
key_id   = "arn:aws:kms:us-east-1:123:key/<uuid>"   # or GCP resource name / Vault key / Azure key URL
region   = "us-east-1"    # AWS; Vault uses address + VAULT_TOKEN; Azure uses DefaultAzureCredential

[audit]
sign = true               # tamper-evident, per-client signed chain

# Transport encryption. Required automatically under client binding /
# enterprise mode — the gRPC + federation servers refuse to start in plaintext.
[grpc]
tls = true
tls_cert = "/etc/maverick/tls/server.crt"
tls_key  = "/etc/maverick/tls/server.key"
tls_client_ca = "/etc/maverick/tls/clients-ca.crt"   # optional: enables mTLS

[federation]
tls = true
tls_cert = "/etc/maverick/tls/server.crt"
tls_key  = "/etc/maverick/tls/server.key"
tls_client_ca = "/etc/maverick/tls/peers-ca.crt"     # mTLS: require peer certs
tls_ca = "/etc/maverick/tls/peers-ca.crt"            # verify peers we dial
tls_client_cert = "/etc/maverick/tls/client.crt"     # our cert when dialing
tls_client_key  = "/etc/maverick/tls/client.key"
```

### 3.3 systemd unit

`/etc/systemd/system/maverick-dashboard.service`:

```ini
[Unit]
Description=Lightwork (client: acme-corp)
After=network-online.target

[Service]
User=maverick
Environment=MAVERICK_HOME=/var/lib/maverick/.maverick
# Also set the client floor in the service environment.
Environment=MAVERICK_CLIENT_ID=acme-corp
Environment=MAVERICK_CLIENT_ENFORCE=1
EnvironmentFile=/etc/maverick/dashboard.env
Environment=MAVERICK_NO_RUNTIME_PROTOC=1
ExecStart=/usr/local/bin/maverick dashboard --host 127.0.0.1 --port 8770
# TLS terminated by the front proxy (gRPC/federation use native TLS)
Restart=on-failure
# Hardening
ProtectSystem=strict
ReadWritePaths=/var/lib/maverick/.maverick
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Provision `/etc/maverick/dashboard.env` through the host's secret manager,
owned by root with mode `0600`, containing `MAVERICK_DASHBOARD_TOKEN=<secret>`.
Systemd reads the file and supplies the value to the service. An environment
assignment to `%d/dashboard_token` supplies a pathname, not the credential's
contents; do not use that pathname as the authentication token.

### 3.4 Verify the binding (gate before go-live)

```bash
sudo -u maverick MAVERICK_HOME=/var/lib/maverick/.maverick \
  MAVERICK_CLIENT_ID=acme-corp maverick doctor
```

`doctor` MUST show:

```
✓ client   (bound to 'acme-corp' — data root /var/lib/maverick/.maverick/tenants/acme-corp)
```

If it shows `✗ client  (client binding ENFORCED but no client id set …)`, the
deployment will refuse to serve — fix the binding before exposing it. The whole
default tenant data tree should resolve under `…/tenants/acme-corp/`.
Inventory explicit workspaces, shared administration/configuration, separately
custodied keys and configured external stores as additional recovery scopes.

### 3.5 Cloud marketplace image

Bake the above: pinned wheels, pre-generated stubs, the systemd unit,
and a first-boot hook that requires `MAVERICK_CLIENT_ID` (and rejects boot
without it). One image template → one instance per client at launch.

### 3.6 Backup & warm-standby failover

```bash
# Provision this once through the host secret manager; use the same secret on
# the active and standby nodes. Example generation: `openssl rand -hex 32`.
export MAVERICK_BACKUP_SIGNING_KEY='<64 hex characters from secret manager>'

# Nightly consistent backup, shipped offsite + to the standby host.
sudo -u maverick MAVERICK_HOME=/var/lib/maverick/.maverick \
  MAVERICK_CLIENT_ID=acme-corp \
  MAVERICK_BACKUP_SIGNING_KEY="$MAVERICK_BACKUP_SIGNING_KEY" \
  maverick backup create --out /backups/acme.tgz
aws s3 cp /backups/acme.tgz s3://acme-maverick-dr/   # or rsync to standby

# On the STANDBY, use the same service identity, home, binding and retained key.
# Stop its dashboard before restoring state; do not serve two active instances.
systemctl stop maverick-dashboard
sudo -u maverick env MAVERICK_HOME=/var/lib/maverick/.maverick \
  MAVERICK_CLIENT_ID=acme-corp \
  MAVERICK_BACKUP_SIGNING_KEY="$MAVERICK_BACKUP_SIGNING_KEY" \
  maverick backup info /backups/acme.tgz
sudo -u maverick env MAVERICK_HOME=/var/lib/maverick/.maverick \
  MAVERICK_CLIENT_ID=acme-corp \
  MAVERICK_BACKUP_SIGNING_KEY="$MAVERICK_BACKUP_SIGNING_KEY" \
  maverick backup restore /backups/acme.tgz
systemctl start maverick-dashboard
```

This archive covers the bound tenant's local data. Before starting the standby,
restore its separately retained encryption/audit signing keys and installation
configuration, and recover external databases through their own backup system.
Test reading encrypted client records on the standby; archive authentication
alone cannot demonstrate decryption or complete application recovery.

The restore first authenticates the manifest with the standby's
`MAVERICK_BACKUP_SIGNING_KEY`, then refuses a backup whose `client_id` differs
from the standby's binding. The CLI has no unsigned-restore bypass.

### 3.7 Offboard a client (right-to-erasure)

```bash
# Run these as the maverick service user with the same MAVERICK_HOME,
# MAVERICK_CLIENT_ID and required retained keys as the service/backup commands.
# Optional: hand the client their data first (portability / DSAR).
maverick client export --out /secure/acme-final-export.tgz
# Stop the dashboard and every worker first. Run the erase only while the
# client data root is quiesced; open SQLite handles can block deletion.
# Remove this client's local data except the retained audit record:
maverick client erase --confirm --keep-audit
```

Erase refuses unless a client is bound, so it can only ever target
`tenants/<client>/` — never the shared root. Preserve the signed activity
receipt and inspect its completion status. Separately inventory and remove
external stores and exported copies before decommissioning the VM/instance.

---

## 4. Pre-go-live checklist (per client)

- [ ] `[client] id` set and `enforce = true`; `doctor` shows the bound client.
- [ ] Default tenant paths resolve correctly; additional workspaces, global administration, keys and external stores are inventoried.
- [ ] TLS on every listener; no plaintext gRPC/federation.
- [ ] Tokens injected from secrets (not literal in `config.toml`); config is `0600`.
- [ ] `[encryption] at_rest + per_tenant`, `[audit] sign` on; `maverick audit verify` passes.
- [ ] Backup job runs; a separate-host restore reads encrypted records and restores configuration plus any external stores.
- [ ] Trust registry populated; `doctor` not RED on an empty engaged registry.
- [ ] Shield present and mandatory.
