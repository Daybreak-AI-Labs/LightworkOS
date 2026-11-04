# External security audit — readiness & scope

This document is the entry point for an **independent penetration test or
security review** of Lightwork. It defines what to attack, what the existing
controls are and how to verify them, what we already test, and where the
known residual risks are. It is the operational companion to two existing
docs — read those first:

- [`SECURITY.md`](../SECURITY.md) — reporting, coordinated disclosure, and
  the execution-posture caveat (the single most important thing to understand).
- [`threat-model.md`](./threat-model.md) — the STRIDE model, trust
  boundaries, and in-scope/out-of-scope assets.

> **The one-line posture:** by default the agent executes model-generated
> shell commands, and with the default `local` sandbox backend those run on
> the host. The Shield is optional and fails *open*. So a successful prompt
> injection on the default config is host code execution — **the operator
> chooses the blast radius** via the sandbox backend. An auditor should test
> both the hardened (container backend, shield present) and default
> (`local`, no shield) configurations and report findings against each.

---

## 1. Scope

### In scope — priority targets

Ordered roughly by blast radius. Each links to the control that's supposed to
contain it (§3) and the tests that exercise it (§4).

| # | Surface | Entry point | Primary control |
|---|---------|-------------|-----------------|
| 1 | **Sandbox escape / unsandboxed exec** | `sandbox.exec()` → backend | Single chokepoint; container flags (`--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit`, non-root `--user`) |
| 2 | **Prompt injection → tool abuse** | model input, tool output, fetched pages | Agent Shield (`scan_input`/`scan_tool_call`/`scan_output`) + `jailbreak_heuristics` |
| 3 | **SSRF** (cloud-metadata, internal hosts) | `http_fetch`, `web_search`, browser tool | `_ssrf` DNS-rebind-pinned client; private-IP block unless `MAVERICK_FETCH_ALLOW_PRIVATE=1` |
| 4 | **Secret exfiltration** | tool stdout, logs, audit, replay export | `maverick.secrets.scrub` + `maverick.safety.secret_detector`; env scrubbing in `LocalBackend` |
| 5 | **MCP supply chain** | MCP server command / tool descriptions | `pin_sha256` command hash-pinning; tool-description scan at registration |
| 6 | **Channel webhook spoofing / double-spend** | SMS/WhatsApp/Telegram/Bluesky inbound | HMAC verification (fail-closed 401); atomic dedup; per-channel sender allowlist |
| 7 | **Audit-log tampering / repudiation** | `~/.maverick/audit/*.ndjson` | Ed25519 hash-chain (`[audit] sign`, on by default), cross-file anchors, fsync durability |
| 8 | **AuthN/AuthZ bypass** | dashboard, MCP HTTP, A2A | Fail-closed bearer tokens (`MAVERICK_DASHBOARD_TOKEN`, `MAVERICK_MCP_TOKEN`, `MAVERICK_A2A_TOKEN`) |
| 9 | **Plugin / skill code execution** | pip entry-points, installed skills | Default-deny plugin allowlist (`MAVERICK_PLUGINS_ALLOW`); skill-body scan + hash-pin at install |
| 10 | **Resource exhaustion / DoS** | long inputs, runaway loops, fork bombs | `Budget` caps; ReDoS-hardened regexes; sandbox `pids_limit`/timeouts; killswitch `~/.maverick/HALT` |

### Out of scope

See [`threat-model.md` § Out-of-scope](./threat-model.md). In short: local-root
attackers, hardware attacks, compromised provider APIs, and untrusted plugins
the operator chose to allowlist.

---

## 2. Trust boundaries & assets

See [`threat-model.md`](./threat-model.md) for the diagram and the full asset
list (`~/.maverick/.env` keys, session cookies, audit log, world-model DB).
The boundaries an auditor will cross most often: **untrusted text → model**
(injection), **model → sandbox** (exec), and **sandbox/tools → network**
(SSRF / exfil).

---

## 3. Security controls inventory

Each control, where it lives, and how to confirm it's active.

| Control | Location | Verify |
|---------|----------|--------|
| Shell chokepoint (no direct `subprocess` in tools) | `maverick/sandbox/` | CI `lint` job greps `shell=True` outside `sandbox/` and fails the build |
| Container isolation flags | `sandbox/docker.py`, `podman.py` | `test_sandbox_backend_coverage.py`, `test_server_sandbox.py` |
| SSRF DNS-rebind pinning | `maverick/tools/_ssrf.py` | `test_ssrf_guard.py`, `test_ssrf_pinning.py` |
| Secret redaction (+ ReDoS-hardened) | `maverick/secrets.py`, `safety/secret_detector.py` | `test_secrets_scrub_fuzz.py`, `test_replay_export_scrub.py` |
| Env scrubbing for child shells | `sandbox/local.py` `scrub_env()` | `test_tool_subprocess_hardening.py` |
| Shield injection detection | `maverick-shield/` | `test_builtin_rules.py`, `test_cascade.py`, `test_deobfuscation.py`, `test_injection_corpus.py` |
| Audit Ed25519 hash-chain + anchors | `maverick/audit/` | `test_audit_anchor.py`, `test_audit_reanchor.py`, `test_audit_durability.py` |
| Fail-closed auth (dashboard/MCP/A2A) | dashboard `app.py`, `mcp/http_transport.py`, `a2a_tasks.py` | dashboard, MCP and A2A authentication suites (for example `test_http_authorization.py`, `test_a2a_tasks.py`) |
| Webhook HMAC + atomic dedup | `maverick/webhooks.py`, `maverick_channels/` | `test_security_invariants.py`, channel test suites |
| Plugin default-deny | `maverick/plugins.py` | `test_plugins.py`, `test_plugin_permissions.py` |
| Budget caps | `maverick/budget.py` | budget test suites |
| Static-analysis gates (SAST, secrets, CVEs) | `.github/workflows/ci.yml` | see §4 |

---

## 4. Reproducible verification harness

Everything below runs offline and **incurs no model/API cost**. This is the
same battery CI runs on every PR, plus the manual sweeps.

### Setup

```bash
pip install -e ./packages/maverick-core
pip install --no-deps -e ./packages/maverick-shield \
                      -e ./packages/maverick-channels \
                      -e ./packages/maverick-dashboard \
                      -e ./packages/maverick-mcp
pip install pytest pytest-asyncio
```

### Static-analysis gates (blocking in CI)

```bash
# SAST — high-severity, shipped source (tests excluded by design)
python -m bandit -q -r packages apps -lll -ii -s B613 -x '*/tests/*,*/test_*.py'

# Secret scanning — fails on any new secret vs the audited baseline
detect-secrets scan --baseline .secrets.baseline   # then diff hashes; see ci.yml lint job

# Dependency CVEs
pip-audit

# Source-hygiene gates (shell=True confinement, bare tomllib)
ruff check .
```

### Security test suites by area

```bash
cd packages/maverick-core
pytest tests/ -q -k "ssrf"                       # SSRF guard + DNS-rebind pinning
pytest tests/ -q -k "sandbox or subprocess"      # sandbox isolation + env scrub
pytest tests/ -q -k "audit"                      # Ed25519 chain, anchors, durability
pytest tests/ -q -k "scrub or redact or secret"  # secret redaction + ReDoS fuzz
pytest tests/ -q -k "inject or security or hardening or tier0"  # injection + invariants
cd ../maverick-shield && pytest tests/ -q        # shield detection + injection corpus
```

### ReDoS sweep (regex DoS)

The redactors and detection rules run on attacker-influenced text, so every
regex over untrusted input must be sub-quadratic. To run the dynamic sweep,
collect every
compiled `re.Pattern` from `maverick.safety`, `maverick_shield`,
and `maverick.tools`, then time `pattern.search`
on long single-character runs (`"a"`, `"A"`, `"\n"`, `"\t"`, `" "`, …) at N
and 2N — a time ratio near 4× on doubling signals O(N²). `scrub()` /
`redact()` should stay linear (~130 ms on a 500 KB run). See
`test_secrets_scrub_fuzz.py::test_secret_redactors_do_not_redos_on_long_runs`
for the committed regression form.

---

## 5. Known residual risks

We track these openly rather than hide them. None is a Critical/RCE on a
hardened config; an auditor should still try to escalate each.

- **Default `local` backend = host exec.** By design (see `SECURITY.md`).
  Injection on the default config reaches the host. Mitigation is operator
  choice of a container backend; the consumer wizard fails closed.
- **Shield coverage remains bounded.** The shipped `maverick-shield` package
  uses its bundled rules when the separate Agent Shield SDK is absent. Health
  and startup output count the actual installed patterns. Decode and phishing
  detector failures retain scan-error evidence: strict/required policies refuse;
  optional policies may allow while preserving any existing block. The kernel
  remains importable without the wrapper, but a required deployment refuses
  external traffic. The repository corpus records supported cases and gaps;
  rule counts do not establish general detection accuracy.
- **`jailbreak_heuristics` precision.** The weighted scorer over-flags some
  benign instruction-shaped text (e.g. "ignore the instructions in the old
  README"); a false-positive-tuning pass is outstanding.
- **Audit tamper-evidence depends on key custody.** Signing is on by default
  (off with `[audit] sign = false` or `MAVERICK_SECURE_DEFAULT=0`), but the
  default key is held on the same host; third-party attribution requires an
  externally-held pubkey.
- **Plugin permissions are enforced by default.** A plugin requesting an
  ungranted permission is skipped (not loaded) unless `enforce_permissions =
  false` downgrades it to advisory; the default-deny load allowlist is a second,
  independent gate. These checks do not confine granted plugin code; import
  and factory execution remain in-process and require trusted plugins.

---

## 6. Reporting

Use the process in [`SECURITY.md`](../SECURITY.md): GitHub Security
Advisories (preferred) or the security email, **not** a public issue.
Coordinated-disclosure window is 90 days. Please report against the config
you tested (hardened vs. default) and include the `maverick version` output.
```
