# Safety

Lightwork wraps its agent loop in Agent Shield (`packages/maverick-shield`) at three chokepoints:

1. **Input scan** — every user message goes through `shield.scan_input()` before the orchestrator sees it.
2. **Tool-call scan** — every `tool_use` request goes through `shield.scan_tool_call(name, args)` before the sandbox executes it.
3. **Output scan** — every final answer goes through `shield.scan_output()` before reaching the user.

All three chokepoints additionally run a **decode/defang pre-pass** (`maverick_shield/deobfuscate.py`): base64 / hex / percent-encoded payloads are decoded and Unicode homoglyphs (Cyrillic/Greek lookalikes NFKC leaves alone) plus zero-width/bidi chars are folded, then the detectors re-run over each variant. This can detect some encoded attacks, but detection is not guaranteed. The pre-pass is part of the **built-in** shield (not the optional SDK), is monotonic (it can only turn an allowed scan into a block, never the reverse), and is bounded against decode bombs. Detector failures, including decoding and phishing checks, retain a scan-error result: strict or required policies refuse; optional policies may allow while retaining the error and any existing block. Escape hatch: `MAVERICK_SHIELD_NO_DECODE=1`; disabling a required scan does not establish that the input is safe.

## Profiles

| Profile | Block threshold | Use case |
|---|---|---|
| `strict` | medium | Sensitive data, enterprise, regulated industries |
| `balanced` | high | Recommended default for personal use |
| `permissive` | critical | Research / experimentation |
| `off` | — | Not recommended. Kernel-only mode for debugging. |

Set in `~/.maverick/config.toml`:

```toml
[safety]
profile = "balanced"
block_threshold = "high"
```

## What gets caught

The built-in rules are best-effort pattern matching, not a security boundary.
Shell syntax, alternate executables, and obfuscation can evade individual rules;
use sandbox isolation, least privilege and scoped credentials independently.
Container workspace checks reject common private locations, but cannot detect
every custom secret directory, hard link, nested mount, or filesystem race.
Use a dedicated workspace and OS-level isolation. The local sandbox executes on
the host and does not provide a filesystem isolation boundary.

The **bundled built-in rules** are what run in the standard release: the
full Agent Shield SDK is **not published on PyPI and not vendored
here**, so the public package name is not an installation path and the fallback
is not a fallback in practice — it is the product. The current internal, reproducible
diagnostic is reported with its corpus size and confidence intervals on the
[Shield benchmark page](./security/shield-benchmark.md). Those small,
repository-authored held-out results are regression evidence, not a generalized
public efficacy or marketing claim. The categories below describe the full SDK
ruleset; treat them as a coverage target, not as shipped coverage:

- **Prompt injection** — system prompt overrides, ChatML/LLaMA delimiters, instruction hijacking
- **Role hijacking** — DAN mode, developer mode, persona attacks, jailbreaks
- **Data exfiltration** — prompt extraction, markdown image leaks, DNS tunneling, side-channel encoding
- **Tool abuse** — shell execution attempts, SQL injection, path traversal, sensitive file access
- **Social engineering** — identity concealment, urgency + authority, gaslighting, false pre-approval
- **Obfuscation** — Unicode homoglyphs, zero-width chars, Base64/hex/ROT13/leetspeak
- **Indirect injection** — RAG poisoning, tool output injection, email/document payloads
- **Visual deception** — hidden HTML/CSS content, LaTeX phantom commands
- **Multi-language attacks** — 19 languages including CJK, Arabic, Cyrillic, Hindi
- **AI phishing** — fake AI login, QR phishing, MFA harvesting
- **Sybil attacks** — coordinated fake agents, voting collusion
- **Side channels** — DNS exfiltration, timing-based encoding, beaconing

> **Obfuscation handling does not need the SDK.** The built-in shield's
> decode/defang pre-pass (above) covers base64/hex/percent/homoglyph/zero-width
> evasion on all three surfaces, so an encoded payload is decoded and re-scanned
> against the built-in rules even without the full SDK. The SDK adds breadth
> (ROT13, leetspeak, the wider pattern set); the *decoding* layer is always
> present.

## Checking your posture

`maverick safety` prints the live safety posture — shield status (installed +
backend, or the fail-open fallback), the sandbox backend and whether it is
container-isolated, and the egress policy (locked vs cloud-capable) — so you can
**assert deployment safety in CI** without the dashboard. Use `maverick safety
--json` and gate a pipeline on the fields (e.g. fail the build if
`sandbox.isolated` is false in production, or if `egress.locked` is false on a
regulated deployment). The dashboard's `/safety` page shows the same posture
interactively.

## When the shield is missing

Two layers can be missing, and they degrade differently:

- **Full `agent-shield` SDK absent** (but the `maverick-shield` wrapper present): detection uses the **bundled built-in rules**, the decode/defang pre-pass, and a cheap-probe (regex + Unicode heuristics, optionally ensembled with a trained linear model via `[shield] probe_model`). The startup warning and health check count the actual installed rules rather than an approximate historical count. No SDK efficacy number is attributed to this built-in backend; scans — including obfuscation-decoding — still run. Detector errors follow the selected strict/required or optional failure policy.
- **Shield wrapper absent entirely**: optional kernel-only operation warns and skips unavailable scans. A required deployment refuses external traffic; the health check reports that failure. The core remains importable without the optional wrapper.

The complete Lightwork release cohort includes the `maverick-shield` wrapper.
Core-only source installs must add `packages/maverick-shield` explicitly. The
separate full `agent-shield` SDK is not available from public PyPI; do not use a
public namesake package.

To verify the shield is loaded:

```python
from maverick_shield import Shield
shield = Shield()
print(shield.enabled, shield.backend)  # e.g. True, "builtin"
```

## Privacy posture

- All Agent Shield detection runs **locally**. Nothing is sent to any external service.
- Your model prompts go only to the LLM provider you chose during
  `maverick init`. If you pick Ollama, model inference is local; tools and other
  process code still need deployment egress controls.
- The world model (SQLite) lives in `~/.maverick/world.db`. Inspect, back up, or wipe it freely.

## Enterprise mode (private / sensitive data)

The kernel ships fail-open and cloud-capable by design — right for a personal agent,
wrong the moment it handles PHI / PII / financial / regulated data. **Enterprise mode**
is one switch that flips those application defaults to *fail-closed*. It blocks
non-local governed model dispatch and supported Python HTTP paths; it is not a
packet-level firewall.

```toml
[enterprise]
mode = true
# Optional: extra self-hosted providers to treat as local (e.g. an internal vLLM
# fronted by a generic OpenAI-compatible provider).
local_providers = ["my-internal-vllm"]
```

Or set `MAVERICK_ENTERPRISE=1`, or pick it in `maverick init`. **Off by default.**

The simplest way to select the whole regulated posture is the **named deployment
profile**: `MAVERICK_PROFILE=enterprise` (or `[profile] name = "enterprise"`).
`enterprise` turns on enterprise mode *plus* the deployment-specific secure
defaults below in one knob; `standard` (the default) keeps the zero-config happy
path. Every individual control still has its own explicit override, and a
compliance floor can force any control on — both win over the profile. When the
posture is on:

| Control | Default kernel behavior | Enterprise mode |
|---|---|---|
| **LLM egress** | any configured provider (incl. cloud) sees the prompt | **pinned to local/self-hosted** (`ollama`/`vllm`/`tgi` or an allow-listed endpoint); a cloud-routed call raises `EgressBlocked` **before any prompt is sent**, and the denial is audited |
| **Consent** | `auto-approve` | `ask`: a task someone started in Lightwork's chat waits for a person on the Approvals page (refused if nobody decides in time); other non-interactive runs are *denied* |
| **Capabilities** | opt-in | enforced (least privilege; sub-agents can only narrow their grant) |
| **Sandbox** | `local` host shell (warned) | **container-default** — a `local`/unset backend is upgraded to an available container runtime (docker → podman); if none is installed it fails closed rather than running `shell=True` on the host (`[sandbox] backend` / `require_container`) |
| **Plugins** | in-process, lockfile off | plugin **tool calls** are proxied through the configured isolation backend, and lock enforcement refuses version/content drift once a lockfile exists; plugin import/discovery, factories, channel plugins, skill plugins, and persona plugins still run in-process, so install only trusted plugins (`[plugins] isolation` / `lock_policy`) |

The model egress lock is enforced at the single LLM dispatch chokepoint
(`maverick.llm.LLM.complete`), so it covers every agent, role, and tool-driven
model call that uses that path. Supported `httpx`, `requests`, and `urllib`
calls are checked separately. An explicit env/config setting still wins per
control, but the model egress lock can never be satisfied by a cloud provider.

For a hard no-egress boundary, also use sandbox network isolation and
host/OS/VPC default-deny egress policy. Application interception cannot contain
raw sockets, subprocess network clients, unwrapped libraries, or untrusted code
running in the Lightwork process.

## Compliance posture (`maverick compliance`)

`maverick compliance` reports which GDPR + EU AI Act controls are active for your
deployment, mapped to the article each supports, and flags the opt-in controls that are
still off — with the exact knob to enable each:

| Control | Article(s) | Status / enable with |
|---|---|---|
| AI transparency disclosure | EU AI Act Art. 50 | on by default (channel server) |
| Audit logging (record-keeping) | EU AI Act Art. 12, GDPR Art. 30 | always on |
| Tamper-evident audit | EU AI Act Art. 12 | `[audit] sign = true` |
| Human oversight (consent) | EU AI Act Art. 14 | `MAVERICK_CONSENT_MODE=ask` or enterprise mode |
| Kill switch | EU AI Act Art. 14 | `~/.maverick/HALT` |
| Data-subject access & portability | GDPR Art. 15 & 20 | `maverick export-user` |
| Right to erasure | GDPR Art. 17 | `maverick erase` |
| Storage limitation (retention) | GDPR Art. 5(1)(e) | `[retention]` + `maverick retention enforce` |
| Data-egress control | GDPR Art. 32 / AI Act Art. 15 | `[enterprise] mode = true` |
| Secret/PII redaction in logs | GDPR Art. 25 & 32 | always on |
| Encryption at rest (memory + world-DB content) | GDPR Art. 32 | `[encryption] at_rest = true` (implied by enterprise mode) — see [encryption.md](encryption.md) |
| Log data minimization | GDPR Art. 5(1)(c) | `[privacy] anonymous = true` |

`--format json` emits the same for pipelines/SIEM. **This is control coverage, not a
legal attestation** — full GDPR / EU AI Act compliance also requires a DPA, ROPA (Art. 30
records), a DPIA, AI-Act risk classification, and review by qualified counsel.
