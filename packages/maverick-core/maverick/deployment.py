"""Regulated-deployment profile + a live verifier for the data-boundary guarantees.

Enterprise mode, at-rest encryption, audit signing and retention each turn on a
piece of the "safe to run on private / sensitive data" posture. This module ties
them into ONE named profile (:data:`REGULATED_PROFILE`) and a verifier that
*actively exercises* the load-bearing guarantees -- it does not merely read the
config flags the way ``maverick compliance`` does. It proves the egress lock
refuses a cloud provider and that at-rest sealing actually round-trips on this
box, which is the difference between "the flag is on" and "the boundary holds"
(a flag can read ``active`` while the ``cryptography`` backend or the key is in
fact missing, which would only surface as a fail-closed error at write time).

Surfaced as ``maverick enterprise verify``.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass

# The one reference profile: the config.toml half of a regulated deployment.
# Enterprise mode alone covers egress lock + fail-closed consent + capability
# enforcement + at-rest encryption; signing and retention are the two extra
# knobs. These settings are NOT enough for the verifier below to pass. It also
# needs:
#   * an off-host audit signing key (MAVERICK_AUDIT_SIGNING_KEY, or a
#     KMS-wrapped key): enterprise mode refuses a key generated on the host;
#   * an isolated sandbox, e.g. ``[sandbox] backend = "docker"`` (the default
#     ``local`` runs agent code on the host);
#   * maverick-shield installed and enforcing.
# Kept here so docs/regulated-deployment.md and the code never drift.
REGULATED_PROFILE = """\
[enterprise]
mode = true            # egress lock + fail-closed consent + capabilities + at-rest encryption

[audit]
sign = true            # Ed25519 tamper-evident audit chain

[retention]
audit_days = 365       # storage limitation (GDPR Art. 5(1)(e)) -- tune to your policy
episodes_days = 90
events_days = 365
messages_days = 365
"""

# Representative providers used to prove the egress policy without contacting
# either: a known cloud provider must be refused, a self-hosted one admitted.
_CLOUD_PROBE = "anthropic"
_LOCAL_PROBE = "ollama"
_SEAL_PROBE = "maverick-at-rest-probe"

_ISOLATED_SANDBOX_BACKENDS = {
    "devcontainer",
    "docker",
    "firecracker",
    "gvisor",
    "kubernetes",
    "modal",
    "podman",
}


def _sandbox_isolated(backend: str) -> bool:
    """Return whether ``backend`` names a supported isolated sandbox backend."""
    return backend in _ISOLATED_SANDBOX_BACKENDS or backend.startswith("ep:")


def _sandbox_isolation_detail(backend: str, sandboxed: bool) -> str:
    if sandboxed:
        return f"backend = {backend}"
    if backend in ("", "local"):
        return (
            "set [sandbox] backend = \"docker\" (or podman/gvisor/kubernetes/"
            "firecracker); 'local' runs agent code on the host unsandboxed"
        )
    known = ", ".join(sorted(_ISOLATED_SANDBOX_BACKENDS))
    return (
        f"unsupported [sandbox] backend = {backend!r}; use one of: {known}, "
        "or an ep:<name> Sandbox SDK backend"
    )


@dataclass(frozen=True)
class GuaranteeCheck:
    """One data-boundary guarantee and whether it currently holds."""

    name: str
    passed: bool
    detail: str


def verify_deployment() -> list[GuaranteeCheck]:
    """Actively verify the regulated-deployment guarantees on this box.

    Unlike :func:`maverick.compliance.compliance_report` (which maps configured
    controls to regulation articles), this exercises the load-bearing ones so a
    pass means the boundary actually holds, not just that a flag is set.
    """
    checks: list[GuaranteeCheck] = []

    # 1. Egress lock -- prove the policy refuses a cloud provider and admits a
    #    self-hosted one, using the same predicates the LLM chokepoint enforces.
    #    No network call and no audit side effect, so it is idempotent / CI-safe.
    from .enterprise import enterprise_enabled, is_local_provider
    ent = enterprise_enabled()
    cloud_blocked = ent and not is_local_provider(_CLOUD_PROBE)
    local_ok = is_local_provider(_LOCAL_PROBE)
    checks.append(GuaranteeCheck(
        "Egress lock",
        bool(cloud_blocked and local_ok),
        f"enterprise mode on; cloud provider {_CLOUD_PROBE!r} refused, self-hosted "
        f"{_LOCAL_PROBE!r} allowed (guard raises EgressBlocked at the LLM chokepoint)"
        if cloud_blocked and local_ok
        else "enable [enterprise] mode = true -- data can currently reach a cloud API",
    ))

    # 2. At-rest encryption -- actually seal + unseal a probe so a missing crypto
    #    backend or unreadable key fails here instead of silently at write time.
    from .crypto_at_rest import EncryptionUnavailable, at_rest_enabled
    enc_ok = False
    enc_detail = "enable [encryption] at_rest = true (or enterprise mode) to seal data"
    if at_rest_enabled():
        try:
            from .crypto_at_rest import seal_to_str, unseal_from_str
            sealed = seal_to_str(_SEAL_PROBE)
            enc_ok = (
                sealed != _SEAL_PROBE
                and _SEAL_PROBE not in sealed
                and unseal_from_str(sealed) == _SEAL_PROBE
            )
            enc_detail = (
                "AES-256-GCM seal/unseal round-trips; plaintext absent from ciphertext"
                if enc_ok
                else "at-rest encryption enabled but seal/unseal failed"
            )
        except EncryptionUnavailable as e:
            enc_detail = f"at-rest enabled but unavailable: {e}"
    checks.append(GuaranteeCheck("At-rest encryption", enc_ok, enc_detail))

    # 3. Tamper-evident audit -- exercise the same signer/key path real audit
    #    writes depend on.  Import-only crypto checks can pass while a malformed
    #    or unreadable key makes the writer fall back to unsigned rows, so append
    #    and verify a signed probe chain.
    checks.append(_verify_audit_signing())

    # 4. Human oversight -- destructive actions are consent-gated, not auto-approved.
    mode = "auto-approve"
    try:
        from .safety.consent import _resolve_mode
        mode = _resolve_mode()
    except Exception:
        pass
    oversight = mode in {"ask", "dashboard", "auto-deny"}
    checks.append(GuaranteeCheck(
        "Human oversight",
        oversight,
        f"consent mode = {mode}" if oversight
        else "set MAVERICK_CONSENT_MODE=ask (or enable enterprise mode)",
    ))

    # 5. Retention -- storage limitation configured (GDPR Art. 5(1)(e)).
    retention = False
    try:
        from .config import load_config
        retention = bool((load_config() or {}).get("retention"))
    except Exception:
        pass
    checks.append(GuaranteeCheck(
        "Retention policy",
        retention,
        "configured; enforce with 'maverick retention enforce'" if retention
        else "set [retention] audit_days / episodes_days / events_days / messages_days",
    ))

    # 6. Sandbox isolation -- agent-generated code must not run unsandboxed on
    # the host. The 'local' backend runs model-generated shell on the host with
    # no container isolation; a container backend is required for a real boundary.
    backend = "local"
    try:
        from .config import load_config
        backend = str(
            (load_config() or {}).get("sandbox", {}).get("backend") or "local"
        ).strip().lower()
    except Exception:
        pass
    sandboxed = _sandbox_isolated(backend)
    checks.append(GuaranteeCheck(
        "Sandbox isolation",
        sandboxed,
        _sandbox_isolation_detail(backend, sandboxed),
    ))

    # 7. Threat shield -- the input/tool/output screen must be installed and
    #    enforcing. The kernel runs fail-open without it (CLAUDE.md rule 1), so
    #    this is only a *gate* under a required enterprise deployment: there, a
    #    silently-absent or disabled shield means the boundary does not hold.
    checks.append(_verify_shield())

    # 8. Data residency -- region pin coherence. Passes (informational)
    #    when residency strict mode is off, so this never breaks an enterprise
    #    deployment that doesn't pin a region; only a strict + misconfigured pin
    #    fails the guarantee (and aborts a required boot).
    from .residency import check_residency
    res_ok, res_detail = check_residency()
    checks.append(GuaranteeCheck("Data residency", res_ok, res_detail))

    return checks


def _shield_sink_enabled(shield: object, attr: str) -> bool:
    """Return whether a Shield scan sink is configured to enforce."""
    return bool(getattr(shield, attr, True))


def _verify_shield() -> GuaranteeCheck:
    """Verify the threat shield is installed and fully enforcing.

    Optional import: maverick-shield is not a hard dependency (kernel rule 1).
    A required enterprise deployment, however, must not run with the screen off
    -- so an absent or disabled shield fails this guarantee. The built-in
    ruleset counts as enforcing (the detail nudges toward the full SDK)."""
    name = "Threat shield"
    try:
        from maverick_shield import Shield
    except Exception:
        return GuaranteeCheck(
            name, False,
            "maverick-shield not installed; input/tool/output screening is off. "
            "Install Shield from the same reviewed Lightwork checkout; "
            "public-index lookup is disabled",
        )
    try:
        shield = Shield.from_config(warn_if_missing=False)
    except Exception as e:
        return GuaranteeCheck(name, False, f"shield construction failed: {e}")
    if not getattr(shield, "enabled", False):
        return GuaranteeCheck(
            name, False,
            "shield installed but disabled ([safety] profile = off); set a "
            "profile (strict/balanced) so screening is enforced",
        )
    sinks = {
        "scan_input": _shield_sink_enabled(shield, "_scan_input_enabled"),
        "scan_tool_calls": _shield_sink_enabled(shield, "_scan_tool_calls_enabled"),
        "scan_output": _shield_sink_enabled(shield, "_scan_output_enabled"),
    }
    disabled = [key for key, enabled in sinks.items() if not enabled]
    if disabled:
        flags = ", ".join(f"{key} = true" for key in disabled)
        return GuaranteeCheck(
            name, False,
            "shield installed but not fully enforcing; enable [safety] "
            f"{flags}",
        )
    backend = getattr(shield, "backend", "?")
    full = backend == getattr(Shield, "BACKEND_SDK", "agent-shield")
    detail = (
        "agent-shield SDK active (full ruleset)" if full
        else f"shield enforcing via {backend!r} backend (install agent-shield "
             "for the full ruleset)"
    )
    return GuaranteeCheck(name, True, detail)


def _verify_audit_signing() -> GuaranteeCheck:
    """Write and verify a signed probe using the real audit signing key path."""
    name = "Tamper-evident audit"
    detail = "enable [audit] sign = true (or MAVERICK_AUDIT_SIGN=1)"
    probe = None
    try:
        from .audit.writer import _resolve_signing

        if not _resolve_signing(None):
            return GuaranteeCheck(name, False, detail)

        from .audit.signing import AuditSigner, _have_crypto, verify_chain

        if not _have_crypto():
            return GuaranteeCheck(
                name,
                False,
                "audit signing requested but 'cryptography' is not installed",
            )

        from .paths import data_dir

        audit_dir = data_dir("audit")
        audit_dir.mkdir(parents=True, exist_ok=True)
        probe = audit_dir / ".enterprise-verify-probe.ndjson"
        try:
            probe.unlink()
        except FileNotFoundError:
            pass

        signer = AuditSigner(probe)
        wrote = signer.write({
            "kind": "enterprise_verify_probe",
            "agent": "system",
            "goal_id": None,
            "v": 1,
        })
        breaks = verify_chain(probe) if wrote else []
        passed = bool(wrote and not breaks)
        detail = (
            "Ed25519 hash-chain probe wrote and verified; verify logs with "
            "'maverick audit verify'"
            if passed
            else "audit signing probe failed to write or verify"
        )
        return GuaranteeCheck(name, passed, detail)
    except Exception as e:
        return GuaranteeCheck(name, False, f"audit signing probe failed: {e}")
    finally:
        try:
            if probe is not None:
                probe.unlink()
        except Exception:
            pass


def all_passed(checks: list[GuaranteeCheck]) -> bool:
    return all(c.passed for c in checks)


def render_text(checks: list[GuaranteeCheck]) -> str:
    head = "Regulated-deployment guarantees"
    width = max((len(c.name) for c in checks), default=10)
    lines = [head, "=" * len(head), ""]
    for c in checks:
        lines.append(f"  [{'PASS' if c.passed else 'FAIL'}]  {c.name:<{width}}  {c.detail}")
    passed = sum(1 for c in checks if c.passed)
    lines += ["", f"{passed}/{len(checks)} guarantees hold"]
    if not all_passed(checks):
        lines += [
            "",
            "Not deployment-ready. Apply the regulated profile "
            "(docs/regulated-deployment.md) and re-run.",
        ]
    return "\n".join(lines)


def render_json(checks: list[GuaranteeCheck]) -> str:
    import json
    return json.dumps(
        {
            "guarantees": [asdict(c) for c in checks],
            "all_passed": all_passed(checks),
        },
        indent=2,
    )


# ----- Enforceable preflight ------------------------------------------------
# Enterprise hardening is opt-in (CLAUDE.md kernel rule 1: never *require* it
# unless explicitly asked). These helpers turn it into a deploy/startup gate
# *only when an operator demands it* via MAVERICK_REQUIRE_ENTERPRISE=1 (or
# ``[enterprise] require = true``); they are a no-op otherwise, so the default
# fail-open posture is unchanged.

# Env flag that promotes the verifier into a hard startup gate. Distinct from
# ``MAVERICK_ENTERPRISE`` (which *turns the boundary on*): this one asserts the
# boundary must already hold, and aborts the deployment if it does not.
REQUIRE_ENTERPRISE_ENV = "MAVERICK_REQUIRE_ENTERPRISE"

_TRUE_WORDS = frozenset({"1", "true", "yes", "on", "enable", "enabled", "y", "t"})


class EnterpriseRequiredError(RuntimeError):
    """A required enterprise preflight failed -- the deployment is not safe to run.

    Carries the failing :class:`GuaranteeCheck` list and a human-readable summary
    so a caller (CLI, dashboard startup, container entrypoint) can log exactly
    which boundary guarantee did not hold before it aborts.
    """

    def __init__(self, checks: list[GuaranteeCheck], summary: str):
        super().__init__(summary)
        self.checks = checks
        self.summary = summary


def enterprise_required() -> bool:
    """True if this deployment has *opted in* to a blocking enterprise preflight.

    Reads ``MAVERICK_REQUIRE_ENTERPRISE`` (a recognized truthy value wins over
    config) then ``[enterprise] require`` in ``~/.maverick/config.toml``. Off by
    default -- with neither set the preflight is a no-op and the kernel keeps its
    fail-open posture. Note this is independent of whether enterprise mode is
    *on*: requiring the preflight while the boundary is off is exactly the
    misconfiguration the gate is meant to catch.
    """
    env = os.environ.get(REQUIRE_ENTERPRISE_ENV)
    if env is not None and env.strip() != "":
        return env.strip().lower() in _TRUE_WORDS
    try:
        from .config import load_config
        val = ((load_config() or {}).get("enterprise") or {}).get("require")
    except Exception:
        return False
    if isinstance(val, str):
        return val.strip().lower() in _TRUE_WORDS
    return bool(val)


def _preflight_summary(checks: list[GuaranteeCheck]) -> str:
    failed = [c for c in checks if not c.passed]
    head = (
        f"enterprise preflight FAILED: {len(failed)} of {len(checks)} "
        "data-boundary guarantees do not hold; refusing to start"
    )
    lines = [head, ""]
    lines += [f"  - {c.name}: {c.detail}" for c in failed]
    lines += [
        "",
        "Apply the regulated profile (docs/regulated-deployment.md) and re-run, "
        "or unset MAVERICK_REQUIRE_ENTERPRISE / [enterprise] require to allow a "
        "non-hardened deployment.",
    ]
    return "\n".join(lines)


def preflight_enterprise(
    *, force: bool | None = None
) -> tuple[bool, str | None]:
    """Non-raising enterprise preflight: ``(ok, report)``.

    ``ok`` is True (and ``report`` is None) when the preflight is not required --
    so callers that always invoke it stay fail-open by default. When required (or
    ``force=True``), runs :func:`verify_deployment` and returns ``ok=False`` with a
    human-readable failure ``report`` if any guarantee does not hold, else
    ``ok=True`` and a short pass summary.

    ``force`` overrides the env/config detection (e.g. a ``--require`` CLI flag).
    """
    required = enterprise_required() if force is None else force
    if not required:
        return True, None
    checks = verify_deployment()
    if all_passed(checks):
        return True, f"enterprise preflight OK: {len(checks)} guarantees hold"
    return False, _preflight_summary(checks)


def require_enterprise_or_die(*, force: bool | None = None) -> None:
    """Blocking enterprise preflight. NO-OP unless required.

    Required = ``MAVERICK_REQUIRE_ENTERPRISE`` truthy or ``[enterprise] require =
    true`` (or ``force=True``). When required and any data-boundary guarantee
    fails (enterprise mode off, audit signing off, egress not locked, at-rest
    sealing broken), raises :class:`EnterpriseRequiredError` with a summary of
    what failed so an unsafe deployment is aborted at startup. Otherwise returns
    silently -- the kernel's default fail-open behaviour is unchanged.
    """
    if force is None:
        force = enterprise_required()
    if not force:
        return
    checks = verify_deployment()
    if not all_passed(checks):
        raise EnterpriseRequiredError(checks, _preflight_summary(checks))


__all__ = [
    "REGULATED_PROFILE",
    "GuaranteeCheck",
    "verify_deployment",
    "all_passed",
    "render_text",
    "render_json",
    "EnterpriseRequiredError",
    "enterprise_required",
    "preflight_enterprise",
    "require_enterprise_or_die",
]
