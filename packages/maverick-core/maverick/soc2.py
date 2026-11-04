"""SOC 2 evidence collector — a machine-readable posture snapshot.

A SOC 2 audit (and any continuous-compliance automation in front of one) needs
to answer a simple question on demand: *which technical controls are actually
ON in this deployment right now, and is the tamper-evident audit log intact?*
This module answers it.

:func:`collect_soc2_evidence` returns a structured dict that an auditor or the
``maverick soc2`` CLI command (see ``docs/compliance/soc2-controls.md``) can
serialize to JSON and attach to an evidence request. It probes the live configuration:

  - capability enforcement (``maverick.capability.capability_enforced``)
  - per-user tenant isolation (``maverick.paths.tenant_by_user_enabled``)
  - per-principal usage quotas (``maverick.quotas.quotas_enforced``)
  - OIDC auth verifier (``maverick.oidc.oidc_enabled``) — optional module
  - encryption at rest (``maverick.crypto_at_rest.at_rest_enabled``)
  - data-subject export / DSAR (``maverick.dsar.export_subject_data`` present)
  - the append-only Ed25519 Merkle-chained audit log: does it verify, and is a
    signing key present?

Design contract — this module is **fail-soft and import-light**:

  - It never raises. A probe that errors, or whose backing module is absent,
    is reported with ``status`` ``"unknown"`` (probe error) or ``"absent"``
    (module not installed) — never a crash. SOC 2 evidence collection must not
    be able to take down the host it is auditing. This explicitly includes
    ``BaseException``: a half-installed native crypto backend can ``panic`` (a
    pyo3 ``PanicException`` is a ``BaseException``, not an ``Exception``), and
    even that must degrade to ``"unknown"`` rather than abort the snapshot.
  - Every dependency is imported lazily inside the probe, so ``import
    maverick.soc2`` succeeds even when optional features (oidc/quotas) or
    ``cryptography`` are not installed.

The snapshot is descriptive, not prescriptive: ``"absent"``/``"unknown"`` are
honest states, not failures. The mapping of these controls to the SOC 2 Trust
Services Criteria lives in ``docs/compliance/soc2-controls.md``.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

# Status vocabulary for a single technical control probe.
#   enabled   — the control is configured ON in this deployment
#   disabled  — the control exists but is OFF (default-open / opt-in)
#   absent    — the backing module is not installed (optional feature)
#   unknown   — the probe raised; we caught it and refuse to crash
STATUS_ENABLED = "enabled"
STATUS_DISABLED = "disabled"
STATUS_ABSENT = "absent"
STATUS_UNKNOWN = "unknown"


def _probe_toggle(import_path: str, attr: str) -> dict[str, Any]:
    """Probe one boolean ``enabled()``-style control, fail-soft.

    ``import_path`` is a dotted module (e.g. ``"maverick.capability"``); ``attr``
    is a zero-arg predicate on it (e.g. ``"capability_enforced"``). Returns a
    small dict with a ``status`` from the vocabulary above and, when the call
    succeeded, the raw boolean under ``enabled``.

    Order of outcomes:
      - module missing              -> ``absent``
      - attr missing / not callable -> ``absent`` (treated as an unshipped
        feature, e.g. a future ``maverick.oidc`` that does not exist yet)
      - call raised                 -> ``unknown`` (with the error string)
      - call returned truthy/falsy  -> ``enabled`` / ``disabled``
    """
    import importlib

    try:
        module = importlib.import_module(import_path)
    except BaseException:  # noqa: BLE001 — fail-soft; absent OR unimportable
        # ImportError for a genuinely-absent optional module, but also any
        # error while importing it — either way the control is not usable here.
        return {"status": STATUS_ABSENT, "enabled": None}

    fn = getattr(module, attr, None)
    if not callable(fn):
        return {"status": STATUS_ABSENT, "enabled": None}

    try:
        value = bool(fn())
    except BaseException as exc:  # noqa: BLE001 — fail-soft; even a pyo3 panic
        # (PanicException is a BaseException) must not propagate out of a probe.
        return {"status": STATUS_UNKNOWN, "enabled": None, "error": str(exc)}

    return {
        "status": STATUS_ENABLED if value else STATUS_DISABLED,
        "enabled": value,
    }


def _probe_present(import_path: str, attr: str) -> dict[str, Any]:
    """Probe whether a *capability* (a callable) is shipped, fail-soft.

    Unlike :func:`_probe_toggle`, this reports the mere presence of an
    implemented feature rather than a runtime on/off toggle: it never calls
    ``attr``, only checks the module imports and the attribute is callable. Used
    for controls whose existence is the control (e.g. a DSAR export endpoint:
    GDPR Art. 15/20 access/portability is satisfied by the code being there).

    Order of outcomes (same fail-soft discipline as :func:`_probe_toggle`):
      - module missing / unimportable -> ``absent``
      - attr missing / not callable   -> ``absent`` (an unshipped feature)
      - both present                  -> ``enabled``

    Returns ``status`` from the shared vocabulary plus ``enabled`` (``True`` iff
    the capability is present). It never invokes the feature, so — unlike a
    toggle probe — there is no ``disabled``/``unknown`` outcome here.
    """
    import importlib

    try:
        module = importlib.import_module(import_path)
    except BaseException:  # noqa: BLE001 — fail-soft; absent OR unimportable
        return {"status": STATUS_ABSENT, "enabled": False}

    fn = getattr(module, attr, None)
    if not callable(fn):
        return {"status": STATUS_ABSENT, "enabled": False}

    return {"status": STATUS_ENABLED, "enabled": True}


def _safe(fn: Callable[[], Any], default: Any) -> Any:
    """Run ``fn`` and swallow anything it throws, returning ``default``.

    Catches ``BaseException`` on purpose: the audit probes call into the native
    crypto backend, which can ``panic`` (a pyo3 ``PanicException`` is a
    ``BaseException``) on a broken install. The fail-soft contract holds anyway.
    """
    try:
        return fn()
    except BaseException:  # noqa: BLE001 — see docstring; fail-soft is the point
        return default


def _resolve_audit_dir():
    """The active, tenant-scoped audit directory (``<data>/audit``).

    Mirrors :class:`maverick.audit.writer.AuditLog`'s own default so the snapshot
    reflects where rows are *currently* written — not a path a process singleton
    cached at import. Lazy import keeps this module light.
    """
    from .paths import data_dir

    return data_dir("audit")


def _audit_signing_expected() -> bool:
    """Whether this deployment is expected to produce a signed/anchored log.

    True when audit signing is configured on (``[audit] sign`` / ``MAVERICK_AUDIT_SIGN``)
    OR a signing key already exists on disk (the host has signed before). The
    operator's signing config lives outside the audit dir, so an attacker who
    can only write the audit dir cannot flip it -- a missing anchor ledger while
    signing is *expected* therefore stays a real break (the tamper-downgrade
    defence). A genuinely unsigned deployment -- no signing config and no key --
    legitimately has no anchor ledger, so its missing ledger is the benign
    ``unsigned`` state, not ``broken``.
    """
    from .audit import signing
    from .audit.writer import _resolve_signing

    if _resolve_signing(None):
        return True
    return any(signing._key_dir().glob("*.key"))


def _probe_audit_chain() -> dict[str, Any]:
    """Verify the append-only Ed25519 Merkle-chained audit log, fail-soft.

    Resolves the active (tenant-aware) audit directory via :func:`_resolve_audit_dir`,
    then runs ``verify_chain`` over every day-file and ``verify_anchors`` over
    the cross-file anchor ledger. Reports one of:

      - ``ok``      — at least one day-file exists and all of them verify clean
      - ``broken``  — a day-file failed cryptographic verification: a real
        chain/hash/signature break (possible tampering). The count of breaks
        and the first reason are included.
      - ``unsigned`` — day-files exist but rows carry no hash/sig/key_id, i.e.
        audit signing is **off** (``[audit] sign`` / ``MAVERICK_AUDIT_SIGN``).
        The log is append-only NDJSON but not cryptographically tamper-evident.
        This is a *configuration* state, deliberately distinct from ``broken``
        so an auditor isn't alarmed by an un-enabled (not a tampered) chain.
      - ``empty``   — no day-files yet (a fresh deployment; not a failure)
      - ``no_crypto`` — ``cryptography`` is not installed, so the chain cannot
        be verified here (the log may still be signed elsewhere)
      - ``unknown`` — the probe itself errored; caught, never raised

    The cross-file anchor ledger (``anchors.ndjson``) is excluded from the
    per-day glob, then checked separately with ``verify_anchors`` so deletion or
    truncation of an entire completed day-file is still detected.
    """
    result: dict[str, Any] = {"status": STATUS_UNKNOWN}

    try:
        from .audit import verify_anchors, verify_chain
    except BaseException as exc:  # noqa: BLE001 — fail-soft import guard
        result["error"] = str(exc)
        return result

    # Resolve the active (tenant-aware) audit dir the same way the writer does —
    # via ``data_dir("audit")`` — rather than via the cached ``default_audit_log``
    # singleton, whose path is frozen at first construction and would be stale in
    # a long-lived / re-homed process (or under a different active tenant).
    audit_dir = _safe(lambda: _resolve_audit_dir(), None)
    if audit_dir is None:
        result["error"] = "could not resolve audit directory"
        return result
    result["audit_dir"] = str(audit_dir)

    # The shared reader defines "what counts as a day-file" (date-named
    # ``*.ndjson``, anchor ledger excluded) once; the cross-file
    # ``anchors.ndjson`` is checked separately by ``verify_anchors`` below.
    from .audit import reader

    day_files = _safe(lambda: reader.day_files(audit_dir), [])
    real_breaks = 0  # genuine tamper/verify failures
    unsigned_rows = 0  # rows missing hash/sig/key_id (signing simply off)
    first_reason: str | None = None
    no_crypto = False
    # Fail-safe to "expected" (stay strict) if the signal can't be read. Compute
    # before row classification so stripped signatures on a host that signs do
    # not get downgraded to the benign unsigned-configuration state.
    signing_expected = _safe(_audit_signing_expected, True)
    for path in day_files:
        breaks = _safe(lambda p=path: verify_chain(p), None)
        if breaks is None:
            # verify_chain itself errored on this file — stay fail-soft and
            # surface it as unknown rather than silently claiming "ok".
            result["status"] = STATUS_UNKNOWN
            result["error"] = f"verify_chain raised for {path.name}"
            return result
        for b in breaks:
            reason = getattr(b, "reason", "")
            if reason == "no_crypto":
                no_crypto = True
                continue
            missing_signature_fields = reason == "unsigned" or (
                reason == "malformed"
                and "missing hash/sig/key_id" in (getattr(b, "detail", "") or "")
            )
            # Missing signing fields are benign only when signing is not
            # expected. If this deployment is configured to sign (or has a
            # signing key), all signing fields disappearing is a possible
            # downgrade/strip attack.
            if missing_signature_fields:
                if signing_expected:
                    real_breaks += 1
                    if first_reason is None:
                        first_reason = "missing_signature_fields"
                else:
                    unsigned_rows += 1
                continue
            real_breaks += 1
            if first_reason is None:
                first_reason = reason or "break"

    anchor_breaks = _safe(lambda: verify_anchors(audit_dir), None)
    if anchor_breaks is None:
        result["status"] = STATUS_UNKNOWN
        result["error"] = "verify_anchors raised"
        return result
    for b in anchor_breaks:
        reason = getattr(b, "reason", "")
        if reason == "no_crypto":
            no_crypto = True
            continue
        # A *completely* absent anchor ledger on a deployment that never signs
        # (no signing config, no key) is the benign "unsigned" state, not
        # tampering -- otherwise every honest unsigned deployment reports
        # "broken" the day after its first audit file. A signed deployment
        # whose ledger was stripped still has signing expected (config/key), so
        # it stays "broken": the downgrade defence is preserved. Other anchor
        # breaks (e.g. an anchored day-file deleted) imply a ledger existed and
        # are always real.
        if reason == "anchor_ledger_missing" and not signing_expected:
            continue
        real_breaks += 1
        if first_reason is None:
            first_reason = reason or "anchor_break"

    result["files_checked"] = len(day_files)
    result["anchors_checked"] = True
    if real_breaks:
        result["status"] = "broken"
        result["breaks"] = real_breaks
        result["first_reason"] = first_reason
        return result
    if no_crypto:
        result["status"] = "no_crypto"
        return result
    if not day_files:
        result["status"] = "empty"
        return result
    if unsigned_rows:
        result["status"] = "unsigned"
        result["unsigned_rows"] = unsigned_rows
        return result
    result["status"] = "ok"
    return result


def _probe_signing_key() -> dict[str, Any]:
    """Report whether an audit signing key (the chain's trust anchor) is present.

    A present signing key means this process can sign new audit rows; without one
    the log is append-only NDJSON but not cryptographically tamper-evident. The
    active key can take two forms, BOTH of which count as present:

      - a local private ``.key`` file, or
      - an **off-host** key (KMS / secrets-manager), held in memory and injected
        at deploy time via ``MAVERICK_AUDIT_SIGNING_KEY`` /
        ``MAVERICK_AUDIT_SIGNING_KEY_WRAPPED``.

    An injected key leaves a ``.injected`` marker + ``.pub`` next to the
    deliberately absent ``.key``. That marker remains useful as a historical
    verification anchor, but it does *not* prove that the current process still
    has private-key material after a restart. Counting a marker alone as
    signing-capable would let a posture check pass while new rows are unsigned.
    Fail-soft: any error -> ``status`` ``unknown``.
    """
    import os

    result: dict[str, Any] = {"status": STATUS_UNKNOWN}
    try:
        from .audit import signing
    except BaseException as exc:  # noqa: BLE001 — fail-soft import guard
        result["error"] = str(exc)
        return result

    key_dir = _safe(signing._key_dir, None)
    if key_dir is None:
        result["error"] = "could not resolve key directory"
        return result
    result["key_dir"] = str(key_dir)

    key_paths = _safe(lambda: sorted(key_dir.glob("*.key")), None)
    if key_paths is None:
        result["error"] = "could not enumerate key directory"
        return result
    # A marker proves historical/public-key provisioning only. Current off-host
    # signing capability requires the raw or KMS-wrapped private key to be
    # configured in this process.
    injected = _safe(lambda: sorted(p.name for p in key_dir.glob("*.injected")), []) or []
    raw_configured = bool(os.environ.get("MAVERICK_AUDIT_SIGNING_KEY", ""))
    wrapped_value = os.environ.get("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", "")

    # Use the signer's one-shot consume/cache path. Reading and decoding the
    # raw env value here would bypass its explicit environment-erasure
    # invariant and prolong private-key exposure through same-user /proc reads.
    injected_keypair = _safe(signing._injected_keypair, None)
    raw_usable = (
        isinstance(injected_keypair, tuple)
        and len(injected_keypair) == 3
    )
    wrapped_usable = bool(
        wrapped_value
        and _safe(lambda: signing._kms_wrapped_keypair() is not None, False)
    )

    disk_usable = False
    disk_error: str | None = None
    if key_paths:
        try:
            active = signing._active_key_id(key_dir)
            if active is None:
                for candidate in key_paths:
                    if not signing._is_valid_key_id(candidate.stem):
                        raise ValueError(
                            "audit key directory contains an invalid key filename"
                        )
                active = max(
                    key_paths,
                    key=lambda path: path.stat().st_mtime_ns,
                ).stem
            signing._read_disk_keypair(key_dir, active)
            disk_usable = True
        except (OSError, ValueError) as exc:
            disk_error = str(exc)

    offhost_required = bool(_safe(signing.require_offhost_signing, False))
    offhost_usable = raw_usable or wrapped_usable
    present = offhost_usable or (disk_usable and not offhost_required)
    result["present"] = present
    result["key_count"] = len(key_paths)
    result["offhost_key"] = offhost_usable
    result["offhost_required"] = offhost_required
    result["raw_key_configured"] = raw_configured
    result["raw_key_usable"] = raw_usable
    result["wrapped_key_configured"] = bool(wrapped_value)
    result["wrapped_key_usable"] = wrapped_usable
    result["disk_key_usable"] = disk_usable
    if disk_error is not None:
        result["disk_key_error"] = disk_error
    result["historical_injected_key_count"] = len(injected)
    result["verification_anchor_present"] = bool(
        disk_usable or injected or offhost_usable
    )
    result["status"] = STATUS_ENABLED if present else STATUS_ABSENT
    return result


def _maverick_version() -> str:
    return _safe(lambda: __import__("maverick").__version__, "unknown")


def collect_soc2_evidence() -> dict[str, Any]:
    """Return a structured SOC 2 posture snapshot for an auditor/automation.

    The returned dict is JSON-serializable and stable in shape (top-level keys
    are always present even when a probe is ``absent``/``unknown``):

      - ``version``      — maverick package version (str; ``"unknown"`` on error)
      - ``collected_at`` — UTC epoch seconds when the snapshot was taken (float)
      - ``controls``     — per-control technical-toggle probes, keyed by a short
        control id; each value has a ``status`` and (for toggles) ``enabled``:
          * ``capability_enforcement`` — signed attenuating per-agent grants
          * ``tenant_isolation``       — per-user multi-tenant data isolation
          * ``usage_quotas``           — per-principal daily spend/token caps
          * ``oidc_auth``              — OIDC ID-token verifier (optional module)
          * ``encryption_at_rest``     — AES-256-GCM at-rest encryption toggle
          * ``data_subject_export``    — DSAR access/portability export present
            (a presence probe: ``enabled``/``absent``, never a runtime toggle)
      - ``audit_log``    — audit-chain verification: ``ok`` / ``broken`` /
        ``unsigned`` / ``empty`` / ``no_crypto`` / ``unknown`` (see
        ``_probe_audit_chain``)
      - ``audit_signing_key`` — signing-key presence (see ``_probe_signing_key``)

    Never raises. Probe a deployment with confidence: a missing optional module
    is reported as ``absent`` and a probe that throws as ``unknown`` — the call
    always returns a dict.
    """
    return {
        "version": _maverick_version(),
        "collected_at": time.time(),
        "controls": {
            "capability_enforcement": _probe_toggle(
                "maverick.capability", "capability_enforced"
            ),
            "tenant_isolation": _probe_toggle(
                "maverick.paths", "tenant_by_user_enabled"
            ),
            "usage_quotas": _probe_toggle("maverick.quotas", "quotas_enforced"),
            "oidc_auth": _probe_toggle("maverick.oidc", "oidc_enabled"),
            "encryption_at_rest": _probe_toggle(
                "maverick.crypto_at_rest", "at_rest_enabled"
            ),
            "data_subject_export": _probe_present(
                "maverick.dsar", "export_subject_data"
            ),
        },
        "audit_log": _safe(_probe_audit_chain, {"status": STATUS_UNKNOWN}),
        "audit_signing_key": _safe(_probe_signing_key, {"status": STATUS_UNKNOWN}),
    }


__all__ = ["collect_soc2_evidence"]
