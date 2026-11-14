"""Finance posture report — the ``finance status`` view (finance-agent-suite §5).

Generalises ``compliance_report()`` to the finance control plane: it introspects
the deployment and reports which finance controls are actually live — SoD
cleanliness of the roster, the maker-checker gate on money movement, amount-aware
delegation-of-authority tiers, the tamper-evident book of record, sanctions
screening, read-only-by-default, encryption at rest, and the egress lock — plus
which compliance regimes are enabled. Honest framing: this is *control coverage*,
not an audit opinion (Lightwork supplies the controls + evidence; humans post, pay,
file, and certify).
"""
from __future__ import annotations

import logging
import math
import time

from ..compliance import ControlCheck
from . import regimes as _regimes

log = logging.getLogger(__name__)

FINANCE_DISCLAIMER = (
    "Finance control-coverage report, not an audit opinion or a certification. "
    "Agents draft; humans post, pay, file, and certify. No agent attests to ICFR, "
    "signs a §302 certification, or files with the SEC/IRS."
)


def _money_gate_active() -> tuple[bool, str]:
    """Is every money/posting action gated to a human (config + regimes)?"""
    from ..governance import Policy
    from ..safety.tool_risk import risk_rank, tool_risk
    effective = _regimes.union_policies(
        [Policy.from_config(), _regimes.compile_policy(_regimes.configured_regimes())])
    covered = set(effective.require_human_actions) | set(effective.deny_actions)
    covered.update(action for action, level in effective.automation.items() if level in {"draft", "approve"})
    missing = [a for a in _regimes._MONEY_ACTIONS if a not in covered and not (
        effective.require_human_min_risk is not None
        and risk_rank(tool_risk(a)) >= risk_rank(effective.require_human_min_risk))]
    if not missing:
        return True, "Money and posting actions require a person to perform or approve them."
    return False, ("set [governance] require_human_min_risk=\"high\" or enable a "
                   "finance regime (e.g. [finance] regimes=[\"sox\"]); ungated: "
                   + ", ".join(missing[:5]))


def _amount_tiers_active() -> tuple[bool, str]:
    from ..governance import Policy
    pol = _regimes.union_policies(
        [Policy.from_config(), _regimes.compile_policy(_regimes.configured_regimes())])
    on = bool(pol.require_human_above or pol.deny_above)
    return on, ("delegation-of-authority dollar tiers configured" if on
                else "set [governance] require_human_above / deny_above thresholds")


def _sod_active() -> tuple[bool, str]:
    from ..domain import available_domains
    from .sod_linter import lint_roster
    packs = {n: p for n, p in available_domains().items()
             if n.startswith("finance_")}
    conflicts = lint_roster(packs)
    if conflicts:
        return False, f"{len(conflicts)} SoD conflict(s): {conflicts[0]}"
    return True, f"{len(packs)} finance packs are segregation-of-duties clean"


def _signing_active() -> tuple[bool, str]:
    try:
        from ..audit.writer import _resolve_signing
        if _resolve_signing(None):
            return True, "Ed25519 hash-chain on; verify with 'maverick audit verify'"
    except Exception as e:
        log.warning("finance status: audit-signing probe failed: %s", e)
        return False, f"could not verify audit signing (probe error: {type(e).__name__})"
    return False, "enable [audit] sign = true for the SOX-grade book of record"


def _sanctions_active() -> tuple[bool, str]:
    from . import aml_screening

    if aml_screening.enabled():
        try:
            versions = aml_screening.list_versions(list_kind="sanctions", limit=10_001)
            if len(versions) > 10_000:
                return False, "governed sanctions list inventory exceeds its status bound"
            if not versions:
                return False, "ingest at least one governed sanctions list version"
            latest = max(
                versions,
                key=lambda row: float(
                    (row.get("provenance") or {}).get("retrieved_at") or 0
                ),
            )
            cases = aml_screening.list_cases(limit=10_001)
            if len(cases) > 10_000:
                return False, "governed sanctions case inventory exceeds its status bound"
            open_cases = len([
                row for row in cases
                if row.get("status") not in {"cleared", "escalated"}
            ])
            return True, (
                f"governed {latest.get('list_kind')} list {latest.get('id')} "
                f"version {latest.get('version')} loaded with SHA-256 provenance; "
                f"{open_cases} case(s) await final disposition"
            )
        except Exception as e:
            log.warning("finance status: governed screening probe failed: %s", e)
            return False, f"governed sanctions screening is unavailable ({type(e).__name__})"
    from ..tools.sanctions_screen import _list_path, load_list
    path = _list_path()
    try:
        names = load_list(path)
    except ValueError as e:
        return False, f"sanctions list at {path} is unusable: {e}"
    if names:
        return True, f"sanctions list loaded ({len(names)} names) at {path}"
    return False, f"add an OFAC SDN list at {path} (or set [screening] sdn_path)"


def _regulatory_monitor_active() -> tuple[bool, str]:
    try:
        from ..config import config_source_errors, load_config, load_global_config
        from .operations_health import success_receipts

        global_section = (load_global_config() or {}).get("finance_operations")
        if not isinstance(global_section, dict) or global_section.get("enable") is not True:
            return False, "enable [finance_operations] to start cited regulatory monitoring"
        if config_source_errors(include_tenant=True):
            return False, "tenant-effective finance operations configuration is invalid"
        section = (load_config() or {}).get("finance_operations")
        if not isinstance(section, dict):
            return False, "tenant-effective [finance_operations] configuration is missing"
        federal_raw = section.get("federal_register_enable", True)
        if not isinstance(federal_raw, bool):
            return False, "finance_operations.federal_register_enable must be boolean"
        federal = federal_raw is True
        texas_raw = section.get("texas_register_enable", False)
        if not isinstance(texas_raw, bool):
            return False, "finance_operations.texas_register_enable must be boolean"
        texas = texas_raw is True
        eur_lex_raw = section.get("eur_lex_enable", False)
        if not isinstance(eur_lex_raw, bool):
            return False, "finance_operations.eur_lex_enable must be boolean"
        edpb_raw = section.get("edpb_enable", False)
        if not isinstance(edpb_raw, bool):
            return False, "finance_operations.edpb_enable must be boolean"
        state_feeds = section.get("state_feeds", [])
        if not isinstance(state_feeds, list):
            return False, "finance_operations.state_feeds must be a list"
        source_keys = ["federal-register"] if federal else []
        if texas:
            source_keys.append("texas-register")
        if eur_lex_raw is True:
            source_keys.append("eur-lex-legislation")
        if edpb_raw is True:
            source_keys.append("edpb-news")
        for index, value in enumerate(state_feeds):
            if not isinstance(value, dict) or not str(value.get("key") or "").strip():
                return False, f"finance_operations.state_feeds[{index}] is invalid"
            source_keys.append(str(value["key"]).strip().lower())
        if len(source_keys) != len(set(source_keys)):
            return False, "finance_operations regulatory feed keys must be unique"
        source_count = len(source_keys)
        if source_count == 0:
            return False, "configure the Federal Register or at least one state register feed"
        interval = section.get("regulatory_poll_seconds", 3600)
        if (
            isinstance(interval, bool)
            or not isinstance(interval, (int, float))
            or not math.isfinite(float(interval))
            or float(interval) <= 0
        ):
            return False, "set finance_operations.regulatory_poll_seconds above zero"
        receipts = {
            str(row["key"]): row
            for row in success_receipts(component="regulatory_poll")
        }
        freshness = max(600.0, float(interval) * 2.0)
        now = time.time()
        missing = [
            key
            for key in source_keys
            if key not in receipts
            or now - float(receipts[key]["succeeded_at"]) > freshness
        ]
        if missing:
            return False, (
                f"{source_count} official feed(s) configured, but {len(missing)} lack a "
                "fresh successful-poll receipt"
            )
        newest = max(float(receipts[key]["succeeded_at"]) for key in source_keys)
        return True, (
            f"{source_count} configured official feed(s) have fresh successful-poll "
            f"receipts (newest {max(0.0, now - newest):.0f}s ago); matched changes "
            "route to the cited human review queue"
        )
    except Exception as e:
        log.warning("finance status: regulatory monitor probe failed: %s", e)
        return False, f"regulatory monitoring is unavailable ({type(e).__name__})"


def _licensing_packs_active() -> tuple[bool, str]:
    try:
        from .licensing import load_licensing_pack, validate_licensing_pack

        packs = [
            load_licensing_pack("money_transmitter"),
            load_licensing_pack("insurance_producer"),
        ]
        for pack in packs:
            validate_licensing_pack(pack)
        return False, (
            "two versioned 50-state source-routing packs validate with renewal "
            "metadata and citations, but all legal conclusions remain "
            "source_check_required"
        )
    except Exception as e:
        log.warning("finance status: licensing pack probe failed: %s", e)
        return False, f"licensing packs are unavailable ({type(e).__name__})"


def _anomaly_engine_active() -> tuple[bool, str]:
    try:
        from . import anomaly_engine

        if not anomaly_engine.enabled():
            return False, "set [finance_operations] anomaly_enable = true"
        anomaly_engine.FinanceAnomalyConfig()
        return True, (
            "duplicate, Benford-eligibility, threshold-straddling, split-payment, "
            "and off-hours rules are loadable; findings require human disposition"
        )
    except Exception as e:
        log.warning("finance status: anomaly engine probe failed: %s", e)
        return False, f"finance anomaly engine is unavailable ({type(e).__name__})"


def _grc_control_loop_active() -> tuple[bool, str]:
    try:
        from .. import security_ops
        from . import control_testing
        from .operations_health import success_receipts

        if not control_testing.enabled():
            return False, "enable [finance_operations] for scheduled finance control tests"
        interval = control_testing.schedule_config()["interval_seconds"]
        if interval <= 0:
            return False, "set finance_operations.control_test_interval_seconds above zero"
        if not security_ops.enabled():
            return False, "enable [security_ops] so finance observations reach GRC evidence queues"
        receipts = success_receipts(component="grc_control_cycle")
        if not receipts:
            return False, (
                "finance-to-GRC scheduling is configured, but no successful scheduled "
                "cycle receipt exists"
            )
        age = max(0.0, time.time() - float(receipts[0]["succeeded_at"]))
        if age > max(600.0, float(interval) * 2.0):
            return False, (
                f"the latest successful finance-to-GRC cycle receipt is stale ({age:.0f}s old)"
            )
        return True, (
            f"finance observations have a fresh scheduled Security/GRC receipt ({age:.0f}s "
            f"old; configured every {interval / 3600:.1f} hour(s)) and remain needs_review"
        )
    except Exception as e:
        log.warning("finance status: GRC control-loop probe failed: %s", e)
        return False, f"finance-to-GRC loop is unavailable ({type(e).__name__})"


def _enc_active() -> tuple[bool, str]:
    try:
        from ..crypto_at_rest import at_rest_enabled
        if at_rest_enabled():
            return True, "AES-256-GCM seals payroll PII / bank details at rest"
    except Exception as e:
        log.warning("finance status: encryption-at-rest probe failed: %s", e)
        return False, f"could not verify encryption at rest (probe error: {type(e).__name__})"
    return False, "enable [encryption] at_rest = true (payroll/treasury PII)"


def _egress_active() -> tuple[bool, str]:
    try:
        from ..enterprise import enterprise_enabled
        if enterprise_enabled():
            return True, "enterprise egress lock: LLM calls pinned on-box (GLBA/PCI)"
    except Exception as e:
        log.warning("finance status: egress-lock probe failed: %s", e)
        return False, f"could not verify egress lock (probe error: {type(e).__name__})"
    return False, "enable [enterprise] mode = true to keep financial data on-box"


def _check(control: str, regulation: str, probe) -> ControlCheck:
    ok, detail = probe()
    return ControlCheck(control, regulation,
                        "active" if ok else "action_needed", detail, framework="finance")


def finance_status() -> list[ControlCheck]:
    """Map live finance controls to their state. Powers ``maverick finance status``."""
    checks = [
        _check("Segregation of duties (roster)", "SOX / COSO", _sod_active),
        _check("Maker-checker on money movement", "SOX §404 / EU AI Act Art 14",
               _money_gate_active),
        _check("Amount-aware authorization (DoA tiers)", "Delegation of Authority",
               _amount_tiers_active),
        _check("Tamper-evident book of record", "SOX §404 / §409", _signing_active),
        _check("Sanctions screening", "AML / BSA / OFAC", _sanctions_active),
        _check("Regulatory-change monitoring", "Federal + state registers",
               _regulatory_monitor_active),
        _check("State licensing source packs", "50-state licensing",
               _licensing_packs_active),
        _check("Deterministic finance anomaly rules", "Finance monitoring",
               _anomaly_engine_active),
        _check("Finance-to-GRC control testing", "GRC evidence workflow",
               _grc_control_loop_active),
        _check("Encryption at rest", "GLBA / PCI-DSS", _enc_active),
        _check("Data-egress lock", "GLBA / data residency", _egress_active),
    ]
    enabled = _regimes.configured_regimes()
    known = [k for k in enabled if k in _regimes.REGIMES]
    checks.append(ControlCheck(
        "Compliance regimes enabled",
        ", ".join(_regimes.REGIMES[k].name for k in known) or "(none configured)",
        "active" if known else "action_needed",
        "regimes compile to the governance policy (strictest-wins)" if known
        else "set [finance] regimes = [\"sox\", \"gaap\", ...]",
        framework="finance",
    ))
    return checks


def render_status_text(checks: list[ControlCheck]) -> str:
    width = max((len(c.control) for c in checks), default=10)
    label = {"active": "active", "action_needed": "ACTION NEEDED", "available": "on-demand"}
    rows = []
    for c in checks:
        rows.append(f"  [{label.get(c.status, c.status):>13}]  {c.control:<{width}}  {c.regulation}")
        rows.append(f"  {'':>13}    {'':<{width}}  -> {c.detail}")
    active = sum(1 for c in checks if c.status == "active")
    needed = sum(1 for c in checks if c.status == "action_needed")
    head = "Finance control coverage"
    return "\n".join([head, "=" * len(head), "", *rows, "",
                      f"{active} active, {needed} need action, {len(checks)} total",
                      "", FINANCE_DISCLAIMER])


def render_status_json(checks: list[ControlCheck]) -> str:
    import json
    from dataclasses import asdict
    return json.dumps({
        "controls": [asdict(c) for c in checks],
        "summary": {"active": sum(1 for c in checks if c.status == "active"),
                    "action_needed": sum(1 for c in checks if c.status == "action_needed"),
                    "total": len(checks)},
        "disclaimer": FINANCE_DISCLAIMER,
    }, indent=2)


__all__ = ["finance_status", "render_status_text", "render_status_json", "FINANCE_DISCLAIMER"]
