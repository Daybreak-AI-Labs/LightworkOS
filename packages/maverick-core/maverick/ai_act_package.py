"""EU AI Act conformance package generator.

Article 11 / Annex IV require a provider's **technical documentation**: the
system's description, risk classification, human-oversight measures,
logging/record-keeping, accuracy/robustness evidence, and transparency
measures. This generator assembles that package from what the deployment
*actually has* — the recorded posture, not aspirations:

* **Classification** — the existing Annex III self-assessment
  (:func:`maverick.ai_act.assess_ai_act`).
* **Human oversight (Art. 14)** — the live consent mode, approval-delegation
  rules, capability enforcement, killswitch presence.
* **Logging & record-keeping (Art. 12)** — audit-chain signing posture,
  retention configuration, world-model event recording.
* **Accuracy & robustness (Art. 15)** — the red-team gate result, shield
  calibration, the reliability certificate when present.
* **Transparency (Art. 50)** — the effective first-turn AI disclosure setting,
  including an operator's explicit opt-out.

Sections without evidence say "no evidence recorded" — nothing fabricated;
each section names its source so an auditor can verify. Output is markdown
(``python -m maverick.ai_act_package``) suitable as the skeleton the
provider's compliance owner completes with organizational context.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def _classification() -> dict:
    from .ai_act import assess_ai_act
    return _safe(assess_ai_act, {"error": "assessment unavailable"})


def _oversight() -> dict:
    import os
    out: dict[str, Any] = {}
    # Mirror the real resolver (maverick.safety.consent._resolve_mode) rather
    # than guessing a posture: the system's actual default is "auto-approve"
    # (low/medium-risk actions run with no human in the loop). Hardcoding
    # "ask (default)" here told an auditor human oversight was in place when the
    # resolver -- and compliance_report() -- say otherwise.
    out["consent_mode"] = os.environ.get("MAVERICK_CONSENT_MODE") or _safe(
        lambda: (__import__("maverick.config", fromlist=["load_config"])
                 .load_config() or {}).get("safety", {}).get("consent_mode"),
        None) or _safe(
        lambda: (__import__("maverick.safety.consent", fromlist=["_resolve_mode"])
                 ._resolve_mode() + " (default)"),
        None) or "auto-approve (default)"
    out["capability_enforcement"] = _safe(
        lambda: __import__("maverick.capability", fromlist=["capability_enforced"])
        .capability_enforced(), False)
    from .paths import maverick_home
    out["killswitch_path"] = str(maverick_home() / "HALT")
    # The delegation rules live in ``[approval] delegation`` (the dashboard's
    # "Who reviews which approvals"); the older ``[approval_delegation]``
    # table name still counts.
    out["approval_delegation_configured"] = _safe(
        lambda: bool(__import__("maverick.approval_delegation", fromlist=["load_rules"])
                     .load_rules()), False) or _safe(
        lambda: bool((__import__("maverick.config", fromlist=["load_config"])
                      .load_config() or {}).get("approval_delegation")), False)
    return out


def _logging_posture() -> dict:
    out: dict[str, Any] = {}
    # Probe the real signing path rather than inferring from config, for the same
    # reason _oversight() mirrors the real consent resolver. `[audit] sign` is one
    # of five inputs writer._resolve_signing consults (compliance floor > explicit
    # arg > MAVERICK_AUDIT_SIGN > [audit] sign > secure-by-default), so reading the
    # key alone reported "audit chain signing: no" on a default install while
    # compliance_report() -- which probes -- reported the same control active. Two
    # compliance artifacts from one deployment disagreeing about one control is
    # worse for an auditor than either answer alone.
    out["audit_signing"] = _safe(
        lambda: bool(__import__("maverick.deployment",
                                fromlist=["_verify_audit_signing"])
                     ._verify_audit_signing().passed), False)
    out["retention_configured"] = _safe(
        lambda: bool((__import__("maverick.config", fromlist=["load_config"])
                      .load_config() or {}).get("retention")), False)
    from .paths import data_dir
    audit_dir = _safe(lambda: data_dir("audit"), None)
    out["audit_dir"] = str(audit_dir) if audit_dir else "unavailable"
    out["audit_days_present"] = _safe(
        lambda: len(list(Path(audit_dir).glob("*.ndjson"))) if audit_dir else 0, 0)
    return out


def _evidence() -> dict:
    """Accuracy/robustness evidence files, when the deployment has them."""
    out: dict[str, Any] = {}
    from .safety_report import _default_calibration_path, _default_redteam_path
    for name, path_fn in (("redteam", _default_redteam_path),
                          ("calibration", _default_calibration_path)):
        path = _safe(path_fn, None)
        if path and Path(path).exists():
            try:
                out[name] = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                out[name] = {"present": True, "unreadable": True}
        else:
            out[name] = None
    from .paths import data_dir
    cert = _safe(lambda: data_dir("reliability_cert.json"), None)
    if cert and Path(cert).exists():
        try:
            out["reliability_cert"] = json.loads(Path(cert).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out["reliability_cert"] = {"present": True, "unreadable": True}
    else:
        out["reliability_cert"] = None
    return out


def _transparency() -> dict:
    """Report the same effective disclosure setting as the channel server."""
    from .compliance import _UNSET, _custom_disclosure

    disclosure = _custom_disclosure()
    enabled = disclosure is _UNSET or bool(disclosure and str(disclosure).strip())
    if disclosure is _UNSET:
        detail = "enabled by default; the channel server applies first-turn AI disclosure"
    elif enabled:
        detail = "enabled with operator text; the channel server applies first-turn AI disclosure"
    else:
        detail = "disabled by operator; no first-turn AI disclosure is configured"
    return {
        "first_turn_disclosure_enabled": enabled,
        "first_turn_disclosure": detail,
    }


def build_package() -> dict:
    return {
        "kind": "ai-act-technical-documentation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": _classification(),
        "human_oversight": _oversight(),
        "logging": _logging_posture(),
        "evidence": _evidence(),
        "transparency": _transparency(),
    }


def _yesno(v: Any) -> str:
    return "yes" if v else "no"


def render_markdown(pkg: dict) -> str:
    cls = pkg["classification"]
    ov = pkg["human_oversight"]
    lg = pkg["logging"]
    ev = pkg["evidence"]
    lines = [
        "# EU AI Act — technical documentation package",
        "",
        f"_Generated {pkg['generated_at']} from the deployment's recorded "
        "posture. Sections without evidence say so; the provider's compliance "
        "owner completes organizational context (intended purpose, provider "
        "identity, conformity-assessment route)._",
        "",
        "## 1. Risk classification (Annex III self-assessment)",
        "```json",
        json.dumps(cls, indent=2, sort_keys=True, default=str),
        "```",
        "",
        "## 2. Human oversight (Art. 14)",
        f"- consent mode: {ov['consent_mode']}",
        f"- capability enforcement: {_yesno(ov['capability_enforcement'])}",
        f"- approval delegation rules configured: "
        f"{_yesno(ov['approval_delegation_configured'])}",
        f"- killswitch: {ov['killswitch_path']} (file-based hard stop)",
        "",
        "## 3. Logging & record-keeping (Art. 12)",
        f"- audit chain signing: {_yesno(lg['audit_signing'])}",
        f"- retention rules configured: {_yesno(lg['retention_configured'])}",
        f"- audit day-files present: {lg['audit_days_present']} "
        f"(at {lg['audit_dir']})",
        "",
        "## 4. Accuracy & robustness evidence (Art. 15)",
    ]
    for name, label in (("redteam", "red-team gate"),
                        ("calibration", "shield calibration"),
                        ("reliability_cert", "reliability certificate")):
        val = ev.get(name)
        if val is None:
            lines.append(f"- {label}: no evidence recorded")
        else:
            lines.append(f"- {label}: present")
            lines.append("```json")
            lines.append(json.dumps(val, indent=2, sort_keys=True, default=str)[:2000])
            lines.append("```")
    lines += [
        "",
        "## 5. Transparency (Art. 50)",
        f"- first-turn AI disclosure: {pkg['transparency']['first_turn_disclosure']}",
        "",
        "## 6. Completed by the provider",
        "- [ ] Intended purpose & deployment context",
        "- [ ] Provider identity & authorized representative",
        "- [ ] Conformity-assessment route & declaration",
        "- [ ] Post-market monitoring plan",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.ai_act_package")
    p.add_argument("-o", "--out", default=None, help="write markdown here")
    args = p.parse_args(argv)
    md = render_markdown(build_package())
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"written: {args.out}")
    else:
        print(md)
    return 0


__all__ = ["build_package", "render_markdown"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
