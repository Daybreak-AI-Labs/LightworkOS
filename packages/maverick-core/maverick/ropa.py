"""GDPR Article 30 — Records of Processing Activities (ROPA) generator.

Article 30 requires a data controller to maintain a record of its processing
activities. Lightwork already *knows* the technical half of that record from its
own schema and configuration: what categories of personal data it stores,
whether that data can leave the deployment boundary (the egress lock), how long
it is kept (retention), and which Art. 32 security measures are active (read
straight from the compliance report). This module assembles those into a
pre-filled Art. 30 record and leaves the organizational fields a controller must
own — identity, DPO, lawful basis, specific purposes — as explicit placeholders.

It is a *scaffold*, not a completed record: the same control-coverage-not-legal-
attestation line as ``maverick compliance``. Fail-soft and import-light like
:mod:`maverick.soc2` — it never raises, so it can be run against any deployment.

Surfaced as ``maverick ropa``.
"""
from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

# Organizational fields the software cannot know — the controller fills them in.
FILL_IN = "<TO BE COMPLETED BY THE DATA CONTROLLER>"

ROPA_DISCLAIMER = (
    "Pre-filled Art. 30 scaffold derived from this deployment's configuration and "
    "schema -- not a completed record or a legal attestation. The controller must "
    "complete the organizational fields (identity, DPO, lawful basis, specific "
    "purposes) and have a DPO / qualified counsel review it."
)

# The personal-data categories Lightwork persists, mapped to where they live —
# the inventory half of Art. 30(1)(c). A stable description of the schema.
_DATA_CATEGORIES: tuple[dict[str, str], ...] = (
    {
        "category": "Channel conversation content",
        "examples": "messages exchanged with channel users (may contain any "
                    "personal data a user discloses)",
        "store": "world DB: turns.content",
    },
    {
        "category": "Derived facts / memory",
        "examples": "facts the agent persists about users or tasks",
        "store": "world DB: facts.value; cross-session memory store",
    },
    {
        "category": "Agent task records",
        "examples": "goal descriptions, per-goal message logs, clarifying questions",
        "store": "world DB: goals, messages.content, questions",
    },
    {
        "category": "Online identifiers",
        "examples": "channel name + user_id used to route conversations",
        "store": "world DB: conversations(channel, user_id)",
    },
    {
        "category": "Processing records",
        "examples": "audit events (secrets/identifiers redacted before write)",
        "store": "~/.maverick/audit/*.ndjson",
    },
)


def _safe(fn, default):
    """Run ``fn``; on any error return ``default`` (fail-soft, as in soc2.py)."""
    try:
        return fn()
    except BaseException:  # noqa: BLE001 -- a ROPA snapshot must never crash
        return default


def _enterprise_on() -> bool:
    from .enterprise import enterprise_enabled
    return enterprise_enabled()


def _retention_cfg() -> dict[str, Any]:
    from .config import load_config

    cfg = load_config() or {}
    if not isinstance(cfg, Mapping):
        return {}

    retention = cfg.get("retention") or {}
    if not isinstance(retention, Mapping):
        return {}
    return dict(retention)


def _active_security_measures() -> list[str]:
    """The deployment's active controls (Art. 32 TOMs) from the compliance report."""
    from .compliance import compliance_report
    return [
        f"{c.control} ({c.regulation})"
        for c in compliance_report()
        if c.status == "active"
    ]


def generate_ropa() -> dict[str, Any]:
    """Assemble a pre-filled Art. 30 ROPA from this deployment. Never raises."""
    enterprise = _safe(_enterprise_on, False)

    # Recipients + international transfers turn entirely on the egress lock.
    if enterprise:
        recipients = [
            "Self-hosted / local LLM only (egress lock on) -- no third-party LLM "
            "processor receives prompt content"
        ]
        transfers = (
            "None via the LLM path: enterprise mode pins inference to local / "
            "self-hosted models, so prompt content does not leave the deployment "
            "boundary."
        )
    else:
        recipients = [
            "Configured LLM provider(s) -- may be a third-party processor (cloud API)"
        ]
        transfers = (
            "Possible: with the egress lock off, prompt content is sent to the "
            "configured LLM provider, which may process it outside the EU/EEA. "
            "Enable [enterprise] mode to pin inference on-box, or put a Chapter V "
            "transfer mechanism (adequacy decision / SCCs) in place."
        )

    retention = _safe(_retention_cfg, {})
    retention_desc = (
        "; ".join(f"{k} = {v}" for k, v in retention.items())
        if retention
        else f"{FILL_IN} (no [retention] policy configured -- data is kept indefinitely)"
    )

    return {
        "record_type": "GDPR Article 30(1) record of processing activities",
        "generated_at": time.time(),
        "controller": {
            "name": FILL_IN,
            "contact": FILL_IN,
            "dpo_contact": FILL_IN,
        },
        "processing": {
            "purposes": f"{FILL_IN} (the service the agent is deployed to provide)",
            "lawful_basis": f"{FILL_IN} (Art. 6 -- e.g. consent / contract / "
                            "legitimate interests)",
            "data_subjects": ["Channel users who interact with the agent"],
            "personal_data_categories": [dict(c) for c in _DATA_CATEGORIES],
            "special_categories": f"{FILL_IN} (Art. 9 -- only if the agent may "
                                  "process health / biometric / etc. data)",
        },
        "recipients": recipients,
        "international_transfers": transfers,
        "retention": retention_desc,
        "security_measures": _safe(_active_security_measures, []),
        "disclaimer": ROPA_DISCLAIMER,
    }


def render_ropa_json(record: dict[str, Any]) -> str:
    import json
    return json.dumps(record, indent=2, default=str)


def render_ropa_text(record: dict[str, Any]) -> str:
    head = "GDPR Art. 30 — Record of Processing Activities (scaffold)"
    lines = [head, "=" * len(head), ""]

    ctrl = record["controller"]
    lines += [
        "Controller",
        f"  Name:        {ctrl['name']}",
        f"  Contact:     {ctrl['contact']}",
        f"  DPO contact: {ctrl['dpo_contact']}",
        "",
    ]

    proc = record["processing"]
    lines += [
        "Processing",
        f"  Purposes:      {proc['purposes']}",
        f"  Lawful basis:  {proc['lawful_basis']}",
        f"  Data subjects: {', '.join(proc['data_subjects'])}",
        f"  Special cat.:  {proc['special_categories']}",
        "",
        "Personal-data categories",
    ]
    for c in proc["personal_data_categories"]:
        lines.append(f"  - {c['category']}: {c['examples']}")
        lines.append(f"      stored in: {c['store']}")
    lines.append("")

    lines += [
        "Recipients",
        *(f"  - {r}" for r in record["recipients"]),
        "",
        "International transfers (Chapter V)",
        f"  {record['international_transfers']}",
        "",
        f"Retention (Art. 5(1)(e)): {record['retention']}",
        "",
        "Security measures in place (Art. 32, active in this deployment)",
    ]
    measures = record["security_measures"]
    if measures:
        lines += (f"  - {m}" for m in measures)
    else:
        lines.append("  (none detected -- enable controls; see 'maverick compliance')")
    lines += ["", record["disclaimer"]]
    return "\n".join(lines)


__all__ = [
    "FILL_IN",
    "ROPA_DISCLAIMER",
    "generate_ropa",
    "render_ropa_json",
    "render_ropa_text",
]
