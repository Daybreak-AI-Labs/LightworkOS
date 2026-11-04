"""Finance platform controls — the governance wrapper for the CFO-office suite.

The product is *not* the finance agents (competent finance models are
commodity) — it is the **governance wrapper**: segregation of duties, maker-checker / dollar-threshold approvals, and
a tamper-evident book of record, enforced by the platform. This subpackage holds
the finance-specific platform pieces that sit on top of the already-shipped
primitives (``governance``, ``capability``, ``audit``, ``assessment``):

  * :mod:`maverick.finance.sod_linter` — segregation-of-duties conflict linter
    over the domain packs (the cardinal control, §2.1).
  * :mod:`maverick.finance.regimes` — finance compliance-regime packs (SOX, COSO,
    GAAP/IFRS, PCI, GLBA, AML, SEC, IRS) compiling to a governance ``Policy`` (§5).
  * :mod:`maverick.finance.profile` — the Finance Operating Profile compiler
    (framework, materiality, automation ladder with hard floors, action-time
    separation of duties, fail-closed approvals; §3.8).
  * :mod:`maverick.finance.status` — the ``finance status`` posture report (§5).
  * :mod:`maverick.finance.regulatory_change` — cited deterministic feed diffs.
  * :mod:`maverick.finance.licensing` — versioned 50-state source-routing packs.
  * :mod:`maverick.finance.anomaly_engine` — explainable finance anomaly rules.
  * :mod:`maverick.finance.aml_screening` — governed list and four-eyes cases.
  * :mod:`maverick.finance.control_testing` — scheduled Security/GRC bridge.
"""
from __future__ import annotations

__all__ = [
    "aml_screening",
    "anomaly_engine",
    "control_testing",
    "licensing",
    "operations_health",
    "profile",
    "regimes",
    "regulatory_change",
    "sod_linter",
    "status",
]
