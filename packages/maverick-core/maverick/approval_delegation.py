"""Select suggested reviewers for matching approval requests.

Rules name a suggested reviewer based on risk and optional tool glob. The
suggestion may be included in approval detail; it does not restrict who can decide,
route notifications, or satisfy a separation-of-duties requirement. Other
authorized reviewers retain their existing authority. ``load_rules`` reads
``[approval] delegation``; with no rules, ``route`` returns ``None``.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

_VALID_RISK = ("low", "medium", "high", "critical")


def _rank(level: str) -> int:
    """Order an approval risk level (low < medium < high < critical)."""
    try:
        return _VALID_RISK.index((level or "").strip().lower())
    except ValueError:
        return 0  # unknown == lowest


@dataclass(frozen=True)
class DelegationRule:
    delegate_to: str
    min_risk: str = ""          # "" = any risk
    tool_glob: str = "*"        # fnmatch over the tool name

    def matches(self, *, risk: str, tool: str) -> bool:
        if self.min_risk and _rank(risk) < _rank(self.min_risk):
            return False
        return fnmatch(tool or "", self.tool_glob or "*")


def parse_rules(raw: list[dict]) -> list[DelegationRule]:
    """Build rules from a list of ``{delegate_to, min_risk?, tool_glob?}`` dicts.

    Rules are evaluated in order; malformed entries (no ``delegate_to``, or a
    ``min_risk`` outside the known levels) are skipped rather than raising.
    """
    out: list[DelegationRule] = []
    for r in raw or []:
        if not isinstance(r, dict):
            continue
        delegate = str(r.get("delegate_to") or "").strip()
        if not delegate:
            continue
        min_risk = str(r.get("min_risk") or "").strip().lower()
        if min_risk and min_risk not in _VALID_RISK:
            continue
        out.append(DelegationRule(
            delegate_to=delegate,
            min_risk=min_risk,
            tool_glob=str(r.get("tool_glob") or "*"),
        ))
    return out


def load_rules() -> list[DelegationRule]:
    """Rules from ``[approval] delegation`` in config (empty when unset)."""
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("approval") or {}
        return parse_rules(cfg.get("delegation") or [])
    except Exception:  # pragma: no cover -- config never blocks approvals
        return []


def route(approval: dict, rules: list[DelegationRule] | None = None) -> str | None:
    """Return the suggested reviewer (first matching rule), or ``None``.

    ``approval`` is a dict with ``risk`` (low/medium/high/critical) and ``tool``.
    The returned value is advisory and never changes decision authority.
    """
    rules = rules if rules is not None else load_rules()
    risk = str(approval.get("risk") or "low").strip().lower()
    if risk not in _VALID_RISK:
        risk = "low"
    tool = str(approval.get("tool") or "")
    for rule in rules:
        if rule.matches(risk=risk, tool=tool):
            return rule.delegate_to
    return None


__all__ = ["DelegationRule", "parse_rules", "load_rules", "route"]
