"""Sanctions / watchlist screening — gate every payment + vendor-onboarding path.

A name (payee, vendor, counterparty) is screened before money moves or a vendor
is onboarded (finance-agent-suite §2.6). When finance operations are enabled,
the tool delegates to the governed AML module: versioned cited lists, the
typo-tolerant matching ladder, a durable case, and four-eyes disposition. The
legacy newline/JSON matcher remains available only when that module is disabled.

A hit does **not** auto-block in code — it raises a finding the payment/vendor
flow routes to a human (an OFAC determination is a human act). This is intentional
defence-in-depth, not a substitute for a licensed screening provider.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from ..paths import data_dir
from . import Tool

_DEFAULT_LIST = data_dir("screening", "sdn.txt")
_PUNCT = re.compile(r"[^a-z0-9\s]")
_WS = re.compile(r"\s+")


def normalize(name: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace for stable comparison."""
    s = _PUNCT.sub(" ", (name or "").lower())
    return _WS.sub(" ", s).strip()


def _tokens(name: str) -> set[str]:
    return {t for t in normalize(name).split() if len(t) > 1}


def _score(query: str, candidate: str) -> float:
    """0–1 match score: 1.0 exact (normalised), else token Jaccard."""
    nq, nc = normalize(query), normalize(candidate)
    if not nq or not nc:
        return 0.0
    if nq == nc:
        return 1.0
    tq, tc = _tokens(query), _tokens(candidate)
    if not tq or not tc:
        return 0.0
    inter = len(tq & tc)
    return inter / len(tq | tc)


def _validate_threshold(value: Any) -> float:
    """Return a finite screening threshold in the safe ``(0, 1]`` range."""
    threshold = 0.85 if value is None else float(value)
    if not math.isfinite(threshold) or threshold <= 0.0 or threshold > 1.0:
        raise ValueError("threshold must be a finite number greater than 0 and no more than 1")
    return threshold


def screen(name: str, sdn_names, *, threshold: float = 0.85) -> dict:
    """Screen ``name`` against ``sdn_names``; return ``{match, hits, screened}``.

    ``hits`` are ``{name, score}`` at or above ``threshold``, highest first.
    """
    threshold = _validate_threshold(threshold)
    hits = []
    for cand in sdn_names or []:
        s = _score(name, str(cand))
        if s >= threshold:
            hits.append({"name": str(cand), "score": round(s, 3)})
    hits.sort(key=lambda h: -h["score"])
    return {"match": bool(hits), "hits": hits, "screened": str(name)}


def load_list(path: str | Path) -> list[str]:
    """Load names from a newline list or a JSON array / ``{"names": [...]}``."""
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            return [str(x) for x in data]
        if isinstance(data, dict) and isinstance(data.get("names"), list):
            return [str(x) for x in data["names"]]
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _list_path() -> Path:
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("screening") or {}
        sp = str(cfg.get("sdn_path") or "").strip()
        if sp:
            return Path(sp).expanduser()
    except Exception:  # pragma: no cover -- config never blocks screening
        pass
    return _DEFAULT_LIST


_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"], "default": "check"},
        "name": {"type": "string", "description": "the payee / vendor / counterparty to screen"},
        "threshold": {
            "type": "number",
            "exclusiveMinimum": 0,
            "maximum": 1,
            "description": (
                "legacy matcher threshold >0–1 (default 0.85); governed "
                "screening uses its fixed, versioned match ladder"
            ),
        },
        "subject_ref": {
            "type": "string",
            "maxLength": 256,
            "description": "optional payment, vendor, or counterparty reference",
        },
    },
    "required": ["name"],
}


def _run(args: dict[str, Any]) -> str:
    name = str(args.get("name") or "").strip()
    if not name:
        return "ERROR: name is required"
    try:
        threshold = _validate_threshold(args.get("threshold"))
    except (TypeError, ValueError):
        return "ERROR: threshold must be a finite number greater than 0 and no more than 1"
    from ..finance import aml_screening

    if aml_screening.enabled():
        if args.get("threshold") is not None and threshold != 0.85:
            return (
                "ERROR: threshold overrides are not allowed while governed sanctions "
                "screening is enabled"
            )
        try:
            from ..connections import current_principal

            actor = str(current_principal() or "agent:screen_sanctions")
            result = aml_screening.screen_subject(
                name,
                screened_by=actor,
                subject_ref=str(args.get("subject_ref") or "").strip()[:256],
            )
        except (
            aml_screening.ScreeningIncompleteError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return f"ERROR: governed sanctions screening is incomplete: {exc}"
        except Exception:
            return "ERROR: governed sanctions screening failed safely"
        lists = result.get("screened_lists") or []
        if not result.get("match"):
            return (
                f"CLEAR (governed): {name!r} produced no candidate match across "
                f"{len(lists)} current cited list source(s). This is a screening "
                "result, not an OFAC determination."
            )
        case = result.get("case") or {}
        lines = [
            f"POSSIBLE SANCTIONS HIT for {name!r} — governed case "
            f"{case.get('id', '<pending>')} requires independent human disposition "
            "(do not proceed):"
        ]
        for hit in (result.get("hits") or [])[:10]:
            citation = hit.get("citation") or {}
            lines.append(
                "  - "
                f"{hit.get('entry_name', '<unknown>')} "
                f"(score {hit.get('score')}, {hit.get('match_method')}; "
                f"{citation.get('source_name', 'cited list')} "
                f"{citation.get('list_version', '')})"
            )
        return "\n".join(lines)

    path = _list_path()
    sdn = load_list(path)
    if not sdn:
        return (f"ERROR: no sanctions list found at {path}. Set [screening] "
                "sdn_path to an OFAC SDN export (newline or JSON name list).")
    result = screen(name, sdn, threshold=threshold)
    if not result["match"]:
        return f"CLEAR: {name!r} not found on the sanctions list ({len(sdn)} names)."
    lines = [f"POSSIBLE SANCTIONS HIT for {name!r} — route to a human for an OFAC "
             "determination (do not proceed):"]
    lines += [f"  - {h['name']} (score {h['score']})" for h in result["hits"][:10]]
    return "\n".join(lines)


def sanctions_screen() -> Tool:
    return Tool(
        name="screen_sanctions",
        description=(
            "Screen a payee / vendor / counterparty name against a sanctions list "
            "(OFAC SDN or operator-supplied). With finance operations enabled, uses "
            "governed cited lists, typo-tolerant matching, and a four-eyes case; "
            "otherwise uses the legacy local list. Never auto-proceeds on a hit."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=False,
    )


__all__ = ["normalize", "screen", "load_list", "sanctions_screen"]
