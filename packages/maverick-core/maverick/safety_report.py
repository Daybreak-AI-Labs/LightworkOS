"""Annual safety report generator.

Aggregates what THIS deployment actually recorded over a reporting period into
an honest markdown report: shield blocks, capability denials, killswitch
activations, consent decisions, and erasure requests from the audit trail,
plus red-team and verifier-calibration results when those files exist. Every
section states its source; a section with no data says so explicitly -- nothing
is estimated or fabricated, and a "Data available" section up front lists
exactly which sources had records.

Offline and deterministic: callers (and tests) inject the audit ``events``
rows and the calibration/red-team file paths; the defaults read the local
audit day-files (fail-soft, like every audit reader) and the standard
``calibration_verdict.json`` / ``redteam_results.json`` locations.

CLI (the generator is operator-run; it is deliberately not a ``maverick``
subcommand)::

    python -m maverick.safety_report --since 2026-01-01 --until 2026-12-31 -o report.md

With no flags the period is the 365 days ending today (UTC).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_DATE_FMT = "%Y-%m-%d"
_MAX_VERBATIM = 2000  # cap for embedded result-file excerpts

# Audit event kinds the report aggregates (count-only; payload text is never
# echoed -- audit rows can contain attacker-influenced strings).
_KINDS = ("shield_block", "capability_denied", "halt", "consent_result", "erase")


def _parse_day(day: str) -> _dt.datetime:
    return _dt.datetime.strptime(day, _DATE_FMT).replace(tzinfo=_dt.timezone.utc)


def _finite_ts(value: Any) -> float | None:
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    return ts if math.isfinite(ts) else None


def _safe_label(value: Any, default: str = "unknown") -> str:
    """A short, identifier-ish label for grouping; anything else is bucketed
    as ``other`` so report labels can't carry injected prose."""
    if not isinstance(value, str) or not value.strip():
        return default
    label = value.strip()
    if len(label) > 48 or not all(c.isalnum() or c in "._:/@-" for c in label):
        return "other"
    return label


def collect(events: Iterable[dict], start_ts: float, end_ts: float) -> dict:
    """Tally the safety-relevant audit events inside [start_ts, end_ts).

    Returns counters per kind plus bookkeeping (rows scanned / in period /
    excluded for missing-or-out-of-range timestamps). Malformed rows are
    skipped, never guessed at.
    """
    stats: dict[str, Any] = {
        "scanned": 0, "in_period": 0, "excluded": 0,
        "shield_blocks": 0, "shield_by_stage": Counter(),
        "capability_denied": 0, "denied_tools": Counter(),
        "halts": 0, "halt_sources": Counter(),
        "consent": Counter(),
        "erasures": 0,
    }
    for ev in events:
        if not isinstance(ev, dict):
            continue
        stats["scanned"] += 1
        kind = ev.get("kind")
        if not isinstance(kind, str) or kind not in _KINDS:
            continue
        ts = _finite_ts(ev.get("ts"))
        if ts is None or not (start_ts <= ts < end_ts):
            stats["excluded"] += 1
            continue
        stats["in_period"] += 1
        if kind == "shield_block":
            stats["shield_blocks"] += 1
            stats["shield_by_stage"][_safe_label(ev.get("stage"))] += 1
        elif kind == "capability_denied":
            stats["capability_denied"] += 1
            stats["denied_tools"][_safe_label(ev.get("tool"))] += 1
        elif kind == "halt":
            stats["halts"] += 1
            stats["halt_sources"][_safe_label(ev.get("source"))] += 1
        elif kind == "consent_result":
            decision = _safe_label(ev.get("decision"))
            if decision in ("approve", "deny", "timeout"):
                stats["consent"][decision] += 1
            else:
                stats["consent"]["other"] += 1
        elif kind == "erase":
            stats["erasures"] += 1
    return stats


def _read_json_file(path: Path | str | None) -> dict | None:
    """Fail-open read of an optional results file: missing/corrupt -> None."""
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _default_calibration_path() -> Path:
    from .calibration import VERDICT_PATH

    return VERDICT_PATH


def _default_redteam_path() -> Path:
    from .paths import data_dir

    return data_dir("redteam_results.json")


def _counter_lines(counter: Counter, label: str) -> list[str]:
    return [f"  - {label} `{name}`: {n}" for name, n in counter.most_common()]


def _verbatim(data: dict) -> str:
    text = json.dumps(data, sort_keys=True, indent=2, default=str)
    if len(text) > _MAX_VERBATIM:
        text = text[:_MAX_VERBATIM] + "\n... (truncated)"
    return f"```json\n{text}\n```"


def _availability_lines(stats: dict, calibration: dict | None, redteam: dict | None) -> list[str]:
    audit_available = stats["scanned"] > 0
    sources = [
        ("audit events", audit_available,
         f"{stats['scanned']} row(s) scanned, {stats['in_period']} safety event(s) in period"),
        ("verifier calibration verdict", calibration is not None, "calibration_verdict.json"),
        ("red-team results", redteam is not None, "redteam_results.json"),
    ]
    lines = ["## Data available", ""]
    for name, present, detail in sources:
        mark = "available" if present else "not available"
        lines.append(f"- {name}: **{mark}**" + (f" ({detail})" if present else ""))
    if audit_available and stats["excluded"]:
        lines.append(
            f"- note: {stats['excluded']} safety event(s) had timestamps outside the "
            "period (or none) and were excluded"
        )
    return lines


def _count_section(title: str, count: int, recorded: str, empty: str,
                   breakdown: list[str]) -> list[str]:
    lines = ["", f"## {title}", ""]
    if count:
        lines.append(f"{count} {recorded} recorded.")
        lines += breakdown
    else:
        lines.append(f"No {empty} recorded in this period.")
    return lines


def _consent_breakdown(consent: Counter) -> list[str]:
    return [
        f"  - {decision}: {consent[decision]}"
        for decision in ("approve", "deny", "timeout", "other")
        if consent[decision]
    ]


def _results_lines(calibration: dict | None, redteam: dict | None) -> list[str]:
    lines = ["", "## Red-team & calibration", ""]
    if calibration is None and redteam is None:
        lines.append("No red-team or calibration results were available on this deployment.")
        return lines
    if calibration is not None:
        lines += ["Verifier calibration verdict (verbatim):", "", _verbatim(calibration), ""]
    else:
        lines.append("No calibration verdict available.")
    if redteam is not None:
        lines += ["Red-team results (verbatim):", "", _verbatim(redteam)]
    else:
        lines.append("No red-team results available.")
    return lines


def generate_report(
    *,
    since: str,
    until: str,
    events: Iterable[dict] | None = None,
    calibration_path: Path | str | None = None,
    redteam_path: Path | str | None = None,
    tenant: str | None = None,
) -> str:
    """Render the safety report (markdown) for the inclusive [since, until]
    period (UTC ``YYYY-MM-DD`` dates).

    ``events`` / ``calibration_path`` / ``redteam_path`` are the injected
    seams. When ``events`` is None the deployment's audit day-files for the
    window are read (fail-soft); the result paths default to the standard
    locations and are simply reported as unavailable when absent.
    """
    start = _parse_day(since)
    end = _parse_day(until) + _dt.timedelta(days=1)  # inclusive end date
    if end <= start:
        raise ValueError(f"empty reporting period: since={since!r} until={until!r}")

    if events is None:
        try:
            from .audit.export import iter_audit_events

            events = list(iter_audit_events(since=since, until=until, tenant=tenant))
        except Exception:  # noqa: BLE001 -- a broken audit dir reads as no data
            events = []

    stats = collect(events, start.timestamp(), end.timestamp())
    calibration = _read_json_file(
        calibration_path if calibration_path is not None else _default_calibration_path()
    )
    redteam = _read_json_file(
        redteam_path if redteam_path is not None else _default_redteam_path()
    )

    lines = [
        "# Lightwork safety report",
        "",
        "## Reporting period",
        "",
        f"- **From:** {since} 00:00 UTC (inclusive)",
        f"- **To:** {until} 23:59 UTC (inclusive)",
        "",
        "This report aggregates only what this deployment recorded. Sections",
        "with no recorded data say so; no figures are estimated or fabricated.",
        "",
    ]
    lines += _availability_lines(stats, calibration, redteam)
    lines += _count_section(
        "Shield blocks", stats["shield_blocks"], "block(s)", "shield blocks",
        _counter_lines(stats["shield_by_stage"], "stage"),
    )
    lines += _count_section(
        "Capability denials", stats["capability_denied"], "denial(s)",
        "capability denials", _counter_lines(stats["denied_tools"], "tool"),
    )
    lines += _count_section(
        "Killswitch activations", stats["halts"], "activation(s)",
        "killswitch activations", _counter_lines(stats["halt_sources"], "source"),
    )
    lines += _count_section(
        "Consent decisions", sum(stats["consent"].values()), "decision(s)",
        "consent decisions", _consent_breakdown(stats["consent"]),
    )
    lines += _count_section(
        "Erasure requests", stats["erasures"],
        "erasure request(s) (GDPR Art. 17)", "erasure requests", [],
    )
    lines += _results_lines(calibration, redteam)
    lines += [
        "",
        "---",
        "Generated by `python -m maverick.safety_report` from local deployment records.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    today = _dt.datetime.now(_dt.timezone.utc).date()
    parser = argparse.ArgumentParser(
        prog="python -m maverick.safety_report",
        description="Generate the (annual) deployment safety report from local records.",
    )
    parser.add_argument(
        "--since", default=(today - _dt.timedelta(days=365)).strftime(_DATE_FMT),
        help="period start, YYYY-MM-DD UTC (default: 365 days ago)",
    )
    parser.add_argument(
        "--until", default=today.strftime(_DATE_FMT),
        help="period end, YYYY-MM-DD UTC, inclusive (default: today)",
    )
    parser.add_argument("--tenant", default=None, help="tenant id (default: active/none)")
    parser.add_argument("-o", "--out", default=None, help="write to this file instead of stdout")
    args = parser.parse_args(argv)

    try:
        report = generate_report(since=args.since, until=args.until, tenant=args.tenant)
    except ValueError as e:
        print(f"safety report failed: {e}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":  # pragma: no cover -- exercised via main() in tests
    raise SystemExit(main())


__all__ = ["collect", "generate_report", "main"]
