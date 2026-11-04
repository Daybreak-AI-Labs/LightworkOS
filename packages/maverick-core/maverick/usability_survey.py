"""Optional in-product usability survey: SUS each quarter, one ease question after top tasks.

Off unless ``[analytics] usability_survey = true``. When on, each signed-in
person is offered the standard 10-item System Usability Scale (SUS) at most
once a quarter; one "Not now" hides it for the rest of that quarter. After a
person finishes one of the :data:`TOP_TASKS` they may be asked the Single Ease
Question (SEQ, 1-7) for that task, again at most once a quarter per task.

Privacy: answers stay in this installation (``~/.maverick/usability-survey.json``,
0600, locked) and are never sent anywhere. A stored answer carries the role the
person chose for themselves (or "not given"), never their name or account. To
stop asking the same person twice, the store keeps a one-way keyed hash of the
account next to the quarter it was asked in; reports never read it.

Scoring follows Brooke (1996) for SUS and Sauro & Dumas (2009) for the SEQ;
see ``docs/usability-research.md``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
MIN_ANSWERS = 5  # below this, results say "not enough answers yet"

# The ten SUS statements as published by Brooke (1996), with "the system"
# replaced by the product name, as the method allows. Answers: 1 = strongly
# disagree ... 5 = strongly agree.
SUS_ITEMS: tuple[str, ...] = (
    "I think that I would like to use Lightwork frequently.",
    "I found Lightwork unnecessarily complex.",
    "I thought Lightwork was easy to use.",
    "I think that I would need the support of a technical person to be able to use Lightwork.",
    "I found the various functions in Lightwork were well integrated.",
    "I thought there was too much inconsistency in Lightwork.",
    "I would imagine that most people would learn to use Lightwork very quickly.",
    "I found Lightwork very cumbersome to use.",
    "I felt very confident using Lightwork.",
    "I needed to learn a lot of things before I could get going with Lightwork.",
)
SEQ_QUESTION = "Overall, how difficult or easy was this task to complete?"

# Roles a person may say they work in (the five personas the survey reports by).
ROLES: tuple[tuple[str, str], ...] = (
    ("administrator", "I set up and run Lightwork"),
    ("employee", "I give Lightwork work to do"),
    ("approver", "I approve or reject requests"),
    ("privacy", "I handle privacy requests and records"),
    ("executive", "I review results, costs and records"),
)
NOT_GIVEN = "not_given"

# Top tasks, one per persona where the product can tell the task finished.
TOP_TASKS: tuple[tuple[str, str], ...] = (
    ("run_task", "get a finished result from a task you gave Lightwork"),
    ("decide_approval", "approve or reject a request"),
    ("change_setting", "change a setting"),
    ("invite_person", "invite a colleague"),
)

# Two-sided 95% Student t critical values for 1..30 degrees of freedom.
_T95 = (12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
        2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
        2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042)


class SurveyError(ValueError):
    """An answer the survey will not store."""


def enabled() -> bool:
    """``[analytics] usability_survey``; off unless set to true."""
    try:
        from .config import load_config

        section = (load_config() or {}).get("analytics")
    except Exception:  # noqa: BLE001 -- an unreadable config keeps the survey off
        return False
    return isinstance(section, dict) and section.get("usability_survey") is True


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "usability-survey.json"


def quarter(now: float | None = None) -> str:
    """``"2026-Q4"`` for the UTC calendar quarter containing ``now``."""
    stamp = time.gmtime(time.time() if now is None else now)
    return f"{stamp.tm_year}-Q{(stamp.tm_mon - 1) // 3 + 1}"


def sus_score(answers: list[int] | tuple[int, ...]) -> float:
    """Brooke's SUS score (0-100) from ten answers on a 1-5 scale."""
    if len(answers) != len(SUS_ITEMS):
        raise SurveyError("answer all ten statements")
    total = 0
    for index, value in enumerate(answers):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
            raise SurveyError("each answer must be from 1 to 5")
        total += (value - 1) if index % 2 == 0 else (5 - value)
    return total * 2.5


def _locked():
    from contextlib import ExitStack

    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import maverick_home

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(store_path()))
        return stack.pop_all()


def _load() -> dict[str, Any]:
    from .file_lock import atomic_read_text, ensure_private_file

    path = store_path()
    data: Any = {}
    if path.exists():
        ensure_private_file(path)
        try:
            data = json.loads(atomic_read_text(path))
        except (OSError, ValueError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    for key, kind in (("asked", dict), ("sus", list), ("seq", list)):
        if not isinstance(data.get(key), kind):
            data[key] = kind()
    if not isinstance(data.get("key"), str) or len(data["key"]) != 64:
        data["key"] = secrets.token_hex(32)
    return data


def _write(data: dict[str, Any]) -> None:
    from .file_lock import atomic_write_text

    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True))


def _who(data: dict[str, Any], principal: str) -> str:
    who = str(principal or "").strip()
    if not who:
        raise SurveyError("sign in to answer the survey")
    return hmac.new(bytes.fromhex(data["key"]), who.encode("utf-8"), hashlib.sha256).hexdigest()


def _role(value: object) -> str:
    known = {key for key, _label in ROLES}
    return value if isinstance(value, str) and value in known else NOT_GIVEN


def _asked(data: dict[str, Any], who: str, topic: str, now: float | None) -> bool:
    return data["asked"].get(who, {}).get(topic) == quarter(now)


def _mark(data: dict[str, Any], who: str, topic: str, now: float | None) -> None:
    row = data["asked"].setdefault(who, {})
    row[topic] = quarter(now)


def offer_sus(principal: str, now: float | None = None) -> bool:
    """True when the survey is on and this person has not been asked this quarter."""
    if not enabled() or not str(principal or "").strip():
        return False
    data = _load()
    return not _asked(data, _who(data, principal), "sus", now)


def offer_seq(principal: str, task: str, now: float | None = None) -> bool:
    if not enabled() or task not in dict(TOP_TASKS) or not str(principal or "").strip():
        return False
    data = _load()
    return not _asked(data, _who(data, principal), "seq:" + task, now)


def record_sus(principal: str, answers: list[int], role: object = None, now: float | None = None) -> float:
    """Store one SUS answer set for this quarter and return its score."""
    if not enabled():
        raise SurveyError("the usability survey is turned off")
    score = sus_score(answers)
    with _locked():
        data = _load()
        who = _who(data, principal)
        if _asked(data, who, "sus", now):
            raise SurveyError("you have already answered or skipped this quarter's survey")
        _mark(data, who, "sus", now)
        data["sus"].append({"quarter": quarter(now), "role": _role(role), "score": score,
                            "answers": list(answers)})
        _write(data)
    return score


def record_seq(principal: str, task: str, rating: int, role: object = None, now: float | None = None) -> None:
    if not enabled():
        raise SurveyError("the usability survey is turned off")
    if task not in dict(TOP_TASKS):
        raise SurveyError("that task is not one the survey asks about")
    if isinstance(rating, bool) or not isinstance(rating, int) or not 1 <= rating <= 7:
        raise SurveyError("the answer must be from 1 to 7")
    with _locked():
        data = _load()
        who = _who(data, principal)
        if _asked(data, who, "seq:" + task, now):
            raise SurveyError("you have already answered or skipped this question this quarter")
        _mark(data, who, "seq:" + task, now)
        data["seq"].append({"quarter": quarter(now), "role": _role(role), "task": task, "rating": rating})
        _write(data)


def dismiss(principal: str, topic: str = "sus", now: float | None = None) -> None:
    """One "Not now": the survey (``"sus"``) or one task's question stays hidden this quarter."""
    if topic != "sus" and topic.removeprefix("seq:") not in dict(TOP_TASKS):
        raise SurveyError("unknown survey question")
    with _locked():
        data = _load()
        _mark(data, _who(data, principal), topic, now)
        _write(data)


def _summary(values: list[float], floor: float, ceiling: float) -> dict[str, Any]:
    n = len(values)
    out: dict[str, Any] = {"n": n, "enough": n >= MIN_ANSWERS}
    if n < MIN_ANSWERS:
        return out
    mean = sum(values) / n
    deviation = math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))
    critical = _T95[n - 2] if n - 1 <= len(_T95) else 1.96
    margin = critical * deviation / math.sqrt(n)
    # The interval is clipped to the scale: a score cannot pass its own ends.
    out.update(mean=round(mean, 1), low=round(max(floor, mean - margin), 1),
               high=round(min(ceiling, mean + margin), 1))
    return out


def results(period: str | None = None) -> dict[str, Any]:
    """Per-role SUS and per-task SEQ summaries for one quarter (default: this one).

    No row carries a person; a group under :data:`MIN_ANSWERS` reports only its count.
    """
    period = period or quarter()
    data = _load() if store_path().exists() else {"sus": [], "seq": []}
    sus = [row for row in data["sus"] if isinstance(row, dict) and row.get("quarter") == period]
    seq = [row for row in data["seq"] if isinstance(row, dict) and row.get("quarter") == period]
    roles = [*ROLES, (NOT_GIVEN, "Role not given")]
    by_role = [{"role": key, "label": label,
                **_summary([float(r["score"]) for r in sus if r.get("role") == key], 0, 100)} for key, label in roles]
    by_task = [{"task": key, "label": label,
                **_summary([float(r["rating"]) for r in seq if r.get("task") == key], 1, 7)} for key, label in TOP_TASKS]
    return {"quarter": period, "minimum": MIN_ANSWERS, "sus": by_role, "seq": by_task,
            "sus_total": _summary([float(r["score"]) for r in sus], 0, 100)}


__all__ = [
    "MIN_ANSWERS",
    "NOT_GIVEN",
    "ROLES",
    "SEQ_QUESTION",
    "SUS_ITEMS",
    "TOP_TASKS",
    "SurveyError",
    "dismiss",
    "enabled",
    "offer_seq",
    "offer_sus",
    "quarter",
    "record_seq",
    "record_sus",
    "results",
    "store_path",
    "sus_score",
]
