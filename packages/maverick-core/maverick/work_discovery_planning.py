"""Private Ekko opportunity plans and explicitly user-reported pilot results.

Plans never grant capture or execution permission. Storage reuses the consented
ledger's scoped encryption and transactions; no provider or workflow is called.
"""
from __future__ import annotations

import math
import re
import secrets
import statistics
from dataclasses import asdict, dataclass

from .work_discovery import DraftReview
from .work_discovery_store import WorkDiscoveryStoreError

MAX_PLANS = 100
MAX_PILOT_RUNS = 30
_OPPORTUNITY = re.compile(r"^[0-9a-f]{24}$")
_SAMPLE = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class PlanConflict(WorkDiscoveryStoreError):
    """The saved plan changed after the person opened it."""


def _number(value, name, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be a number between 0 and {maximum}.")
    return float(value)


@dataclass(frozen=True)
class BenefitAssumptions:
    runs_per_week: float = 0
    manual_minutes: float = 0
    remaining_minutes: float | None = None
    setup_hours: float | None = None

    def __post_init__(self):
        for name, limit in (("runs_per_week", 10000), ("manual_minutes", 10080),
                            ("remaining_minutes", 10080), ("setup_hours", 10000)):
            if name in {"remaining_minutes", "setup_hours"} and getattr(self, name) is None:
                continue
            object.__setattr__(self, name, _number(getattr(self, name), name.replace("_", " "), limit))

    def estimate(self):
        complete = self.runs_per_week > 0 and self.manual_minutes > 0 and self.remaining_minutes is not None and self.setup_hours is not None
        weekly = self.runs_per_week * (self.manual_minutes - (self.remaining_minutes or 0)) / 60
        return {
            "basis": "owner_assumptions", "complete": complete,
            "weekly_hours": round(weekly, 2) if complete else None,
            "four_week_hours_after_setup": round(weekly * 4 - (self.setup_hours or 0), 2) if complete else None,
            "break_even_weeks": round((self.setup_hours or 0) / weekly, 2) if complete and weekly > 0 else None,
        }


def pilot_summary(samples):
    """Rejected results incur the reported review/rework plus manual fallback."""
    savings = [sample["manual_minutes"] - sample["remaining_minutes"] if sample["accepted"]
               else -sample["remaining_minutes"] for sample in samples]
    return {
        "basis": "owner_reported_pilot", "runs": len(samples),
        "accepted": sum(sample["accepted"] for sample in samples),
        "median_minutes_saved": round(statistics.median(savings), 2) if samples else None,
        "total_minutes_saved": round(sum(savings), 2) if samples else None,
    }


def validate_sample(value):
    if set(value) != {"sample_id", "manual_minutes", "remaining_minutes", "accepted"}:
        raise ValueError("Use the pilot form to record the run.")
    if not isinstance(value["sample_id"], str) or not _SAMPLE.fullmatch(value["sample_id"]):
        raise ValueError("The pilot run reference is invalid. Reopen the form.")
    if not isinstance(value["accepted"], bool):
        raise ValueError("Choose whether the output was accepted.")
    manual = _number(value["manual_minutes"], "Manual baseline minutes", 10080)
    if manual <= 0:
        raise ValueError("Enter a manual baseline greater than zero.")
    return {**value, "manual_minutes": manual,
            "remaining_minutes": _number(value["remaining_minutes"], "Human effort minutes", 10080)}


class OpportunityPlans:
    def __init__(self, store):
        self.store = store

    def _rows(self, conn):
        return conn.execute(
            "SELECT * FROM ekko_plans WHERE tenant_key=? AND owner_key=? AND device_key=? ORDER BY expires_at DESC LIMIT 101",
            self.store._scope,
        ).fetchall()

    def _read(self, row):
        value = self.store._unseal(bytes(row["payload"]), purpose="plan")
        if any(value.get(key) != row[key] for key in ("opportunity_id", "revision", "expires_at")):
            raise WorkDiscoveryStoreError("Saved opportunity integrity could not be verified.")
        return value

    def _find(self, conn, opportunity_id):
        row = conn.execute(
            "SELECT * FROM ekko_plans WHERE tenant_key=? AND owner_key=? AND device_key=? AND opportunity_id=?",
            (*self.store._scope, opportunity_id),
        ).fetchone()
        return self._read(row) if row else None

    def _write(self, conn, value):
        self.store._assert_database_capacity()
        value = {**value, "revision": secrets.token_hex(16)}
        blob = self.store._seal(value, purpose="plan")
        conn.execute(
            "INSERT INTO ekko_plans VALUES (?,?,?,?,?,?,?) ON CONFLICT(tenant_key,owner_key,device_key,opportunity_id) "
            "DO UPDATE SET revision=excluded.revision,payload=excluded.payload,expires_at=excluded.expires_at",
            (*self.store._scope, value["opportunity_id"], value["revision"], blob, value["expires_at"]),
        )
        self.store._queue_audit(conn, "ekko_opportunity_plan", {
            "opportunity_id": value["opportunity_id"], "stage": value["stage"],
            "pilot_runs": len(value["samples"]), "basis": "owner_supplied",
        }, at=self.store._now())
        return self.public(value)

    @staticmethod
    def public(value):
        return {**value, "benefit": BenefitAssumptions(**value["assumptions"]).estimate(),
                "pilot": pilot_summary(value["samples"])}

    def list(self):
        if not self.store.path.exists():
            return []
        self.store._purge_expired_events()
        with self.store._connect() as conn:
            return [self.public(self._read(row)) for row in self._rows(conn)]

    def save(self, candidate, *, review, assumptions, stage, expected_revision, retention_days):
        review = DraftReview(**review)
        assumptions = BenefitAssumptions(**assumptions)
        if stage not in {"shortlisted", "pilot", "parked"}:
            raise ValueError("Choose Shortlisted, In pilot or Parked.")
        if not isinstance(retention_days, int) or not 2 <= retention_days <= 30:
            raise ValueError("Saved plans must expire within 2–30 days.")
        self.store._purge_expired_events()
        now = self.store._now()
        with self.store._deployment_control_barrier(), self.store._consent_barrier(), self.store._transaction() as conn:
            old = self._find(conn, candidate.opportunity_id)
            if (old["revision"] if old else "") != expected_revision:
                raise PlanConflict("This plan changed. Open its latest saved version before saving again.")
            if old is None and len(self._rows(conn)) >= MAX_PLANS:
                raise ValueError("This device has 100 saved opportunities. Remove a saved plan before adding another.")
            sessions = {item.session_id for item in candidate.evidence}
            for session in sessions:
                if conn.execute("SELECT 1 FROM ekko_sessions WHERE tenant_key=? AND owner_key=? AND device_key=? AND session_id=?",
                                (*self.store._scope, session)).fetchone() is None:
                    raise PlanConflict("The source activity was erased. Refresh the opportunities before saving.")
            value = {
                "opportunity_id": candidate.opportunity_id, "review": asdict(review),
                "assumptions": asdict(assumptions), "stage": stage,
                "evidence_revision": candidate.to_dict()["evidence_revision"],
                "samples": old["samples"] if old else [], "updated_at": now,
                "expires_at": now + retention_days * 86400,
            }
            result = self._write(conn, value)
            conn.execute("DELETE FROM ekko_plan_sources WHERE tenant_key=? AND owner_key=? AND device_key=? AND opportunity_id=?",
                         (*self.store._scope, candidate.opportunity_id))
            conn.executemany("INSERT INTO ekko_plan_sources VALUES (?,?,?,?,?)",
                             [(*self.store._scope, candidate.opportunity_id, session) for session in sorted(sessions)])
            return result

    def record_run(self, opportunity_id, *, sample, expected_revision):
        sample = validate_sample(sample)
        self.store._purge_expired_events()
        with self.store._transaction() as conn:
            value = self._find(conn, opportunity_id)
            if value is None:
                raise PlanConflict("This plan expired or was removed. Refresh your saved opportunities.")
            existing = next((item for item in value["samples"] if item["sample_id"] == sample["sample_id"]), None)
            if existing is not None:
                if existing != sample:
                    raise PlanConflict("That pilot run was already recorded with different values.")
                return self.public(value)
            if value["revision"] != expected_revision:
                raise PlanConflict("The plan changed. Reload it before recording another pilot run.")
            if len(value["samples"]) >= MAX_PILOT_RUNS:
                raise ValueError("This pilot already contains 30 runs. Review the results before starting another plan.")
            value["samples"].append(sample)
            value["updated_at"] = self.store._now()
            return self._write(conn, value)

    def delete(self, opportunity_id, *, expected_revision):
        if not _OPPORTUNITY.fullmatch(opportunity_id):
            raise ValueError("Choose a saved opportunity.")
        if not self.store.path.exists():
            return False
        with self.store._transaction() as conn:
            value = self._find(conn, opportunity_id)
            if value is None:
                return False
            if value["revision"] != expected_revision:
                raise PlanConflict("The plan changed. Open its latest version before removing it.")
            conn.execute("DELETE FROM ekko_plans WHERE tenant_key=? AND owner_key=? AND device_key=? AND opportunity_id=?",
                         (*self.store._scope, opportunity_id))
            return True
