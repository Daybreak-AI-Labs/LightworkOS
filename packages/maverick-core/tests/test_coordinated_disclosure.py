"""coordinated_disclosure: vulnerability disclosure timeline/status tracking."""
from __future__ import annotations

from maverick.tools.coordinated_disclosure import coordinated_disclosure


def _s(records, today=None, policy=None, embargo_days=None):
    args = {"op": "status", "records": records}
    if today is not None:
        args["today"] = today
    if policy is not None:
        args["policy"] = policy
    if embargo_days is not None:
        args["embargo_days"] = embargo_days
    return coordinated_disclosure().fn(args)


def test_embargoed_with_days_remaining():
    out = _s([{"id": "CVE-1", "reported": "2026-06-01"}], today="2026-06-09")
    # 90-day default: deadline 2026-08-30, 82 days out
    assert "[EMBARGOED] CVE-1" in out
    assert "82d to deadline 2026-08-30" in out
    assert "1 EMBARGOED" in out


def test_due_soon_threshold():
    # deadline 2026-06-07, 6 days out -> DUE_SOON (<=14)
    out = _s([{"id": "v", "reported": "2026-03-09"}], today="2026-06-01")
    assert "[DUE_SOON] v" in out


def test_overdue():
    out = _s([{"id": "old", "reported": "2026-01-01"}], today="2026-06-09")
    assert "[OVERDUE] old" in out
    assert "passed" in out and "disclosure permitted" in out


def test_patched_shortcircuits():
    out = _s([{"id": "p", "reported": "2026-01-01", "patched": "2026-02-15"}], today="2026-06-09")
    assert "[PATCHED] p" in out and "fixed 2026-02-15" in out


def test_disclosed_wins_over_patched():
    out = _s([{
        "id": "d", "reported": "2026-01-01",
        "patched": "2026-02-15", "disclosed": "2026-03-01",
    }], today="2026-06-09")
    assert "[DISCLOSED] d" in out and "public on 2026-03-01" in out


def test_per_severity_policy():
    out = _s(
        [{"id": "crit", "reported": "2026-06-01", "severity": "critical"}],
        today="2026-06-09",
        policy={"critical": 30, "default": 90},
    )
    # 30-day window: deadline 2026-07-01, 22 days out
    assert "deadline 2026-07-01" in out


def test_flat_embargo_days():
    out = _s([{"id": "x", "reported": "2026-06-01"}], today="2026-06-09", embargo_days=7)
    # deadline 2026-06-08 already passed
    assert "[OVERDUE] x" in out


def test_sorted_and_summary():
    out = _s([
        {"id": "b-emb", "reported": "2026-06-01"},
        {"id": "a-over", "reported": "2026-01-01"},
    ], today="2026-06-09")
    lines = out.splitlines()
    # OVERDUE sorts before EMBARGOED
    assert "OVERDUE" in lines[1] and "EMBARGOED" in lines[2]
    assert "1 OVERDUE" in lines[0] and "1 EMBARGOED" in lines[0]


def test_errors():
    t = coordinated_disclosure()
    assert t.fn({"op": "status", "records": "x"}).startswith("ERROR")
    assert t.fn({"op": "status", "records": [{"id": "a"}]}).startswith("ERROR")
    assert t.fn({"op": "status", "records": [{"id": "a", "reported": "nope"}]}).startswith("ERROR")
    assert t.fn({"op": "status", "records": [], "embargo_days": -1}).startswith("ERROR")
    assert t.fn({"op": "nope", "records": []}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "coordinated_disclosure" in names


# ---- coordinated_disclosure ----

def test_cvd_status_open_and_expired():
    t = coordinated_disclosure()
    open_out = t.fn({"op": "status", "reported": "2027-01-01", "embargo_days": 90, "today": "2027-02-01"})
    assert "embargo: OPEN" in open_out and "disclose-on: 2027-04-01" in open_out
    assert "days-remaining: 59" in open_out
    exp = t.fn({"op": "status", "reported": "2027-01-01", "embargo_days": 90, "today": "2027-05-01"})
    assert "embargo: EXPIRED" in exp


def test_cvd_advisory():
    t = coordinated_disclosure()
    out = t.fn({
        "op": "advisory", "id": "MAV-2027-001", "severity": "high",
        "summary": "sandbox escape via crafted args", "reported": "2027-03-01",
        "embargo_days": 30, "today": "2027-03-10", "cve": "CVE-2027-1234",
    })
    assert "# Advisory MAV-2027-001  [HIGH]" in out
    assert "Coordinated-disclosure date: 2027-03-31 (embargo OPEN)" in out
    assert "CVE: CVE-2027-1234" in out


def test_cvd_validation():
    t = coordinated_disclosure()
    assert t.fn({"op": "status", "reported": "nope", "embargo_days": 30}).startswith("ERROR")
    assert t.fn({"op": "status", "reported": "2027-01-01", "embargo_days": -1}).startswith("ERROR")
    assert t.fn({"op": "advisory", "reported": "2027-01-01", "embargo_days": 1, "severity": "bogus", "id": "x", "summary": "y"}).startswith("ERROR")


def test_records_form_agrees_with_single_form_and_ignores_severity_case():
    rec = [{"id": "v", "reported": "2026-01-01"}]
    assert "[OVERDUE] v" in _s(rec, today="2026-04-01", embargo_days=90)
    rec = [{"id": "h", "reported": "2026-01-01", "severity": "High"}]
    assert "[OVERDUE] h" in _s(rec, today="2026-01-09", policy={"high": 7})
