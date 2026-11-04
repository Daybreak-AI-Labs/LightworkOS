"""audit_mirror: verify a primary audit log against an independent mirror."""
from __future__ import annotations

from maverick.tools.audit_mirror import audit_mirror


def _verify(primary, mirror):
    return audit_mirror().fn({"op": "verify", "primary": primary, "mirror": mirror})


def test_identical_logs_consistent():
    log = [{"seq": 1, "hash": "a"}, {"seq": 2, "hash": "b"}, {"seq": 3, "hash": "c"}]
    out = _verify(log, list(log))
    assert out.startswith("CONSISTENT")
    assert "3 entries" in out


def test_order_independent():
    primary = [{"seq": 2, "hash": "b"}, {"seq": 1, "hash": "a"}]
    mirror = [{"seq": 1, "hash": "a"}, {"seq": 2, "hash": "b"}]
    assert _verify(primary, mirror).startswith("CONSISTENT")


def test_hash_mismatch_diverges():
    out = _verify(
        [{"seq": 1, "hash": "a"}, {"seq": 2, "hash": "b"}],
        [{"seq": 1, "hash": "a"}, {"seq": 2, "hash": "TAMPERED"}],
    )
    assert out.startswith("DIVERGED")
    assert "hash mismatch at seq=2" in out


def test_sequence_gap_detected():
    log = [{"seq": 1, "hash": "a"}, {"seq": 3, "hash": "c"}]  # missing 2
    out = _verify(log, list(log))
    assert out.startswith("DIVERGED")
    assert "seq=2 missing" in out


def test_missing_entry_on_one_side():
    out = _verify(
        [{"seq": 1, "hash": "a"}, {"seq": 2, "hash": "b"}],
        [{"seq": 1, "hash": "a"}],  # mirror dropped seq 2 -> gap or missing
    )
    assert out.startswith("DIVERGED")


def test_duplicate_seq_diverges():
    out = _verify(
        [{"seq": 1, "hash": "a"}, {"seq": 1, "hash": "a"}],
        [{"seq": 1, "hash": "a"}],
    )
    assert out.startswith("DIVERGED")
    assert "duplicate seq=1" in out


def test_both_empty_consistent():
    assert _verify([], []).startswith("CONSISTENT")


def test_errors():
    t = audit_mirror()
    assert t.fn({"op": "verify", "mirror": []}).startswith("ERROR")  # no primary
    assert t.fn({"op": "verify", "primary": []}).startswith("ERROR")  # no mirror
    assert t.fn({"op": "nope", "primary": [], "mirror": []}).startswith("ERROR")
    assert t.fn({"op": "verify",
                 "primary": [{"seq": "x", "hash": "a"}],
                 "mirror": []}).startswith("ERROR")  # bad seq
