"""Discovery Title: commitments, conception map, scrutiny problems, signed seal."""
from __future__ import annotations

import copy

from maverick.immune import title as t


def _dossier(**over):
    idea = t.commit("RT + accessory protein + evenly spaced repeat array")
    d = {
        "problem": {"statement": "Find uncharacterised RT systems in phage", "signed_off_by": "dr.lee"},
        "inputs": [{"name": "rt-families.fasta", "kind": "data", "sha256": "ab" * 32}],
        "inputs_committed_at": 100.0,
        "priority": [{"commitment": idea["commitment"], "at": 200.0, "label": "array"}],
        "gates": [
            {"id": "g1", "human": "dr.lee", "decision": "framed", "elements": ["RT family"], "at": 150.0},
            {"id": "g2", "human": "dr.kim", "decision": "selected", "elements": ["repeat array"], "at": 250.0},
            {"id": "g3", "human": "dr.kim", "decision": "reviewed", "elements": ["accessory protein"], "at": 260.0},
        ],
        "claims": [{"id": "c1", "elements": ["RT family", "repeat array", "accessory protein"]}],
        "verification": [{"checker": "small-RNA sequencing", "passed": True}],
        "coverage": {"examined": 3564, "total": 3564},
    }
    d.update(over)
    return d, idea


def test_commitment_hides_and_binds():
    c = t.commit("idea")
    assert t.opens(c["commitment"], c["salt"], "idea")
    assert not t.opens(c["commitment"], c["salt"], "idea!")
    assert t.commit("idea")["commitment"] != c["commitment"]  # salted: not guessable


def test_non_ascii_commitment_does_not_open():
    # The commitment is the holder's published text: non-ASCII is a failed
    # opening, not a TypeError from the comparison.
    c = t.commit("idea")
    assert t.opens("é" * 64, c["salt"], "idea") is False


def test_recognition_is_not_conception():
    d, _ = _dossier()
    m = t.conception_map(d)
    assert m == {"RT family": ["g1"], "repeat array": ["g2"], "accessory protein": []}
    assert t.problems(d) == ["claim element without human conception: accessory protein"]


def test_problems_catch_each_weakness():
    d, _ = _dossier(problem={"statement": "x"}, verification=[{"checker": "lean", "passed": False}],
                    coverage={"examined": 1, "total": 11}, inputs_committed_at=999.0)
    p = t.problems(d)
    assert "problem statement not signed off by a human" in p
    assert "verification failed: lean" in p
    assert "search coverage 1/11 (9%)" in p
    assert "inputs were committed after the first recorded idea" in p
    assert "no independent verification recorded" in t.problems(_dossier(verification=[])[0])
    assert "search coverage unknown" in t.problems(_dossier(coverage={})[0])


def test_seal_verifies_offline_and_detects_tampering():
    from maverick.audit.signing import trusted_audit_public_keys
    d, idea = _dossier()
    sealed = t.seal(d)
    pub = trusted_audit_public_keys()[sealed["signature"]["key_id"]]
    reveal = {idea["commitment"]: (idea["salt"], "RT + accessory protein + evenly spaced repeat array")}
    assert t.verify(sealed, pub, reveal)
    assert not t.verify(sealed, pub, {idea["commitment"]: (idea["salt"], "a different idea")})
    forged = copy.deepcopy(sealed)
    forged["dossier"]["gates"][2]["decision"] = "conceived"
    assert not t.verify(forged, pub)
