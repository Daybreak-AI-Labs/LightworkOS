"""provenance_chain: verify a tamper-evident chain of agent actions."""
from __future__ import annotations

import hashlib

from maverick.tools.provenance_chain import provenance_chain

_GENESIS = "0" * 64


def _h(actor, action, prev):
    return hashlib.sha256(f"{actor}|{action}|{prev}".encode()).hexdigest()


def _run(**kw):
    return provenance_chain().fn({"op": "verify", **kw})


def _build(steps):
    """steps: list of (actor, action). Returns a valid linked chain."""
    links = []
    prev = _GENESIS
    for actor, action in steps:
        links.append({"actor": actor, "action": action, "prev_hash": prev})
        prev = _h(actor, action, prev)
    return links


def test_valid_single():
    out = _run(links=_build([("alice", "init")]))
    assert out.startswith("VALID") and "1 link(s)" in out


def test_valid_multi():
    out = _run(links=_build([("alice", "init"), ("bob", "edit"), ("carol", "ship")]))
    assert out.startswith("VALID") and "3 link(s)" in out


def test_broken_genesis():
    bad = _build([("alice", "init")])
    bad[0]["prev_hash"] = "f" * 64  # not the genesis
    out = _run(links=bad)
    assert out.startswith("BROKEN") and "link 0" in out


def test_broken_linkage():
    chain = _build([("alice", "init"), ("bob", "edit")])
    chain[1]["prev_hash"] = "a" * 64  # wrong link to previous
    out = _run(links=chain)
    assert out.startswith("BROKEN") and "link 1" in out


def test_broken_stated_hash():
    chain = _build([("alice", "init")])
    chain[0]["hash"] = "deadbeef"  # claimed content hash is wrong
    out = _run(links=chain)
    assert out.startswith("BROKEN") and "content hash mismatch" in out


def test_valid_with_correct_stated_hash():
    chain = _build([("alice", "init"), ("bob", "edit")])
    prev = _GENESIS
    for link in chain:
        link["hash"] = _h(link["actor"], link["action"], prev)
        prev = link["hash"]
    assert _run(links=chain).startswith("VALID")


def test_errors():
    t = provenance_chain()
    assert t.fn({"op": "verify"}).startswith("ERROR")  # no links
    assert t.fn({"op": "verify", "links": []}).startswith("ERROR")  # empty
    assert t.fn({"op": "nope", "links": []}).startswith("ERROR")
