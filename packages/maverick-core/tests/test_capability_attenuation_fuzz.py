"""Adversarial property test: capability attenuation can NEVER escalate.

The whole governance model rests on one invariant -- a spawned child's grant
is a subset of its parent's authority. If a child could gain a tool, path,
host, or risk ceiling the parent lacked, every downstream control (no money
without a human, read-not-write fleets, egress lock) is bypassable by simply
spawning a child. This fuzzes attenuate() and intersect() over many random
grants + random attenuation requests and asserts the result is always
authority-subset of the parent: anything the child permits, the parent permits.
"""
from __future__ import annotations

import random

from maverick.capability import Capability
from maverick.safety.tool_risk import RISK_LEVELS

_TOOLS = ["read_file", "write_file", "shell", "browser", "http_fetch",
          "wire_transfer", "list_dir", "apply_patch", "web_search", "delete_file"]
_RISKY = {"shell": "high", "wire_transfer": "high", "write_file": "medium",
          "delete_file": "high", "apply_patch": "medium", "browser": "medium"}


def _rand_grant(rng) -> Capability:
    allow = frozenset(rng.sample(_TOOLS, rng.randint(0, 4)))
    deny = frozenset(rng.sample(_TOOLS, rng.randint(0, 3)))
    risk = rng.choice([None, *RISK_LEVELS, "bogus-level"])
    paths = frozenset(rng.sample(["a/*", "b/*", "secret/*", "*"], rng.randint(0, 2)))
    hosts = frozenset(rng.sample(["*.internal", "api.x.com", "*"], rng.randint(0, 2)))
    return Capability(principal="p", allow_tools=allow, deny_tools=deny,
                      max_risk=risk, allow_paths=paths, allow_hosts=hosts)


def test_attenuate_never_escalates():
    rng = random.Random(1337)
    test_paths = ["a/f.txt", "b/g.txt", "secret/k.pem", "other/z"]
    test_hosts = ["api.x.com", "evil.com", "db.internal"]
    for _ in range(4000):
        parent = _rand_grant(rng)
        child = parent.attenuate(
            allow=frozenset(rng.sample(_TOOLS, rng.randint(0, 3))) or None,
            deny=frozenset(rng.sample(_TOOLS, rng.randint(0, 2))) or None,
            max_risk=rng.choice([None, *RISK_LEVELS]),
            allow_paths=frozenset(rng.sample(["a/*", "x/*"], rng.randint(0, 2))) or None,
            allow_hosts=frozenset(rng.sample(["api.x.com", "y.com"], rng.randint(0, 2))) or None,
        )
        for t in _TOOLS:
            if child.permits(t):
                assert parent.permits(t), (
                    f"ESCALATION: child permits tool {t!r} parent denies\n"
                    f"parent={parent}\nchild={child}"
                )
        for p in test_paths:
            if child.permits_path(p):
                assert parent.permits_path(p), f"ESCALATION: path {p}\n{parent}\n{child}"
        for h in test_hosts:
            if child.permits_host(h):
                assert parent.permits_host(h), f"ESCALATION: host {h}\n{parent}\n{child}"


def test_intersect_is_subset_of_both():
    rng = random.Random(99)
    for _ in range(3000):
        a = _rand_grant(rng)
        b = _rand_grant(rng)
        c = a.intersect(b)
        for t in _TOOLS:
            if c.permits(t):
                assert a.permits(t) and b.permits(t), (
                    f"ESCALATION via intersect: {t}\na={a}\nb={b}\nc={c}"
                )


def test_disjoint_whitelists_deny_all_not_allow_all():
    # The classic "empty set means all" footgun: {A} attenuated by {B}.
    parent = Capability(principal="p", allow_tools=frozenset({"read_file"}))
    child = parent.attenuate(allow=frozenset({"shell"}))
    assert not child.permits("shell")
    assert not child.permits("read_file")
    assert not child.permits("anything_at_all")
