"""Property-based proof that capability attenuation is a *meet* in the privilege
lattice — a derived grant can NEVER permit a tool / path / host / risk the
parent didn't. This is the backbone of the least-privilege model: federation
delegation, the cross-host queue worker, RBAC role-narrowing, and subagent
spawning all assume ``Capability.intersect`` / ``.attenuate`` only ever narrow.

Seed-based (stdlib ``random``, fixed seeds) so it needs no new dependency and is
byte-for-byte reproducible in CI — the same posture as the parser fuzz harness.

For parent ``P``, other/child ``C``, and ``R = P ⊓ C`` (and the ``attenuate``
form), over random probes drawn from the *real* domain (NUL-free names):

    R.permits(t)       ⟹  P.permits(t)  ∧  C.permits(t)
    R.permits_path(p)  ⟹  P.permits_path(p)  ∧  C.permits_path(p)
    R.permits_host(h)  ⟹  P.permits_host(h)  ∧  C.permits_host(h)
    R.deny_tools       ⊇  P.deny_tools ∪ C.deny_tools

plus: a CHAIN of attenuations never re-widens (transitivity of ⊑), and
``P ⊓ P`` permits exactly what ``P`` does (idempotence).

Domain note: the ``_DENY_ALL`` sentinel for "permits nothing" is the single NUL
byte ``"\\x00"``. A literal-NUL probe would observe it as a match, but a NUL is
never a valid filesystem path, host, or tool name, so it is excluded from the
probe domain (exactly the assumption the Z3 glob proof discharges).
"""
from __future__ import annotations

import random

from maverick.capability import Capability

# Probe + generator universes (no NUL — see module docstring).
_TOOLS = ["read_file", "write_file", "shell", "http_fetch", "memory", "search",
          "send_email", "code_exec", "browser", "unknown_a", "unknown_b"]
_GLOBS = ["src/*", "*/foo.py", "a/b/*", "*.py", "x*", "data/*", "src/secret",
          "*", "**", "conf?g", "[ab]*", "src/a/b"]
_PATHS = ["src/foo.py", "src/secret", "a/b/c", "x123", "data/x.csv", "conf1g",
          "main.py", "src/a/b", "etc/passwd", "ab", "zz", "foo.py"]
_HOSTS = ["example.com", "api.internal", "localhost", "x.y.z", "1.2.3.4",
          "evil.com", "sub.example.com", "abhost"]
_RISKS = [None, "low", "medium", "high"]
# expires_at: past (always expired) / future (never, within the run) / never.
_EXPIRIES = [None, 0.0, 1e12]
_NOW = 1e9  # strictly between the "past" and "future" expiries above


def _rand_set(rng, universe, *, p_empty=0.3) -> frozenset[str]:
    if rng.random() < p_empty:
        return frozenset()  # empty == "all", the convention under test
    k = rng.randint(1, max(1, len(universe) // 2))
    return frozenset(rng.sample(universe, k))


def _rand_cap(rng, principal="p") -> Capability:
    return Capability(
        principal=principal,
        allow_tools=_rand_set(rng, _TOOLS),
        deny_tools=_rand_set(rng, _TOOLS, p_empty=0.5),
        max_risk=rng.choice(_RISKS),
        expires_at=rng.choice(_EXPIRIES),
        allow_paths=_rand_set(rng, _GLOBS),
        allow_hosts=_rand_set(rng, _HOSTS),
    )


def _assert_le(child: Capability, parent: Capability, label: str) -> None:
    """Assert ``child ⊑ parent``: everything child permits, parent permits."""
    for t in _TOOLS:
        if child.permits(t, now=_NOW):
            assert parent.permits(t, now=_NOW), (
                f"{label}: tool {t!r} permitted by child but not parent\n"
                f"  child ={child}\n  parent={parent}")
    for p in _PATHS:
        if child.permits_path(p):
            assert parent.permits_path(p), (
                f"{label}: path {p!r} permitted by child but not parent\n"
                f"  child.allow_paths ={sorted(child.allow_paths)}\n"
                f"  parent.allow_paths={sorted(parent.allow_paths)}")
    for h in _HOSTS:
        if child.permits_host(h):
            assert parent.permits_host(h), (
                f"{label}: host {h!r} permitted by child but not parent\n"
                f"  child.allow_hosts ={sorted(child.allow_hosts)}\n"
                f"  parent.allow_hosts={sorted(parent.allow_hosts)}")


def test_intersect_is_a_meet():
    """R = P ⊓ C is ≤ BOTH operands, and its deny-set is ≥ both."""
    rng = random.Random(1234)
    for _ in range(5000):
        P = _rand_cap(rng, "P")
        C = _rand_cap(rng, "C")
        R = P.intersect(C, principal="R")
        _assert_le(R, P, "intersect ⊑ P")
        _assert_le(R, C, "intersect ⊑ C")
        assert R.deny_tools >= P.deny_tools, "deny-set shrank vs P"
        assert R.deny_tools >= C.deny_tools, "deny-set shrank vs C"


def test_attenuate_never_widens():
    """The keyword-arg attenuation form can only narrow its parent."""
    rng = random.Random(99)
    for _ in range(5000):
        P = _rand_cap(rng, "P")
        child = P.attenuate(
            principal="c",
            allow=_rand_set(rng, _TOOLS) or None,
            deny=_rand_set(rng, _TOOLS, p_empty=0.6),
            max_risk=rng.choice(_RISKS),
            allow_paths=_rand_set(rng, _GLOBS) or None,
            allow_hosts=_rand_set(rng, _HOSTS) or None,
        )
        _assert_le(child, P, "attenuate ⊑ P")
        assert child.deny_tools >= P.deny_tools, "attenuate shrank the deny-set"


def test_chain_attenuation_never_rewidens():
    """A whole delegation chain (root → … → leaf), mixing attenuate and
    intersect at each hop, never re-widens past the root."""
    rng = random.Random(7)
    for _ in range(2500):
        root = _rand_cap(rng, "root")
        cur = root
        for i in range(rng.randint(1, 6)):
            if rng.random() < 0.5:
                cur = cur.attenuate(
                    principal=f"c{i}",
                    allow=_rand_set(rng, _TOOLS) or None,
                    deny=_rand_set(rng, _TOOLS, p_empty=0.7),
                    max_risk=rng.choice(_RISKS),
                    allow_paths=_rand_set(rng, _GLOBS) or None,
                    allow_hosts=_rand_set(rng, _HOSTS) or None,
                )
            else:
                cur = cur.intersect(_rand_cap(rng, f"o{i}"), principal=f"c{i}")
            _assert_le(cur, root, f"chain hop {i} ⊑ root")


def test_self_intersect_is_idempotent():
    """P ⊓ P permits exactly what P permits (the meet is idempotent)."""
    rng = random.Random(55)
    for _ in range(2000):
        P = _rand_cap(rng)
        R = P.intersect(P, principal=P.principal)
        for t in _TOOLS:
            assert R.permits(t, now=_NOW) == P.permits(t, now=_NOW)
        for p in _PATHS:
            assert R.permits_path(p) == P.permits_path(p)
        for h in _HOSTS:
            assert R.permits_host(h) == P.permits_host(h)


def test_known_escalation_attempts_are_refused():
    """Concrete, named cases (not just random): each must fail to escalate."""
    # All-permissive parent restricted by a child -> child is the ceiling.
    root = Capability(principal="root")  # empty everything == allow all
    child = root.attenuate(principal="c", allow={"read_file"},
                           allow_paths={"src/*"}, max_risk="low")
    assert child.permits("read_file", now=_NOW)
    assert not child.permits("shell", now=_NOW)        # not in allow
    assert child.permits_path("src/x.py")
    assert not child.permits_path("etc/passwd")        # outside allow_paths

    # Disjoint path globs -> the meet permits NOTHING (not "all").
    a = Capability(principal="a", allow_paths={"src/*"})
    b = Capability(principal="b", allow_paths={"lib/*"})
    meet = a.intersect(b, principal="m")
    assert not meet.permits_path("src/x")              # neither side's union
    assert not meet.permits_path("lib/x")
    _assert_le(meet, a, "disjoint ⊑ a")
    _assert_le(meet, b, "disjoint ⊑ b")

    # A child cannot raise the risk ceiling.
    low = Capability(principal="p", max_risk="low")
    raised = low.attenuate(principal="c", max_risk="high")
    assert raised.max_risk == "low"                    # tighten-only
    assert not raised.permits("shell", now=_NOW)       # shell is high-risk
