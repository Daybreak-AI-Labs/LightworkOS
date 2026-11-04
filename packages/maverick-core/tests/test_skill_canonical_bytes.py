"""_canonical_signed_bytes binds name/triggers/tools_needed/purposes/body.

These run without `cryptography` (pure function), so they pin the actual
security property -- a signed skill's activation triggers, requested tools,
and purpose-scoped recall metadata can't be altered without changing the
signed bytes -- even in environments
where the ed25519 path isn't exercised. The end-to-end sign/verify policy
lives in test_skill_signing.py.

A canonical form of only ``name + "\\n" + body`` would let a signed skill's
``triggers``/``tools_needed``/``purposes`` be tampered with while the
signature still verified.
"""
from __future__ import annotations

from pathlib import Path

from maverick.skills import Skill, _canonical_signed_bytes


def _skill(
    *, name="s", body="b", triggers=None, tools_needed=None, purposes=None
) -> Skill:
    return Skill(
        name=name, triggers=list(triggers or []),
        tools_needed=list(tools_needed or []), body=body, path=Path("x.md"),
        purposes=tuple(purposes or ()),
    )


def test_triggers_are_bound():
    a = _canonical_signed_bytes(_skill(triggers=["t1"]))
    b = _canonical_signed_bytes(_skill(triggers=["t1", "evil"]))
    assert a != b   # adding/altering a trigger changes the signed bytes


def test_tools_needed_are_bound():
    a = _canonical_signed_bytes(_skill(tools_needed=["read_file"]))
    b = _canonical_signed_bytes(_skill(tools_needed=["read_file", "shell"]))
    assert a != b   # escalating requested tools changes the signed bytes


def test_purposes_are_bound():
    a = _canonical_signed_bytes(_skill(purposes=("audit",)))
    b = _canonical_signed_bytes(_skill(purposes=("finance",)))
    c = _canonical_signed_bytes(_skill(purposes=()))
    assert a != b   # changing purpose scope changes the signed bytes
    assert a != c   # removing purpose scope changes the signed bytes


def test_name_and_body_still_bound():
    base = _skill()
    assert _canonical_signed_bytes(base) != _canonical_signed_bytes(_skill(name="other"))
    assert _canonical_signed_bytes(base) != _canonical_signed_bytes(_skill(body="other"))


def test_deterministic_and_bytes():
    out = _canonical_signed_bytes(_skill(name="n", triggers=["a", "b"], tools_needed=["x"]))
    again = _canonical_signed_bytes(_skill(name="n", triggers=["a", "b"], tools_needed=["x"]))
    assert out == again
    assert isinstance(out, bytes)


def test_no_field_shifting_via_newline():
    # The old f"{name}\n{body}" form let name="a\nb",body="" collide with
    # name="a",body="b" (same bytes -> a signature was liftable between them).
    # Canonical JSON keeps them distinct.
    collide = _canonical_signed_bytes(_skill(name="a\nb", body=""))
    split = _canonical_signed_bytes(_skill(name="a", body="b"))
    assert collide != split


def test_trigger_order_is_significant():
    # Reordering triggers changes the signed bytes (a publisher signs an order).
    assert _canonical_signed_bytes(_skill(triggers=["a", "b"])) != \
           _canonical_signed_bytes(_skill(triggers=["b", "a"]))
