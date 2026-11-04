"""rectification: GDPR Art. 16 field-correction validation/application."""
from __future__ import annotations

import json

from maverick.tools.rectification import rectification


def _a(record, changes, immutable=None, allow_new=None):
    args = {"op": "apply", "record": record, "changes": changes}
    if immutable is not None:
        args["immutable"] = immutable
    if allow_new is not None:
        args["allow_new"] = allow_new
    return rectification().fn(args)


def test_apply_correction():
    out = _a({"name": "Jon", "city": "NYC"}, {"name": "John"})
    assert out.startswith("APPLIED: 1 applied, 0 rejected")
    assert "name: 'Jon' -> 'John'" in out
    rec = json.loads(out.splitlines()[-1].split("corrected record: ", 1)[1])
    assert rec == {"name": "John", "city": "NYC"}


def test_immutable_rejected():
    out = _a({"id": "x1", "name": "Jon"}, {"id": "x2", "name": "John"}, immutable=["id"])
    assert out.startswith("PARTIAL")
    assert "id: immutable" in out
    assert "name: 'Jon' -> 'John'" in out


def test_no_op_change_rejected():
    out = _a({"name": "John"}, {"name": "John"})
    assert out.startswith("REJECTED")
    assert "name: unchanged" in out


def test_new_field_blocked_by_default():
    out = _a({"name": "John"}, {"email": "j@x.com"})
    assert out.startswith("REJECTED")
    assert "email: not in record" in out


def test_allow_new_completes_field():
    out = _a({"name": "John"}, {"email": "j@x.com"}, allow_new=True)
    assert out.startswith("APPLIED")
    assert "email: '(absent)' -> 'j@x.com'" in out


def test_errors():
    t = rectification()
    assert t.fn({"op": "apply", "record": [], "changes": {"a": 1}}).startswith("ERROR")
    assert t.fn({"op": "apply", "record": {}, "changes": {}}).startswith("ERROR")
    assert t.fn({"op": "apply", "record": {}, "changes": {"a": 1}, "immutable": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "record": {}, "changes": {"a": 1}}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "rectification" in names
