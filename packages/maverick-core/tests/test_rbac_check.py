"""rbac_check: role-based access-control authorization decisions."""
from __future__ import annotations

from maverick.tools.rbac_check import rbac_check


def _c(roles, assignments, user, permission, inherits=None):
    args = {"op": "check", "roles": roles, "assignments": assignments,
            "user": user, "permission": permission}
    if inherits is not None:
        args["inherits"] = inherits
    return rbac_check().fn(args)


_ROLES = {"viewer": ["doc:read"], "editor": ["doc:read", "doc:write"], "admin": ["*"]}
_ASSIGN = {"alice": ["editor"], "bob": ["viewer"], "root": ["admin"]}


def test_allow_direct():
    out = _c(_ROLES, _ASSIGN, "alice", "doc:write")
    assert out.startswith("ALLOW") and "via role 'editor'" in out


def test_deny_missing_permission():
    out = _c(_ROLES, _ASSIGN, "bob", "doc:write")
    assert out.startswith("DENY")
    assert "lacks 'doc:write'" in out and "roles: viewer" in out


def test_no_roles():
    out = _c(_ROLES, _ASSIGN, "nobody", "doc:read")
    assert out.startswith("DENY") and "no roles assigned" in out


def test_wildcard_all():
    out = _c(_ROLES, _ASSIGN, "root", "anything:goes")
    assert out.startswith("ALLOW") and "via role 'admin'" in out


def test_prefix_wildcard():
    roles = {"docmgr": ["doc:*"]}
    out = _c(roles, {"u": ["docmgr"]}, "u", "doc:delete")
    assert out.startswith("ALLOW")
    # but not a different prefix
    assert _c(roles, {"u": ["docmgr"]}, "u", "user:delete").startswith("DENY")


def test_inheritance():
    roles = {"base": ["read"], "super": ["write"]}
    inherits = {"super": ["base"]}  # super inherits base's perms
    out = _c(roles, {"u": ["super"]}, "u", "read", inherits=inherits)
    assert out.startswith("ALLOW")


def test_inheritance_cycle_safe():
    roles = {"a": ["pa"], "b": ["pb"]}
    inherits = {"a": ["b"], "b": ["a"]}  # cycle
    out = _c(roles, {"u": ["a"]}, "u", "pb", inherits=inherits)
    assert out.startswith("ALLOW")  # resolves both without hanging


def test_errors():
    t = rbac_check()
    assert t.fn({"op": "check", "roles": [], "assignments": {}, "user": "u", "permission": "p"}).startswith("ERROR")
    assert t.fn({"op": "check", "roles": {}, "assignments": [], "user": "u", "permission": "p"}).startswith("ERROR")
    assert t.fn({"op": "check", "roles": {}, "assignments": {}, "user": "", "permission": "p"}).startswith("ERROR")
    assert t.fn({"op": "check", "roles": {}, "assignments": {}, "user": "u", "permission": ""}).startswith("ERROR")
    assert t.fn({"op": "check", "roles": {}, "assignments": {}, "user": "u", "permission": "p", "inherits": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "roles": {}, "assignments": {}, "user": "u", "permission": "p"}).startswith("ERROR")


def test_rejects_malformed_policy_values():
    t = rbac_check()
    assert t.fn({
        "op": "check",
        "roles": {"a": ["*"], "admin": []},
        "assignments": {"mallory": "admin"},
        "user": "mallory",
        "permission": "secrets:read",
    }).startswith("ERROR")
    assert t.fn({
        "op": "check",
        "roles": {"admin": {"*": False}},
        "assignments": {"mallory": ["admin"]},
        "user": "mallory",
        "permission": "secrets:read",
    }).startswith("ERROR")
    assert t.fn({
        "op": "check",
        "roles": {"base": ["secrets:read"], "admin": []},
        "assignments": {"mallory": ["admin"]},
        "inherits": {"admin": "base"},
        "user": "mallory",
        "permission": "secrets:read",
    }).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "rbac_check" in names
