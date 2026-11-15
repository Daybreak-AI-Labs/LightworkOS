"""tighten(): one definition of "looser" per kind of policy key."""
from __future__ import annotations

import pytest
from maverick.policy_tighten import tighten


@pytest.mark.parametrize(("kind", "upper", "lower", "expected", "loosened", "order"), [
    ("deny_list", ["shell"], [], ["shell"], True, ()),
    ("deny_list", ["shell"], ["shell", "browser"], ["shell", "browser"], False, ()),
    ("allow_list", ["a", "b"], ["a", "c"], ["a"], True, ()),
    ("allow_list", ["a", "b"], [], ["a", "b"], True, ()),  # empty means everything
    ("allow_list", [], ["a"], ["a"], False, ()),
    ("subset", [], ["a"], [], True, ()),  # empty means nothing
    ("protection", True, False, True, True, ()),
    ("protection", False, True, True, False, ()),
    ("permission", False, True, False, True, ()),
    ("permission", True, "false", False, False, ()),
    ("limit", 60, 120, 60, True, ()),
    ("limit", 60, 30, 30, False, ()),
    ("limit", None, 30, 30, False, ()),
    ("limit", {"*": 100.0}, {"pay": 500, "send": 50}, {"*": 100.0, "send": 50.0}, True, ()),
    ("approval", ["pay"], [], ["pay"], True, ()),
    ("approval", False, True, True, False, ()),
    ("rank", "strict", "permissive", "strict", True, ("strict", "balanced", "permissive")),
    ("rank", "balanced", "strict", "strict", False, ("strict", "balanced", "permissive")),
])
def test_a_lower_layer_may_only_tighten(kind, upper, lower, expected, loosened, order):
    assert tighten(kind, upper, lower, order=order) == (expected, loosened)
    with pytest.raises(ValueError):
        tighten(kind if kind != "rank" else "limit", upper, object(), order=order)
