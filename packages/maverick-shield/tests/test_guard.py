"""Shield guard: tool-call scanning over nested arguments."""

from __future__ import annotations

import pytest


class TestScanToolCallNestedArgs:
    def test_rm_rf_in_nested_list_is_blocked(self):
        from maverick_shield.guard import Shield
        s = Shield(backend="builtin")
        # The dangerous command is split across a list; scanning repr(args)
        # would bury it behind quotes/commas so the rm_rf_root rule never matches.
        v = s.scan_tool_call("shell", {"argv": ["rm", "-rf", "/"]})
        assert not v.allowed

    def test_arg_strings_collects_nested_leaves(self):
        from maverick_shield.guard import _collect_arg_strings
        leaves = _collect_arg_strings({"a": ["x", {"b": "y"}], "c": 3})
        assert "x" in leaves and "y" in leaves


# ---------- 4. shield tool-call gating ----------

@pytest.mark.parametrize("cmd", ["rm -rf /", "rm -rf ~", "rm -rf $HOME"])
def test_shield_scan_tool_call_blocks_destructive_rm(cmd):
    from maverick_shield.guard import Shield
    sh = Shield(backend=Shield.BACKEND_BUILTIN)
    verdict = sh.scan_tool_call("shell", {"cmd": cmd})
    assert not verdict.allowed
    assert verdict.severity == "critical"


def test_shield_scan_tool_call_allows_benign():
    from maverick_shield.guard import Shield
    sh = Shield(backend=Shield.BACKEND_BUILTIN)
    assert sh.scan_tool_call("shell", {"cmd": "ls -la /tmp"}).allowed
