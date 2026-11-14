"""Capability-algebra non-escalation proof for a code patch (Gap 5).

Pins the differential: a patch widens authority iff it introduces a capability
CLASS the baseline did not already use, decided through Capability.permits (the
real least-privilege algebra), and that a missing baseline can only over-report.
"""
from __future__ import annotations

from maverick import self_modify_capability as cap
from maverick.self_modify_capability import capability_delta, classes_in, widens


def _patch(added: str, *, context: str = "old", removed: str | None = None) -> str:
    body = f" {context}\n"
    if removed is not None:
        body += f"-{removed}\n"
    body += f"+{added}\n"
    return f"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n{body}"


class TestClassesIn:
    def test_detects_named_classes(self):
        assert classes_in(["import socket"]) == frozenset({"network"})
        assert classes_in(["subprocess.run(x)"]) == frozenset({"process"})
        assert "dynamic_code" in classes_in(["y = eval(z)"])
        assert "fs_write" in classes_in(["p.write_text('x')"])

    def test_comment_only_line_is_not_a_capability(self):
        assert classes_in(["# subprocess is avoided"]) == frozenset()

    def test_clean_code_has_no_classes(self):
        assert classes_in(["value = 1 + 2", "return value"]) == frozenset()


class TestWidensDifferential:
    def test_adding_a_new_class_widens(self):
        # baseline (context) has no network; the added line introduces it.
        w, new = widens(_patch("import socket"))
        assert w is True and new == ["network"]

    def test_editing_within_an_existing_class_does_not_widen(self):
        # With a REAL baseline file that already does networking, tweaking a
        # network call is not an escalation (the differential earns this).
        p = _patch("resp = requests.post(url)", context="resp = requests.get(url)")
        w, new = widens(p, baseline_files={"x.py": "resp = requests.get(url)"})
        assert w is False and new == []

    def test_without_baseline_any_construct_is_conservative(self):
        # No baseline_files -> empty baseline -> even editing within a class reads
        # as introducing it (fail-closed; context lines never seed the baseline).
        p = _patch("resp = requests.post(url)", context="resp = requests.get(url)")
        w, new = widens(p)
        assert w is True and new == ["network"]

    def test_clean_edit_does_not_widen(self):
        w, new = widens(_patch("TUNING = 0.7"))
        assert w is False and new == []

    def test_baseline_files_prevent_false_positive(self):
        # The added line uses network, but the full baseline file already did too,
        # so with the real file as baseline it is NOT an escalation.
        p = _patch("s2 = socket.socket()")
        w, _ = widens(p, baseline_files={"x.py": "import socket\ns = socket.socket()"})
        assert w is False

    def test_missing_baseline_is_conservative(self):
        # WITHOUT a baseline file the baseline is empty, so any added construct
        # reads as new -> over-reports (fail-closed).
        p = _patch("s2 = socket.socket()")
        w, _ = widens(p)
        assert w is True

    def test_context_line_word_cannot_seed_the_baseline(self):
        # Security regression: an unchanged context line mentioning "allowlist"
        # must NOT put authority_grant in `before` and mask an added grant.
        p = _patch("editable_paths = ['**']",
                   context="# this file manages the allowlist")
        w, new = widens(p)
        assert w is True and "authority_grant" in new


class TestCapabilityDeltaShape:
    def test_returns_before_after_probe_over_the_algebra(self):
        before, after, probe = capability_delta(_patch("subprocess.run(x)"))
        assert probe == cap.CAPABILITY_CLASSES
        # after permits 'process'; before does not -> the gate sees escalation.
        assert after.permits("process") is True
        assert before.permits("process") is False
        # a class neither uses is permitted by neither.
        assert after.permits("network") is False

    def test_empty_grant_permits_nothing_not_everything(self):
        # A clean patch -> before and after both permit no capability class
        # (guards the capability-algebra 'empty allow == all' inversion).
        before, after, probe = capability_delta(_patch("x = 1"))
        assert not any(before.permits(c) for c in probe)
        assert not any(after.permits(c) for c in probe)


class TestAstDetection:
    """The AST pass catches obfuscation/aliasing the line regex cannot."""

    def test_import_aliasing_is_caught(self):
        assert "process" in cap.classes_in_source("from os import system as s\ns()")

    def test_getattr_obfuscation_is_caught(self):
        assert "dynamic_code" in cap.classes_in_source("f = getattr(o, 'sy'+'stem')")

    def test_attribute_call_on_imported_module(self):
        assert "fs_write" in cap.classes_in_source("import shutil\nshutil.rmtree(d)")

    def test_builtins_dynamic_exec_attribute_is_caught(self):
        assert "dynamic_code" in cap.classes_in_source("import builtins\nbuiltins.eval(user)")

    def test_literal_getattr_dangerous_attributes_are_caught(self):
        assert "process" in cap.classes_in_source('import os\ngetattr(os, "system")("id")')
        assert "fs_write" in cap.classes_in_source(
            'import shutil\ngetattr(shutil, "rmtree")(path)')
        assert "dynamic_code" in cap.classes_in_source(
            'import builtins\ngetattr(builtins, "eval")(code)')

    def test_from_import_of_dangerous_name_flags_immediately(self):
        assert "process" in cap.classes_in_source("from subprocess import run")

    def test_open_write_mode_is_fs_write_read_is_not(self):
        # AST reads the mode argument structurally (regex over-flags a filename
        # that happens to contain a mode char, which is the safe direction).
        assert "fs_write" in cap.classes_in_source("open('out', 'w')")
        assert "fs_write" not in cap.classes_in_source("open('f', 'r')")

    def test_unparseable_fragment_falls_back_to_regex(self):
        # a bare partial expression won't AST-parse; regex still flags it
        assert "network" in cap.classes_in_source("    resp = requests.get(")

    def test_clean_source_has_nothing(self):
        assert cap.classes_in_source("def f(x):\n    return x + 1") == frozenset()


class TestDynamicCodePrecision:
    """dynamic_code must flag every obfuscation spelling (fail-closed) WITHOUT
    firing on same-named methods (`compiler.compile`, `df.eval`) or on a getattr
    whose attribute name is a plain string literal (`getattr(x, "CONST")` is
    static attribute access, == x.CONST). Regressions here surfaced as real gold
    fixes wrongly held back by the capability gate (django-15930, pytest-5631).
    The line regex is what fires -- diff fragments rarely AST-parse -- so this is
    pinned on ``classes_in`` (the regex screen), not just ``classes_in_source``."""

    def _dyn(self, line: str) -> bool:
        return "dynamic_code" in classes_in([line])

    # --- false positives that must NOT flag --------------------------------
    def test_method_named_compile_is_not_builtin_compile(self):
        # django__django-15930's gold fix: an ORM query-compiler method call.
        assert not self._dyn("sql, params = compiler.compile(Value(True))")
        assert not self._dyn("x = self.query.compile(node)")

    def test_method_named_eval_or_exec_is_not_the_builtin(self):
        assert not self._dyn('out = df.eval("a + b")')
        assert not self._dyn("cur.execute(sql)")           # not exec(

    def test_getattr_with_string_literal_name_is_static(self):
        # pytest-dev__pytest-5631's gold fix: getattr(mod, "DEFAULT", sentinel).
        assert not self._dyn('m = getattr(sys.modules.get("mock"), "DEFAULT", object())')
        assert not self._dyn('x = getattr(obj, "attr_name")')
        assert not self._dyn('y = getattr(self.thing, "CONST", None)')
        assert not self._dyn('z = getattr(obj,"nospace")')

    # --- threats that must STILL flag (fail-closed preserved) ----------------
    def test_builtin_dynamic_exec_still_flags(self):
        assert self._dyn("v = eval(user_input)")
        assert self._dyn("exec(payload)")
        assert self._dyn('c = compile(src, "<s>", "exec")')

    def test_dynamic_getattr_name_still_flags(self):
        assert self._dyn("f = getattr(os, 'sy'+'stem')")   # concatenation
        assert self._dyn("g = getattr(mod, dynamic_name)")  # variable name
        assert self._dyn("h = getattr(mod, name, None)")    # variable + default

    def test_getattr_split_across_lines_flags_conservatively(self):
        # A getattr whose args we cannot see on the line can't be proven safe.
        assert self._dyn("val = getattr(")

    def test_other_obfuscation_primitives_still_flag(self):
        assert self._dyn('b = __builtins__["eval"]')
        assert self._dyn('d = codecs.decode(blob, "rot13")')
        assert self._dyn("import base64")

    def test_real_instance_gold_patches_do_not_widen(self):
        # The two gold fixes that motivated this precision fix must show NO new
        # capability class vs their own baseline files (empty baseline here, so
        # this proves the added lines introduce nothing -- not merely masked).
        django = ("sql, params = compiler.compile(Value(True))")
        pytest_ = ('m = getattr(sys.modules.get("mock"), "DEFAULT", object())')
        for added in (django, pytest_):
            w, new = widens(_patch(added))
            assert w is False, f"{added!r} wrongly widens -> {new}"


def test_common_spawn_apis_and_cross_file_baselines_are_caught():
    for line in ("await asyncio.create_subprocess_shell('id')",
                 "os.posix_spawn('/bin/sh', ['sh'], {})",
                 "builtins.__dict__['ex' + 'ec'](code)"):
        assert widens(_patch(line))[0] is True, line
    # A class used only in ANOTHER baseline file does not mask its first use here.
    w, new = widens(_patch("import subprocess"), baseline_files={"other.py": "import subprocess\n"})
    assert w is True and new == ["process"]
