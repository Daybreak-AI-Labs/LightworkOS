"""Tests for defensive_validate — grader brittleness rules."""
from __future__ import annotations


class TestForbiddenPaths:
    """The grader applies its test_patch AFTER ours, or refuses to
    process a patch that pins dependencies. Both cause silent failures
    we cannot recover from at submit time."""

    def test_test_file_blocked(self):
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/tests/test_foo.py b/tests/test_foo.py\n"
            "--- a/tests/test_foo.py\n"
            "+++ b/tests/test_foo.py\n"
            "@@ -1 +1 @@\n"
            "-assert x == 1\n"
            "+assert x == 2\n"
        )
        result = defensive_validate(patch)
        assert not result.ok
        assert "tests/test_foo.py" in result.blocked_paths

    def test_timestamped_diff_header_cannot_smuggle_a_test_edit(self):
        # Regression: git ---/+++ headers may carry a trailing tab+timestamp that
        # git apply ignores. A plain unified diff (no `diff --git` line, so the
        # only path source is the ---/+++ headers) editing a root-level test file
        # -- which matches ONLY the $-anchored forbidden pattern -- must still be
        # blocked, or the timestamp defeats the anchor and git apply patches the
        # real test file.
        from maverick.coding_mode import defensive_validate
        ts = "\t2024-01-01 00:00:00.000000000 +0000"
        patch = (f"--- a/test_evil.py{ts}\n"
                 f"+++ b/test_evil.py{ts}\n"
                 "@@ -1 +1 @@\n-assert x == 1\n+assert x == 2\n")
        result = defensive_validate(patch)
        assert not result.ok
        assert "test_evil.py" in result.blocked_paths

    def test_timestamped_diff_header_cannot_smuggle_a_graded_file_edit(self):
        # Same evasion against the exact FAIL_TO_PASS path match: a graded file
        # that is NOT named like a test still must not be editable by appending a
        # timestamp that defeats the exact-string membership check.
        from maverick.coding_mode import defensive_validate
        ts = "\t2024-01-01 00:00:00.000000000 +0000"
        graded = "pkg/checks.py"
        patch = (f"--- a/{graded}{ts}\n+++ b/{graded}{ts}\n"
                 "@@ -1 +1 @@\n-a\n+b\n")
        result = defensive_validate(patch, fail_to_pass=[f"{graded}::test_a"])
        assert not result.ok
        assert graded in result.blocked_paths

    def test_conftest_warned_not_blocked(self):
        """conftest.py changes are no longer
        hard-blocked; the grader either accepts the edit (when the
        test_patch doesn't touch conftest) or silently drops it. Warn,
        but don't fail the candidate — real fixes do legitimately
        register fixtures here."""
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/src/conftest.py b/src/conftest.py\n"
            "--- a/src/conftest.py\n+++ b/src/conftest.py\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch)
        assert result.ok is True, "conftest is no longer hard-blocked"
        assert any("conftest" in w for w in result.warnings)
        assert result.fn_risk in ("medium", "high")

    def test_setup_py_warned_not_blocked(self):
        """setup.py warns; some fixes legitimately
        adjust entry_points or extras_require."""
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/setup.py b/setup.py\n"
            "--- a/setup.py\n+++ b/setup.py\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch)
        assert result.ok is True
        assert any("setup.py" in w for w in result.warnings)

    def test_pyproject_warned_not_blocked(self):
        """pyproject.toml warns. Many fixes touch
        [tool.*] sections, which are safe."""
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/pyproject.toml b/pyproject.toml\n"
            "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch)
        assert result.ok is True
        assert any("pyproject.toml" in w for w in result.warnings)

    def test_lockfile_still_blocked(self):
        """Lock files remain hard-blocked. Modifying a lock
        file is the surest way to break the grader's dep resolution."""
        from maverick.coding_mode import defensive_validate
        for fname in ("poetry.lock", "Cargo.lock", "yarn.lock", "go.sum"):
            patch = (
                f"diff --git a/{fname} b/{fname}\n"
                f"--- a/{fname}\n+++ b/{fname}\n@@ -1 +1 @@\n-x\n+y\n"
            )
            result = defensive_validate(patch)
            assert not result.ok, f"{fname} should still be hard-blocked"

    def test_package_lock_blocked(self):
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/package-lock.json b/package-lock.json\n"
            "--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch)
        assert not result.ok

    def test_production_file_allowed(self):
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/src/app/models.py b/src/app/models.py\n"
            "--- a/src/app/models.py\n+++ b/src/app/models.py\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch)
        assert result.ok

    def test_fail_to_pass_path_blocked(self):
        from maverick.coding_mode import defensive_validate
        # If FAIL_TO_PASS mentions src/foo.py::TestX::test_y, the agent
        # must not touch src/foo.py at all.
        patch = (
            "diff --git a/src/foo.py b/src/foo.py\n"
            "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(
            patch, fail_to_pass=["src/foo.py::TestX::test_y"],
        )
        assert not result.ok

    def test_opaque_off_disables_all_blocks(self):
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/tests/test_foo.py b/tests/test_foo.py\n"
            "--- a/tests/test_foo.py\n+++ b/tests/test_foo.py\n@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch, opaque=False)
        assert result.ok


class TestCheatingDetector:
    """Scale's Nov-2025 cheating detection blog: patches with >20%
    verbatim overlap to the gold are flagged. We refuse to submit
    them."""

    def test_high_overlap_rejected(self):
        """Substantive gold patch (>=30 tokens) — verbatim copy is the
        actual cheating signal and must be rejected.

        The detector skips tiny gold patches because those would flag
        legitimate independent solutions as cheating. Use a
        gold patch with enough substance (multiple lines + identifiers)
        to make a verbatim match meaningful.
        """
        from maverick.coding_mode import defensive_validate
        gold = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -1,12 +1,12 @@\n"
            "-def calculate_quarterly_growth(prev, current, market_segment):\n"
            "-    if prev == 0 or prev is None:\n"
            "-        return None\n"
            "-    raw_delta = current - prev\n"
            "-    return raw_delta / prev\n"
            "+def calculate_quarterly_growth(prev, current, market_segment):\n"
            "+    if prev in (0, None):\n"
            "+        return float('inf') if current else 0.0\n"
            "+    raw_delta = (current - prev) * adjustment_factor(market_segment)\n"
            "+    normalized_delta = normalize_for_segment(raw_delta, market_segment)\n"
            "+    return normalized_delta / abs(prev)\n"
        )
        # ours = verbatim copy of gold — the unambiguous cheating signal.
        result = defensive_validate(gold, gold_patch=gold)
        assert not result.ok
        assert result.fn_risk == "high"

    def test_low_overlap_passes(self):
        from maverick.coding_mode import defensive_validate
        gold = "diff --git a/x.py b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
        # Different fix entirely.
        ours = (
            "diff --git a/y.py b/y.py\n@@ -100,2 +100,2 @@\n"
            "-frobnicate(z)\n+frobnicate(z, mode='careful')\n"
        )
        result = defensive_validate(ours, gold_patch=gold)
        assert result.ok


class TestWhitespaceOnly:
    def test_whitespace_only_warned(self):
        from maverick.coding_mode import defensive_validate
        patch = (
            "diff --git a/foo.py b/foo.py\n"
            "--- a/foo.py\n+++ b/foo.py\n"
            "@@ -1 +1 @@\n"
            "-    \n"
            "+\t\n"
        )
        result = defensive_validate(patch)
        # ok=True (no forbidden paths) but flagged high-FN risk.
        assert result.fn_risk == "high"
        assert any("whitespace" in w for w in result.warnings)


class TestCheatingDetectorMinSize:
    """The cheating detector skips small gold patches where any agent
    would produce the same code independently (e.g. a 5-line gold patch
    whose independent correct fix matches 100% of gold tokens)."""

    def test_tiny_obvious_gold_does_not_trigger_false_positive(self):
        from maverick.coding_mode import defensive_validate
        # Tiny gold — adding an empty-name guard. ~10 tokens.
        gold = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -10,3 +10,5 @@\n"
            "+    if not name:\n"
            "+        raise ValueError('empty name')\n"
            "     other_code = True\n"
        )
        # Agent independently produces the same fix.
        ours = gold
        result = defensive_validate(ours, gold_patch=gold)
        # Should NOT be rejected — gold is too small for the cheating
        # signal to be meaningful.
        assert result.ok, (
            "tiny gold patch should be exempt from cheating detection "
            "to avoid false positives on obvious independent fixes"
        )

    def test_tiny_exact_match_emits_forensic_warning(self):
        """Below the 30-token threshold, byte-identical copies are not
        rejected (to avoid false positives), but they DO emit a
        non-blocking warning so the operator can spot-check later.
        Independent reproductions of obvious fixes almost never come
        out byte-for-byte identical.
        """
        from maverick.coding_mode import defensive_validate
        gold = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -10,3 +10,5 @@\n"
            "+    if not name:\n"
            "+        raise ValueError('empty name')\n"
            "     other_code = True\n"
        )
        result = defensive_validate(gold, gold_patch=gold)
        assert result.ok
        assert any(
            "tiny gold patch matched byte-for-byte" in w
            for w in result.warnings
        ), f"missing forensic warning; got {result.warnings}"

    def test_tiny_non_exact_does_not_warn(self):
        """When the tiny candidate is NOT byte-identical to gold, no
        warning is emitted — independent reproductions are exempt."""
        from maverick.coding_mode import defensive_validate
        gold = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -10,3 +10,5 @@\n"
            "+    if not name:\n"
            "+        raise ValueError('empty name')\n"
        )
        ours = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -10,3 +10,5 @@\n"
            "+    if name is None:\n"
            "+        raise ValueError('name required')\n"
        )
        result = defensive_validate(ours, gold_patch=gold)
        assert result.ok
        assert not any(
            "tiny gold patch matched byte-for-byte" in w
            for w in result.warnings
        )

    def test_substantive_gold_still_catches_real_copy(self):
        """The detector engages once gold has enough substance (>=30
        tokens by the _substantive() tokenizer, which only counts
        `+` lines minus diff syntax)."""
        from maverick.coding_mode import defensive_validate
        # Patch with 40+ substantive identifier tokens on `+` lines.
        gold = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -1,10 +1,15 @@\n"
            "+def process_intricate_calculation(values, weights, normalize_strategy):\n"
            "+    intermediate_total = sum(value * weight for value, weight in zip(values, weights))\n"
            "+    if normalize_strategy == 'mean' and weights:\n"
            "+        intermediate_total = intermediate_total / sum(weights)\n"
            "+    elif normalize_strategy == 'softmax':\n"
            "+        intermediate_total = softmax_normalize(intermediate_total, temperature_parameter)\n"
            "+    elif normalize_strategy == 'minmax':\n"
            "+        intermediate_total = minmax_normalize(intermediate_total, lower_bound, upper_bound)\n"
            "+    return intermediate_total\n"
        )
        result = defensive_validate(gold, gold_patch=gold)
        # Substantive verbatim copy IS rejected.
        assert not result.ok, (
            f"verbatim copy should be rejected; warnings={result.warnings}"
        )


class TestQuotedPaths:
    """git quotes paths with spaces / non-ASCII.
    A plain \\S+ regex matches only the first whitespace-delimited
    segment, silently bypassing the test-file blocker."""

    def test_path_with_space_extracted(self):
        from maverick.coding_mode import _extract_diff_paths
        patch = (
            'diff --git "a/dir with space/foo.py" "b/dir with space/foo.py"\n'
            '--- "a/dir with space/foo.py"\n'
            '+++ "b/dir with space/foo.py"\n'
            "@@ -1 +1 @@\n-x\n+y\n"
        )
        paths = _extract_diff_paths(patch)
        assert "dir with space/foo.py" in paths

    def test_quoted_test_file_still_blocked(self):
        """The real teeth: quoted test paths must still be caught by
        the forbidden-paths blocker."""
        from maverick.coding_mode import defensive_validate
        patch = (
            'diff --git "a/tests/with space/test_foo.py" '
            '"b/tests/with space/test_foo.py"\n'
            '--- "a/tests/with space/test_foo.py"\n'
            '+++ "b/tests/with space/test_foo.py"\n'
            "@@ -1 +1 @@\n-x\n+y\n"
        )
        result = defensive_validate(patch)
        assert not result.ok, "quoted-path test files must still be blocked"


class TestTokenizedCheatingDetector:
    """Token-level overlap is more meaningful
    than character-level and immune to whitespace games."""

    def test_whitespace_diff_does_not_reduce_overlap(self):
        from maverick.coding_mode import defensive_validate
        # Substantive gold (>=30 substantive `+`-line tokens) so the
        # cheating detector actually engages.
        gold = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -1,12 +1,12 @@\n"
            "+def calculate_compound_interest_schedule(principal_amount, annual_rate, years_horizon, compounding_freq, currency_code):\n"
            "+    effective_periodic_rate = annual_rate / hundred_constant / compounding_freq\n"
            "+    total_compounding_periods = years_horizon * compounding_freq\n"
            "+    growth_multiplier = single_period_growth ** total_compounding_periods\n"
            "+    final_value_amount = principal_amount * growth_multiplier\n"
            "+    accrued_interest_amount = final_value_amount - principal_amount\n"
            "+    rounded_accrued_amount = round_to_currency_precision(accrued_interest_amount, currency_code)\n"
            "+    annual_yield_percentage = compute_annual_yield(rounded_accrued_amount, principal_amount, years_horizon)\n"
            "+    formatted_result_payload = format_currency_result(rounded_accrued_amount, currency_code, annual_yield_percentage)\n"
            "+    return formatted_result_payload\n"
        )
        # Same tokens, different whitespace — should still flag.
        ours = (
            "diff --git a/foo.py b/foo.py\n"
            "@@ -1,12 +1,12 @@\n"
            "+def calculate_compound_interest_schedule(principal_amount , annual_rate , years_horizon , compounding_freq , currency_code):\n"
            "+    effective_periodic_rate = annual_rate / hundred_constant / compounding_freq\n"
            "+    total_compounding_periods = years_horizon * compounding_freq\n"
            "+    growth_multiplier = single_period_growth ** total_compounding_periods\n"
            "+    final_value_amount = principal_amount * growth_multiplier\n"
            "+    accrued_interest_amount = final_value_amount - principal_amount\n"
            "+    rounded_accrued_amount = round_to_currency_precision(accrued_interest_amount, currency_code)\n"
            "+    annual_yield_percentage = compute_annual_yield(rounded_accrued_amount, principal_amount, years_horizon)\n"
            "+    formatted_result_payload = format_currency_result(rounded_accrued_amount, currency_code, annual_yield_percentage)\n"
            "+    return formatted_result_payload\n"
        )
        result = defensive_validate(ours, gold_patch=gold)
        assert not result.ok, (
            "token-level matcher should catch this; "
            "whitespace tricks don't fool it"
        )

    def test_different_implementation_passes(self):
        from maverick.coding_mode import defensive_validate
        gold = (
            "diff --git a/x.py b/x.py\n@@ -1,3 +1,3 @@\n"
            "-def f():\n-    return 1\n+def f():\n+    return 2\n"
        )
        ours = (
            "diff --git a/y.py b/y.py\n@@ -1,3 +1,3 @@\n"
            "-class Helper:\n-    pass\n"
            "+class Helper:\n"
            "+    def transform(self, payload): return payload.upper()\n"
        )
        result = defensive_validate(ours, gold_patch=gold)
        assert result.ok


class TestASTCheck:
    def test_clean_python_passes(self, tmp_path):
        from maverick.coding_mode import _ast_check_python_files
        (tmp_path / "ok.py").write_text("def f():\n    return 1\n")
        errors = _ast_check_python_files(tmp_path, ["ok.py"])
        assert errors == []

    def test_syntax_error_caught(self, tmp_path):
        from maverick.coding_mode import _ast_check_python_files
        (tmp_path / "broken.py").write_text("def f(:\n    return 1\n")
        errors = _ast_check_python_files(tmp_path, ["broken.py"])
        assert len(errors) == 1
        assert "broken.py" in errors[0]

    def test_non_python_skipped(self, tmp_path):
        from maverick.coding_mode import _ast_check_python_files
        (tmp_path / "broken.js").write_text("function f({ {{{")
        errors = _ast_check_python_files(tmp_path, ["broken.js"])
        assert errors == []

    def test_missing_file_ignored(self, tmp_path):
        from maverick.coding_mode import _ast_check_python_files
        errors = _ast_check_python_files(tmp_path, ["nonexistent.py"])
        assert errors == []


class TestForbiddenPathPrecision:
    """The grader-integrity blocker must catch real test files without
    over-blocking production modules that merely start with 'test'."""

    def _patch(self, path: str) -> str:
        return (
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n+++ b/{path}\n"
            "@@ -1 +1 @@\n-x\n+y\n"
        )

    def test_production_modules_named_test_prefix_not_blocked(self):
        from maverick.coding_mode import defensive_validate
        for path in ("testing.py", "testutils.py", "testimonials.py",
                     "pkg/testing.py"):
            result = defensive_validate(self._patch(path))
            assert path not in result.blocked_paths, f"{path} wrongly blocked"

    def test_real_test_files_still_blocked(self):
        from maverick.coding_mode import defensive_validate
        for path in ("test_foo.py", "tests.py", "test.py", "testfoo.py",
                     "pkg/testfoo.py", "foo_test.py", "foo_tests.py",
                     "tests/x.py"):
            result = defensive_validate(self._patch(path))
            assert not result.ok, f"{path} should be blocked"
