"""Failure-class router for test-driven revision."""
from __future__ import annotations


class TestClassifyFailure:
    def test_import_error(self):
        from maverick.coding_mode import classify_failure
        out = "Traceback (most recent call last):\n  File ...\nImportError: cannot import name 'foo'"
        name, hint = classify_failure(out)
        assert name == "ImportError"
        assert "import" in hint.lower()

    def test_module_not_found(self):
        from maverick.coding_mode import classify_failure
        out = "ModuleNotFoundError: No module named 'mymod'"
        name, _ = classify_failure(out)
        assert name == "ImportError"

    def test_attribute_error(self):
        from maverick.coding_mode import classify_failure
        name, hint = classify_failure("AttributeError: 'NoneType' object has no attribute 'foo'")
        assert name == "AttributeError"
        assert "method" in hint.lower() or "attribute" in hint.lower()

    def test_type_error(self):
        from maverick.coding_mode import classify_failure
        name, _ = classify_failure("TypeError: f() takes 2 positional arguments but 3 were given")
        assert name == "TypeError"

    def test_assertion_error(self):
        from maverick.coding_mode import classify_failure
        name, hint = classify_failure(
            "  >       assert result == expected\nE       AssertionError"
        )
        assert name == "AssertionError"
        assert "production" in hint.lower() or "expected" in hint.lower()

    def test_syntax_error(self):
        from maverick.coding_mode import classify_failure
        out = "  File 'foo.py', line 5\n    def f(:\n          ^\nSyntaxError: invalid syntax"
        name, _ = classify_failure(out)
        assert name == "SyntaxError"

    def test_indentation_error(self):
        from maverick.coding_mode import classify_failure
        name, _ = classify_failure("IndentationError: unexpected indent")
        assert name == "IndentationError"

    def test_timeout(self):
        from maverick.coding_mode import classify_failure
        name, hint = classify_failure("TIMEOUT after 60s\nexit 124")
        assert name == "Timeout"
        assert "loop" in hint.lower() or "infinite" in hint.lower()

    def test_other_falls_back(self):
        from maverick.coding_mode import classify_failure
        name, hint = classify_failure("some random output")
        assert name == "other"
        assert hint == ""

    def test_empty_output(self):
        from maverick.coding_mode import classify_failure
        assert classify_failure("") == ("other", "")
        assert classify_failure(None) == ("other", "")

    def test_more_specific_class_wins_over_assertion(self):
        # An ImportError that ALSO contains the word "assert" should
        # still be classified as ImportError (first match wins, more
        # specific classes are listed earlier).
        from maverick.coding_mode import classify_failure
        out = "ImportError: foo\n  asserted at line 5"
        name, _ = classify_failure(out)
        assert name == "ImportError"
