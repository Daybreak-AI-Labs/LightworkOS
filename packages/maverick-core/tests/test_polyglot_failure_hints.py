"""Repair-loop failure hints for Rust / Go / TypeScript (polyglot coding-mode).

classify_failure() turns a failed test/build run into a (class, hint) pair that
the best-of-N repair loop injects as targeted revision guidance. It was
Python-exception-only; these pin the new toolchain classes and -- critically --
that adding them did NOT shadow the existing Python classification (the Python
exception patterns are listed first and win on Python output).
"""
from maverick.coding_mode import classify_failure

# ---------- Rust ----------

def test_rust_compile_error_classified():
    out = "error[E0425]: cannot find value `foo` in this scope\n --> src/lib.rs:3:5"
    name, hint = classify_failure(out)
    assert name == "RustCompileError"
    assert "compile" in hint.lower() and hint


def test_rust_mismatched_types_classified():
    name, _ = classify_failure("error[E0308]: mismatched types\n expected `u32`, found `&str`")
    assert name == "RustCompileError"


def test_rust_panic_classified():
    out = (
        "thread 'tests::it_adds' panicked at src/lib.rs:10:5:\n"
        "assertion `left == right` failed\n  left: 4\n right: 5"
    )
    name, hint = classify_failure(out)
    assert name == "RustPanic"
    assert hint


# ---------- Go ----------

def test_go_build_error_classified():
    out = "# example.com/m\n./calc.go:12:6: undefined: Helper"
    name, hint = classify_failure(out)
    assert name == "GoBuildError"
    assert hint


def test_go_panic_classified():
    out = "panic: runtime error: index out of range [3] with length 3\n\ngoroutine 1 [running]:"
    name, hint = classify_failure(out)
    assert name == "GoPanic"
    assert hint


# ---------- TypeScript ----------

def test_typescript_error_classified():
    out = "src/index.ts(5,7): error TS2304: Cannot find name 'foo'."
    name, hint = classify_failure(out)
    assert name == "TypeScriptError"
    assert hint


def test_typescript_not_assignable_classified():
    name, _ = classify_failure("error TS2345: Argument of type 'string' is not assignable to parameter of type 'number'.")
    assert name == "TypeScriptError"


# ---------- regression: Python classification is unchanged ----------

def test_python_importerror_still_wins():
    name, _ = classify_failure("E   ImportError: cannot import name 'x' from 'pkg'")
    assert name == "ImportError"


def test_python_assertionerror_not_misread_as_rust_panic():
    # pytest assertion output must stay AssertionError, not leak into RustPanic.
    name, _ = classify_failure("E   AssertionError: assert 1 == 2")
    assert name == "AssertionError"


def test_timeout_still_wins_for_any_language():
    name, _ = classify_failure("running cargo test...\nTIMEOUT after 600s\nexit 124")
    assert name == "Timeout"


def test_timeout_wins_over_polyglot_diagnostics():
    mixed_outputs = [
        "error[E0308]: mismatched types\nTIMEOUT after 600s\nexit 124",
        "thread 'tests::it_adds' panicked at src/lib.rs:10:5:\nTIMEOUT after 600s",
        "./calc.go:12:6: undefined: Helper\nTIMEOUT after 600s",
        "panic: runtime error: index out of range\nexit 124",
        "src/index.ts(5,7): error TS2304: Cannot find name 'foo'.\nTIMEOUT after 600s",
    ]
    for out in mixed_outputs:
        name, hint = classify_failure(out)
        assert name == "Timeout"
        assert "longer than the budget" in hint


def test_clean_output_is_other():
    assert classify_failure("ok. 5 passed") == ("other", "")
    assert classify_failure("") == ("other", "")
