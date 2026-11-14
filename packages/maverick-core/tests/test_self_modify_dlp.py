"""Fail-closed secret detection for self-modification data paths."""
from __future__ import annotations

from maverick.safety.self_modify_dlp import _has_lowercase_secret_literal


def test_lowercase_secret_patterns_are_linear_on_blank_lines():
    # Two adjacent \s* before "=" split a run of blank lines every possible
    # way, so "password" followed by many blank lines was quadratic. The
    # same assignments, annotated or split across lines, are still caught.
    assert _has_lowercase_secret_literal("password" + "\n" * 50_000) is False
    assert _has_lowercase_secret_literal('password = "s3cr3tvalue"')
    assert _has_lowercase_secret_literal('cfg.password: str\n= "s3cr3tvalue"')
    assert _has_lowercase_secret_literal("db_password = Zx9vQ2mL7pR4tK")
    assert not _has_lowercase_secret_literal('password = "changeme-please"')
