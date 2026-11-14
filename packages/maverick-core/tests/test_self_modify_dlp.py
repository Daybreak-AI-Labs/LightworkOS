"""Fail-closed secret detection for self-modification data paths."""
from __future__ import annotations

from maverick.safety.self_modify_dlp import (
    _has_lowercase_secret_literal,
    contains_secret_material,
)


def test_lowercase_secret_patterns_are_linear_on_blank_lines():
    # Two adjacent \s* before "=" split a run of blank lines every possible
    # way, so "password" followed by many blank lines (or an annotation colon
    # followed by many spaces) backtracked. Assignments are still caught.
    assert _has_lowercase_secret_literal("password" + "\n" * 50_000) is False
    assert contains_secret_material("password:" + " " * 50_000 + "x") is False
    assert _has_lowercase_secret_literal('password = "s3cr3tvalue"')  # pragma: allowlist secret
    assert _has_lowercase_secret_literal('cfg.password: str = "s3cr3tvalue"')
    assert _has_lowercase_secret_literal("db_password = Zx9vQ2mL7pR4tK")
    assert not _has_lowercase_secret_literal('password = "changeme-please"')  # pragma: allowlist secret
