"""Closed default-off configuration for the managed customer sandbox lifecycle."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def test_customer_sandbox_lifecycle_is_known_closed_and_default_off() -> None:
    assert "customer_sandbox_lifecycle" in KNOWN_SECTIONS
    assert lint_config(
        {"customer_sandbox_lifecycle": {"enable": False, "source_revision": 1}}
    ) == []
    unknown = lint_config(
        {"customer_sandbox_lifecycle": {"enable": False, "workspace_root": "C:/unsafe"}}
    )
    assert any(
        finding.key == "workspace_root" and "unknown" in finding.message.lower()
        for finding in unknown
    )


def test_customer_sandbox_gate_and_revision_types_fail_closed() -> None:
    for config in (
        {"customer_sandbox_lifecycle": {"enable": "true"}},
        {"customer_sandbox_lifecycle": {"source_revision": 0}},
        {"customer_sandbox_lifecycle": {"source_revision": True}},
        {"customer_sandbox_lifecycle": {"source_revision": 2**31}},
    ):
        findings = lint_config(config)
        assert any(finding.severity == "error" for finding in findings), findings
