"""[knowledge_sources] limits: config-lint reports a value the runtime would refuse."""
from __future__ import annotations

from maverick.config_lint import lint_config


def _messages(config: dict) -> list[str]:
    return [finding.message for finding in lint_config(config)]


def test_whole_number_knowledge_sources_limits_lint_clean() -> None:
    config = {"knowledge_sources": {"max_items": 200, "max_pages": 16, "max_download_mib": 8, "max_text_kib": 512}}
    assert not [message for message in _messages(config) if "knowledge_sources" in message]


def test_a_fractional_knowledge_sources_limit_is_an_error() -> None:
    messages = _messages({"knowledge_sources": {"max_items": 64.5}})
    assert "knowledge_sources.max_items must be an integer, got float" in messages


def test_a_fractional_refresh_time_limit_is_an_error() -> None:
    messages = _messages({"knowledge_sources": {"max_refresh_minutes": 5.5}})
    assert "knowledge_sources.max_refresh_minutes must be an integer, got float" in messages
