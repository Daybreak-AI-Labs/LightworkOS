"""The in-product service banner: what is affected, what happens to
running tasks, and when Lightwork checks again, from a faked breaker state."""
from __future__ import annotations

from maverick import circuit_breaker, service_status


def _row(provider, state, *, opened_at=1000.0, cooldown=30.0):
    return {"key": f"llm:{provider}", "state": state, "opened_at": opened_at, "cooldown_seconds": cooldown}


def test_no_banner_while_every_ai_service_is_working():
    rows = [_row("anthropic", "closed"), {"key": "tool:web_search", "state": "open"}]
    assert service_status.current(breakers=rows, in_use={"anthropic"}) is None


def test_one_paused_service_with_a_healthy_backup_reads_reduced_not_down():
    status = service_status.current(breakers=[_row("anthropic", "open")], in_use={"anthropic", "openai"})
    assert status["level"] == "reduced"
    assert status["affected"] == "Anthropic"
    assert "still working with OpenAI" in status["title"]
    assert "backup model" in status["tasks"] and "Failed" in status["tasks"]
    assert status["checks"] == [{"provider": "Anthropic", "at": 1030.0}]
    assert status["alternative"] == "Meanwhile, start new work as usual: it uses OpenAI."


def test_every_service_in_use_paused_reads_down_and_says_what_happens_to_tasks():
    status = service_status.current(breakers=[_row("anthropic", "open"), _row("openai", "open", cooldown=60)],
                                    in_use={"anthropic", "openai"})
    assert status["level"] == "down"
    assert status["title"].startswith("Anthropic and OpenAI are paused")
    assert status["tasks"] == service_status.TASKS_DOWN
    assert "kept" in status["tasks"] and "run them again" in status["tasks"]
    assert [check["at"] for check in status["checks"]] == [1030.0, 1060.0]
    # And another way to carry on meanwhile.
    assert status["alternative"] == service_status.ALTERNATIVE_DOWN and "Settings > AI models" in status["alternative"]


def test_a_service_being_tested_again_says_so_instead_of_a_time():
    status = service_status.current(breakers=[_row("anthropic", "half_open")], in_use={"anthropic"})
    assert status["checks"] == [{"provider": "Anthropic", "at": None}]


def test_live_breaker_snapshot_carries_the_cooldown_the_banner_needs(monkeypatch):
    circuit_breaker.reset_all()
    try:
        breaker = circuit_breaker.get("llm:anthropic", failure_threshold=2, cooldown_seconds=45)
        breaker.record_failure()
        breaker.record_failure()
        monkeypatch.setattr(service_status, "providers_in_use", lambda: {"anthropic"})
        status = service_status.current()
        assert status["level"] == "down"
        snapshot = next(row for row in circuit_breaker.snapshot() if row["key"] == "llm:anthropic")
        assert status["checks"][0]["at"] == snapshot["opened_at"] + 45
    finally:
        circuit_breaker.reset_all()


def test_providers_in_use_include_role_models_and_backup_chains(monkeypatch, tmp_path):
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text('[models]\norchestrator = "openai:gpt-4.1"\n'
                    '[provider_failover.chains]\n"openai:gpt-4.1" = ["gemini:gemini-2"]\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    config.reset_config_cache()
    try:
        used = service_status.providers_in_use()
    finally:
        config.reset_config_cache()
    assert {"openai", "gemini"} <= used


def test_support_settings_hide_anything_that_is_not_a_secure_address_or_email(monkeypatch, tmp_path):
    from maverick import config

    path = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    try:
        path.write_text('[support]\nstatus_page_url = "https://status.example.com"\n'
                        'contact_email = "help@example.com"\n', encoding="utf-8")
        config.reset_config_cache()
        assert config.get_support() == {"status_page_url": "https://status.example.com",
                                        "contact_email": "help@example.com"}
        path.write_text('[support]\nstatus_page_url = "http://status.example.com"\n'
                        'contact_email = "javascript:alert(1)"\n', encoding="utf-8")
        config.reset_config_cache()
        assert config.get_support() == {"status_page_url": "", "contact_email": ""}
    finally:
        config.reset_config_cache()


def test_a_route_scoped_breaker_reads_as_its_provider_not_its_raw_key():
    # llm._dispatch_client names a native client's breaker ``llm:<provider>:route:<sha256>``;
    # the banner must name the provider, and that paused provider must not read as healthy.
    route = "06fb22ec" * 8
    status = service_status.current(breakers=[_row(f"anthropic:route:{route}", "open")],
                                    in_use={"anthropic", "openai"})
    assert status["level"] == "reduced"
    assert status["affected"] == "Anthropic"
    assert status["healthy"] == ["OpenAI"]
    assert route not in status["title"] and "Route" not in status["title"]
    assert status["checks"] == [{"provider": "Anthropic", "at": 1030.0}]


def test_several_route_breakers_of_one_provider_are_one_paused_provider():
    rows = [_row("openai:route:" + "a" * 64, "open", opened_at=1000.0),
            _row("openai:route:" + "b" * 64, "half_open", opened_at=2000.0),
            _row("openai", "closed")]
    status = service_status.current(breakers=rows, in_use={"openai", "anthropic"})
    assert status["affected"] == "OpenAI"
    assert status["healthy"] == ["Anthropic"]
    assert len(status["checks"]) == 1
