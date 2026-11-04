"""One truth about whether an AI service is connected (provider_readiness)."""
from __future__ import annotations

import pytest
from maverick.config import PROVIDER_BASE_URL_ENV_VARS, PROVIDER_CREDENTIAL_ENV_VARS


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A fresh install: no keys in the environment, config.toml under tmp."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    for name in (*PROVIDER_CREDENTIAL_ENV_VARS, *PROVIDER_BASE_URL_ENV_VARS,
                 "MAVERICK_MODEL_OVERRIDE", "UNSET_TEST_VAR", "MAVERICK_ENTERPRISE"):
        monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    from maverick import config
    from maverick_dashboard import integration_readiness

    config.reset_config_cache()
    integration_readiness._clear_for_testing()

    def write(text: str) -> None:
        config_path.write_text(text, encoding="utf-8")
        config.reset_config_cache()

    yield write
    config.reset_config_cache()
    integration_readiness._clear_for_testing()


def _record(name: str, *, verified: bool, detail: str = "") -> None:
    from maverick.config import get_provider_config
    from maverick_dashboard import integration_readiness

    integration_readiness.record(
        "provider", name, get_provider_config(name) or {},
        verified=verified,
        detail=detail or ("provider accepted the bounded models request" if verified
                          else "provider probe failed (ConnectError)"),
    )


def _row(readiness: dict, name: str) -> dict:
    return next(row for row in readiness["providers"] if row["name"] == name)


def test_unset_env_placeholder_is_not_configured(workspace):
    from maverick_dashboard.provider_readiness import workspace_readiness

    workspace('[providers.anthropic]\napi_key = "${UNSET_TEST_VAR}"\n')
    readiness = workspace_readiness()
    anthropic = _row(readiness, "anthropic")
    assert anthropic["configured"] is False
    assert anthropic["status"] == "not_set_up"
    assert anthropic["routed"] is True and "orchestrator" in anthropic["used_by_roles"]
    assert readiness["configured_count"] == 0 and readiness["connected_count"] == 0
    assert readiness["verdict"] == "not_ready"
    assert readiness["verdict_label"] == "Not connected"
    assert "Anthropic (Claude) is not set up" in readiness["reason"]
    assert readiness["next_action"] == {
        "label": "Add an AI provider key", "href": "/settings#settings-integrations"}


def test_hosted_service_with_only_a_proxy_address_is_not_set_up(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://proxy.example.test")
    workspace("")
    anthropic = _row(workspace_readiness(), "anthropic")
    assert anthropic["configured"] is False and anthropic["status"] == "not_set_up"


def test_every_known_provider_is_reported(workspace):
    from maverick.providers import KNOWN_PROVIDERS
    from maverick_dashboard.provider_readiness import workspace_readiness

    workspace("")
    readiness = workspace_readiness()
    assert [row["name"] for row in readiness["providers"]] == list(KNOWN_PROVIDERS)
    assert readiness["total"] == len(KNOWN_PROVIDERS)
    for row in readiness["providers"]:
        assert row["status"] == "not_set_up" and row["last_test"]["status"] == "never"
        assert row["label"] and "_" not in row["label"]


def test_key_saved_but_never_tested_needs_test(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    readiness = workspace_readiness()
    openai = _row(readiness, "openai")
    assert openai["configured"] is True and openai["status"] == "untested"
    assert openai["status_label"] == "Key saved, not tested yet"
    assert openai["last_test"]["status"] == "never"
    assert readiness["verdict"] == "needs_test"
    # The workspace verdict covers keyless providers too, so it says "set up".
    assert readiness["verdict_label"] == "Set up, not tested yet"
    assert readiness["next_action"] == {"label": "Test the connection", "href": "/providers"}
    assert readiness["summary"] == "1 set up · 0 connected"
    # A key that was never tested is never called "connected".
    assert "connected" not in readiness["reason"].lower()


def test_passing_test_makes_the_workspace_ready(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    _record("openai", verified=True)
    readiness = workspace_readiness()
    openai = _row(readiness, "openai")
    assert openai["status"] == "connected" and openai["status_label"] == "Connected"
    assert openai["last_test"]["status"] == "passed"
    assert openai["last_test"]["tested_at"]
    assert readiness["verdict"] == "ready" and readiness["next_action"] is None
    assert readiness["summary"] == "1 set up · 1 connected"


def test_failed_test_is_not_ready_with_a_plain_reason(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    _record("openai", verified=False)
    readiness = workspace_readiness()
    openai = _row(readiness, "openai")
    assert openai["status"] == "failed"
    assert openai["status_label"].startswith("Connection failed: ")
    assert "ConnectError" not in openai["status_label"]
    assert "could not reach the service" in openai["reason"]
    assert openai["last_test"]["status"] == "failed"
    assert openai["last_test"]["detail"] == "provider probe failed (ConnectError)"
    assert readiness["verdict"] == "not_ready"
    assert readiness["reason"].startswith("OpenAI connection failed: ")
    assert readiness["next_action"]["href"] == "/providers"


def test_one_failed_and_one_passed_across_two_providers(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    # Roles split across two providers: every provider the models use counts.
    workspace('[models]\norchestrator = "openai:gpt-test"\n')
    _record("openai", verified=True)
    _record("anthropic", verified=False, detail="provider readiness request returned HTTP 401")
    readiness = workspace_readiness()
    assert _row(readiness, "openai")["status"] == "connected"
    anthropic = _row(readiness, "anthropic")
    assert anthropic["status"] == "failed"
    assert "did not accept the key" in anthropic["reason"]
    assert readiness["verdict"] == "not_ready"
    assert readiness["summary"] == "2 set up · 1 connected"
    # Fix the failing one and the workspace is ready.
    _record("anthropic", verified=True)
    fixed = workspace_readiness()
    assert fixed["verdict"] == "ready"
    assert "OpenAI" in fixed["reason"] and "Anthropic (Claude)" in fixed["reason"]


def test_configured_provider_that_no_model_uses_does_not_make_ready(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    workspace("")  # default roles route to anthropic, which has no key
    _record("openai", verified=True)
    readiness = workspace_readiness()
    assert _row(readiness, "openai")["status"] == "connected"
    assert _row(readiness, "openai")["routed"] is False
    assert readiness["verdict"] == "not_ready"
    assert "Anthropic (Claude) is not set up" in readiness["reason"]
    assert "OpenAI is connected but no model uses it" in readiness["reason"]
    assert readiness["next_action"] == {"label": "Choose models", "href": "/settings#settings-models"}


def test_wizard_default_ollama_server_address_is_set_up_but_not_connected(workspace):
    from maverick_dashboard.provider_readiness import workspace_readiness

    workspace('[providers.ollama]\nbase_url = "http://localhost:11434"\n')
    readiness = workspace_readiness()
    ollama = _row(readiness, "ollama")
    assert ollama["configured"] is True and ollama["status"] == "untested"
    assert ollama["status_label"] == "Server address saved, not tested yet"
    assert readiness["configured_count"] == 1 and readiness["connected_count"] == 0
    assert readiness["verdict"] == "not_ready"  # the models still use Anthropic
    assert readiness["verdict_label"] != "Connected"


def test_stale_receipt_after_a_key_change_counts_as_never_tested(workspace, monkeypatch):
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace('[providers.openai]\napi_key = "sk-old"\n')  # pragma: allowlist secret
    _record("openai", verified=True)
    assert workspace_readiness()["verdict"] == "ready"
    workspace('[providers.openai]\napi_key = "sk-new"\n')  # pragma: allowlist secret
    assert workspace_readiness()["verdict"] == "needs_test"


def test_unreadable_configuration_is_a_plain_not_ready_verdict(workspace, monkeypatch):
    from maverick_dashboard import provider_readiness

    workspace("")

    def boom():
        raise RuntimeError("disk")

    monkeypatch.setattr(provider_readiness, "provider_labels", boom)
    readiness = provider_readiness.workspace_readiness()
    assert readiness["verdict"] == "not_ready" and readiness["providers"] == []
    assert readiness["next_action"]["href"].startswith("/settings")
    assert "disk" not in readiness["reason"]


@pytest.mark.parametrize("detail, expected", [
    ("provider readiness request returned HTTP 302", "redirected the test"),
    ("provider readiness request returned HTTP 401", "did not accept the key"),
    ("provider readiness request returned HTTP 429", "reached its limit"),
    ("provider readiness request returned HTTP 503", "problem on its side"),
    ("provider endpoint is blocked by the egress policy", "outbound-connection rules"),
    ("provider probe failed (ConnectError)", "could not reach the service"),
    ("openai SDK not installed. From the reviewed checkout run: pip", "Software this service needs"),
    ("configured Codex CLI binary was not found", "not installed"),
    ("something new", "did not work"),
])
def test_plain_reason_never_leaks_technical_wording(detail, expected):
    from maverick_dashboard.provider_readiness import plain_reason

    reason = plain_reason(detail)
    assert expected in reason
    for word in ("HTTP 4", "ConnectError", "SDK", "egress", "probe", "binary"):
        assert word not in reason


# ---- persisted test receipts -------------------------------------------------

def _receipts_file(tmp_path):
    return tmp_path / "mvhome" / "provider_test_receipts.json"


def test_receipt_survives_a_fresh_process(workspace, monkeypatch, tmp_path):
    """The receipt is written privately (POSIX 0600 or Windows DACL) and is
    read back once the in-process memory is gone, as after a restart."""
    import json

    from maverick.file_lock import private_path_is_restricted
    from maverick_dashboard import integration_readiness
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    _record("openai", verified=True)
    path = _receipts_file(tmp_path)
    assert path.exists()
    assert private_path_is_restricted(path, 0o600)
    text = path.read_text(encoding="utf-8")
    assert "sk-test" not in text
    stored = json.loads(text)["providers"]["openai"]
    assert stored["verified"] is True and len(stored["fingerprint"]) == 64
    integration_readiness._clear_for_testing()  # a new process has no memory
    readiness = workspace_readiness()
    assert readiness["verdict"] == "ready"
    assert _row(readiness, "openai")["last_test"]["tested_at"] == stored["tested_at"]


def test_two_workers_saving_receipts_at_once_do_not_drop_each_other(workspace, tmp_path, monkeypatch):
    """Each dashboard worker holds only its own in-process lock, so the file's
    read-modify-write has to serialize across processes. Worker one reads, then
    worker two saves a receipt in full before worker one writes."""
    import json
    import threading
    import time

    from maverick_dashboard import integration_readiness

    one_has_read, two_is_done = threading.Event(), threading.Event()
    plain = integration_readiness._load_persisted

    def load():
        rows = plain()
        if threading.current_thread().name == "worker-one":
            one_has_read.set()
            two_is_done.wait(0.5)
        return rows

    monkeypatch.setattr(integration_readiness, "_load_persisted", load)
    receipt = {"status": "verified", "verified": True, "detail": "ok", "tested_at": time.time(),
               "evidence": {}, "fingerprint": "f" * 64}

    def worker_two():
        one_has_read.wait(5)
        integration_readiness._persist("two", receipt)
        two_is_done.set()

    threads = [
        threading.Thread(target=integration_readiness._persist, args=("one", receipt), name="worker-one"),
        threading.Thread(target=worker_two, name="worker-two"),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    stored = json.loads(_receipts_file(tmp_path).read_text(encoding="utf-8"))["providers"]
    assert set(stored) == {"one", "two"}


def test_failed_receipt_survives_a_fresh_process_with_its_plain_reason(workspace, monkeypatch, tmp_path):
    import json

    from maverick_dashboard import integration_readiness
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    _record("openai", verified=False, detail="provider readiness request returned HTTP 401")
    stored = json.loads(_receipts_file(tmp_path).read_text(encoding="utf-8"))["providers"]["openai"]
    assert "did not accept the key" in stored["reason"]
    integration_readiness._clear_for_testing()
    openai = _row(workspace_readiness(), "openai")
    assert openai["status"] == "failed" and "did not accept the key" in openai["reason"]


def test_receipt_older_than_max_age_reads_as_not_tested_yet(workspace, monkeypatch, tmp_path):
    from maverick_dashboard import integration_readiness
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    _record("openai", verified=True)
    integration_readiness._clear_for_testing()
    real_time = integration_readiness.time.time
    monkeypatch.setattr(integration_readiness.time, "time", lambda: real_time() + 31 * 86400)
    readiness = workspace_readiness()
    openai = _row(readiness, "openai")
    assert openai["status"] == "untested"
    assert openai["status_label"] == "Key saved, not tested yet"
    assert "Last successful test was 31 days ago." in openai["reason"]
    assert readiness["verdict"] == "needs_test"
    assert "Last successful test was 31 days ago." in readiness["reason"]
    assert ">Connected<" not in readiness["verdict_label"]
    # A longer configured window keeps the receipt valid.
    monkeypatch.setenv("MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS", "60")
    assert workspace_readiness()["verdict"] == "ready"
    monkeypatch.delenv("MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS")
    workspace("[providers]\ntest_receipt_max_age_days = 45\n")
    assert workspace_readiness()["verdict"] == "ready"


def test_max_age_knob_defaults_and_clamps(workspace, monkeypatch):
    from maverick.config import provider_test_receipt_max_age_days

    workspace("")
    assert provider_test_receipt_max_age_days() == 30
    workspace("[providers]\ntest_receipt_max_age_days = 0\n")
    assert provider_test_receipt_max_age_days() == 1
    workspace('[providers]\ntest_receipt_max_age_days = "soon"\n')
    assert provider_test_receipt_max_age_days() == 30
    monkeypatch.setenv("MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS", "7")
    assert provider_test_receipt_max_age_days() == 7


def test_stored_receipt_is_ignored_after_the_key_changes(workspace, monkeypatch):
    from maverick_dashboard import integration_readiness
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace('[providers.openai]\napi_key = "sk-old"\n')  # pragma: allowlist secret
    _record("openai", verified=True)
    integration_readiness._clear_for_testing()
    assert workspace_readiness()["verdict"] == "ready"
    workspace('[providers.openai]\napi_key = "sk-new"\n')  # pragma: allowlist secret
    assert workspace_readiness()["verdict"] == "needs_test"
    assert _row(workspace_readiness(), "openai")["last_test"]["status"] == "never"


def test_unreadable_receipt_file_means_never_tested_without_crashing(workspace, monkeypatch, tmp_path):
    from maverick_dashboard import integration_readiness
    from maverick_dashboard.provider_readiness import workspace_readiness

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace("")
    path = _receipts_file(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    readiness = workspace_readiness()
    assert readiness["verdict"] == "needs_test"
    assert _row(readiness, "openai")["last_test"]["status"] == "never"
    # A directory in the file's place is just as harmless, and a new receipt
    # that cannot be saved still counts in this process.
    path.unlink()
    path.mkdir()
    _record("openai", verified=True)
    assert workspace_readiness()["verdict"] == "ready"
    integration_readiness._clear_for_testing()
    assert workspace_readiness()["verdict"] == "needs_test"
