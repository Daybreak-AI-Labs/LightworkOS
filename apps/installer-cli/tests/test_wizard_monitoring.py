"""The advanced wizard's "Monitoring and key management" step.

Each answer path is checked through the TOML it writes and the ~/.maverick/.env keys it
adds; a skipped question writes nothing. Credentials go to .env and never to config.toml.
The prompts are scripted: a question not in the script fails the test.
"""
from __future__ import annotations

import json

import pytest

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]

from maverick_installer import wizard

CREDENTIAL_ENV = (
    "MAVERICK_SIEM_TOKEN", "MAVERICK_DATADOG_API_KEY", "MAVERICK_SENTINEL_TENANT_ID",
    "MAVERICK_SENTINEL_CLIENT_ID", "MAVERICK_SENTINEL_CLIENT_SECRET", "VAULT_TOKEN",
    "MAVERICK_KMS_KEY_ID", "MAVERICK_OTEL_EXPORTER", "MAVERICK_OTEL_METRICS",
)

# Distinctive words of each question, so the script does not depend on prompt order.
TRACE = "a trace of each task"
METRICS = "Also send measurements"
COLLECTOR = "Collector address"
KMS = "Where should Lightwork lock"
KEY_NAME = "Key name at the service"
KEY_ADDRESS = "Key address"
REGION = "Region of the key"
VAULT_ADDRESS = "Vault web address"
VAULT_MOUNT = "Vault key area"
VAULT_TOKEN = "Vault access token"
SIEM = "activity record to a security monitoring service"
KIND = "Which kind of service?"
DD_SITE = "Datadog site"
ADDRESS = "Address (for example"
PLAIN_HTTP = "not encrypted"
SIEM_TOKEN = "Access key for the service"
DD_KEY = "Datadog API key"
TENANT = "Directory (tenant) ID"
CLIENT = "App (client) ID"
CLIENT_SECRET = "App client secret"  # pragma: allowlist secret

KMS_LOCAL = "On this computer"
KMS_AWS = "Amazon Web Services key service"
KMS_GCP = "Google Cloud key service"
KMS_VAULT = "HashiCorp Vault"
KMS_AZURE = "Azure Key Vault or Managed HSM"
KIND_HTTPS = "A web address (https://)"
KIND_TCP = "Syslog over TCP (host:port)"
KIND_UDP = "Syslog over UDP (host:port)"
KIND_DATADOG = "Datadog"
KIND_SENTINEL = "Microsoft Sentinel"

SENTINEL_ADDRESS = (
    "sentinel://acme-dce.eastus-1.ingest.monitor.azure.com"
    "/dcr-0123456789abcdef0123456789abcdef/Custom-LightworkAudit"  # pragma: allowlist secret
)


class _Answers:
    """Scripted answers for every prompt type; each entry is used once, by the first
    unused question containing its phrase. Any other question fails the test."""

    def __init__(self, monkeypatch, *script):
        self.script = list(script)
        self.asked: list[str] = []
        for name in ("_q_confirm", "_q_text", "_q_select", "_q_secret"):
            monkeypatch.setattr(wizard, name, self._ask)

    def _ask(self, message, *_args, **_kwargs):
        self.asked.append(message)
        for index, (phrase, answer) in enumerate(self.script):
            if phrase in message:
                del self.script[index]
                return answer
        raise AssertionError(f"unexpected question: {message!r}")

    def unused(self):
        return [phrase for phrase, _answer in self.script]


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for name in CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)


def _pick(monkeypatch, *script):
    answers = _Answers(monkeypatch, *script)
    config, keys = wizard.pick_monitoring()
    assert answers.unused() == [], "some scripted answers were never asked"
    return config, keys


def _write(tmp_path, monkeypatch, *, monitoring=None, keys=None, advanced=None):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    wizard.write_config(
        providers=["anthropic"], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": str(tmp_path / "ws")},
        keys=dict(keys or {}), capabilities={}, advanced=advanced or {},
        monitoring=monitoring,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    env_file = tmp_path / ".env"
    env = env_file.read_text(encoding="utf-8") if env_file.exists() else None
    return tomllib.loads(text), text, env


def _label(choices, value):
    return next(label for key, label in choices if key == value)


# ---------- skipping writes nothing ----------

def test_skipping_every_question_returns_nothing(monkeypatch):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, False),
    )
    assert config == {}
    assert keys == {}


def test_skipped_step_writes_no_monitoring_tables_or_env(tmp_path, monkeypatch):
    cfg, _text, env = _write(tmp_path, monkeypatch, monitoring={}, keys={})
    for table in ("observability", "kms", "audit"):
        assert table not in cfg
    assert env is None


def test_skipped_step_keeps_audit_signing_as_it_was(tmp_path, monkeypatch):
    cfg, text, _env = _write(
        tmp_path, monkeypatch, monitoring={}, advanced={"audit_sign": True})
    assert cfg["audit"] == {"sign": True}
    assert text.count("[audit]") == 1
    assert "siem_dest" not in text


def test_choosing_the_built_in_keys_writes_nothing(monkeypatch):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, False),
    )
    assert "kms" not in config and keys == {}


# ---------- traces and measurements ----------

def test_traces_with_the_default_address(tmp_path, monkeypatch):
    config, keys = _pick(
        monkeypatch,
        (TRACE, True), (METRICS, False),
        (COLLECTOR, "http://localhost:4318/v1/traces"),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")), (SIEM, False),
    )
    cfg, _text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["observability"] == {
        "otel_exporter": "otlp", "otel_endpoint": "http://localhost:4318/v1/traces"}
    assert env is None


def test_measurements_are_written_when_the_address_ends_in_v1_traces(tmp_path, monkeypatch):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, True), (METRICS, True),
        (COLLECTOR, "https://collector.example.com/v1/traces"),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")), (SIEM, False),
    )
    cfg, _text, _env = _write(tmp_path, monkeypatch, monitoring=config)
    assert cfg["observability"]["otlp_metrics"] is True


def test_measurements_need_a_v1_traces_address_and_a_no_is_honoured(monkeypatch, capsys):
    # The address is asked first. A yes that the address cannot carry is asked again, and
    # the no that follows is taken: the address is not asked a second time.
    config, _keys = _pick(
        monkeypatch,
        (TRACE, True),
        (COLLECTOR, "https://collector.example.com:4318"),
        (METRICS, True), (METRICS, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")), (SIEM, False),
    )
    assert config["observability"] == {
        "otel_exporter": "otlp", "otel_endpoint": "https://collector.example.com:4318"}
    assert "ends in /v1/traces" in capsys.readouterr().out


def test_collector_address_with_a_password_is_refused(monkeypatch, capsys):
    secret = "collector-password-do-not-store"  # pragma: allowlist secret
    config, _keys = _pick(
        monkeypatch,
        (TRACE, True), (METRICS, False),
        (COLLECTOR, f"https://user:{secret}@collector.example.com/v1/traces"),
        (COLLECTOR, "https://collector.example.com/v1/traces"),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")), (SIEM, False),
    )
    assert config["observability"]["otel_endpoint"] == "https://collector.example.com/v1/traces"
    assert secret not in capsys.readouterr().out


def test_remote_plain_http_collector_is_refused(monkeypatch, capsys):
    # Traces name tasks and tools, so only a collector on this computer may take plain http.
    config, _keys = _pick(
        monkeypatch,
        (TRACE, True), (METRICS, False),
        (COLLECTOR, "http://collector.example.com:4318/v1/traces"),
        (COLLECTOR, "https://collector.example.com/v1/traces"),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")), (SIEM, False),
    )
    assert config["observability"]["otel_endpoint"] == "https://collector.example.com/v1/traces"
    assert "Only a collector on this computer may use http://" in capsys.readouterr().out


@pytest.mark.parametrize("address", [
    "http://localhost:4318/v1/traces", "http://127.0.0.1:4318/v1/traces",
    "http://[::1]:4318/v1/traces",
])
def test_plain_http_collector_on_this_computer_is_accepted(monkeypatch, address):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, True), (METRICS, False), (COLLECTOR, address),
        (KMS, _label(wizard._KMS_PROVIDERS, "local")), (SIEM, False),
    )
    assert config["observability"]["otel_endpoint"] == address


@pytest.mark.parametrize("setting", [
    "observability.otel_endpoint", "kms.key_id", "kms.region", "kms.address",
    "kms.mount", "audit.siem_dest",
])
def test_shared_setting_contract_drives_the_settings_page(setting):
    # The wizard and page both consume the same source contract.
    from maverick.config_contracts import TEXT_SETTINGS
    from maverick_dashboard import settings_catalog

    row = settings_catalog.BY_ID[setting]
    contract = TEXT_SETTINGS[setting]
    assert row.pattern == contract.pattern
    assert row.default == contract.default
    assert row.max_length == contract.dashboard_max_length
    assert row.env == contract.dashboard_env


# ---------- key services ----------

def test_aws_key_and_region(tmp_path, monkeypatch):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "aws")),
        (KEY_NAME, "arn:aws:kms:us-east-1:123456789012:key/abcd-ef01"),
        (REGION, "us-east-1"),
        (SIEM, False),
    )
    cfg, text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["kms"] == {
        "provider": "aws",
        "key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd-ef01",
        "region": "us-east-1",
    }
    assert env is None


def test_aws_region_left_blank_is_not_written(monkeypatch):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "aws")),
        (KEY_NAME, "alias-lightwork"),
        (REGION, ""),
        (SIEM, False),
    )
    assert config["kms"] == {"provider": "aws", "key_id": "alias-lightwork"}


def test_gcp_key_name(monkeypatch):
    key = "projects/acme/locations/global/keyRings/lightwork/cryptoKeys/workspace"
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "gcp")),
        (KEY_NAME, key),
        (SIEM, False),
    )
    assert config["kms"] == {"provider": "gcp", "key_id": key}


def test_key_name_with_spaces_is_reasked(monkeypatch, capsys):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "gcp")),
        (KEY_NAME, "not a key name"),
        (KEY_NAME, "lightwork-workspace"),
        (SIEM, False),
    )
    assert config["kms"]["key_id"] == "lightwork-workspace"
    assert "without spaces" in capsys.readouterr().out


def test_key_name_outside_the_settings_page_pattern_is_reasked(monkeypatch, capsys):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "gcp")),
        (KEY_NAME, "lightwork@prod"),
        (KEY_NAME, "lightwork-prod"),
        (SIEM, False),
    )
    assert config["kms"]["key_id"] == "lightwork-prod"
    assert "without spaces" in capsys.readouterr().out


def test_aws_region_must_be_a_region_name(monkeypatch):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "aws")),
        (KEY_NAME, "alias-lightwork"),
        (REGION, "useast1"),
        (REGION, "us-east-1"),
        (SIEM, False),
    )
    assert config["kms"] == {"provider": "aws", "key_id": "alias-lightwork", "region": "us-east-1"}


def test_vault_address_and_key_area_must_fit_the_settings_page(monkeypatch):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "vault")),
        (KEY_NAME, "lightwork"),
        (VAULT_ADDRESS, "https://vault.internal:8200/?token=x"),
        (VAULT_ADDRESS, "https://vault.internal:8200"),
        (VAULT_MOUNT, "kv keys"),
        (VAULT_MOUNT, "kv-keys"),
        (VAULT_TOKEN, "hvs.token-for-the-test"),  # pragma: allowlist secret
        (SIEM, False),
    )
    assert config["kms"]["address"] == "https://vault.internal:8200"
    assert config["kms"]["mount"] == "kv-keys"


def test_siem_address_outside_the_settings_page_pattern_is_reasked(monkeypatch, capsys):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, "https://siem.example.com/<raw>"),
        (ADDRESS, "https://siem.example.com/raw"),
        (SIEM_TOKEN, ""),
    )
    assert config["audit"] == {"siem_dest": "https://siem.example.com/raw"}
    assert "cannot send to that address" in capsys.readouterr().out


def test_azure_key_address_is_checked_and_reasked(tmp_path, monkeypatch, capsys):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "azure")),
        (KEY_ADDRESS, "lightwork-kek"),
        (KEY_ADDRESS, "https://acme-vault.vault.azure.net/keys/lightwork-kek"),
        (SIEM, False),
    )
    cfg, _text, _env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["kms"] == {
        "provider": "azure",
        "key_id": "https://acme-vault.vault.azure.net/keys/lightwork-kek",
    }
    assert "web address" in capsys.readouterr().out


def test_vault_address_mount_and_token_in_env(tmp_path, monkeypatch, capsys):
    token = "hvs.vault-token-do-not-store"
    config, keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "vault")),
        (KEY_NAME, "lightwork"),
        (VAULT_ADDRESS, "http://vault.internal:8200"),
        (VAULT_ADDRESS, "https://vault.internal:8200"),
        (VAULT_MOUNT, "kv-keys"),
        (VAULT_TOKEN, token),
        (SIEM, False),
    )
    cfg, text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["kms"] == {
        "provider": "vault", "key_id": "lightwork",
        "address": "https://vault.internal:8200", "mount": "kv-keys",
    }
    assert keys == {"VAULT_TOKEN": token}
    assert env is not None and f"VAULT_TOKEN={token}" in env
    assert token not in text
    assert token not in capsys.readouterr().out


def test_vault_default_key_area_is_not_written(monkeypatch):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "vault")),
        (KEY_NAME, "lightwork"),
        (VAULT_ADDRESS, "https://vault.internal:8200"),
        (VAULT_MOUNT, "transit"),
        (VAULT_TOKEN, "hvs.default-area-token"),  # pragma: allowlist secret
        (SIEM, False),
    )
    assert "mount" not in config["kms"]


def test_vault_without_a_token_is_not_saved(tmp_path, monkeypatch, capsys):
    # The runtime reads the token only from VAULT_TOKEN, so a Vault table with no token
    # would be an unauthenticated client. The built-in keys stay in use instead.
    config, keys = _pick(
        monkeypatch,
        (TRACE, False),
        (KMS, _label(wizard._KMS_PROVIDERS, "vault")),
        (KEY_NAME, "lightwork"),
        (VAULT_ADDRESS, "https://vault.internal:8200"),
        (VAULT_MOUNT, "transit"),
        (VAULT_TOKEN, ""),
        (SIEM, False),
    )
    cfg, _text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert "kms" not in cfg
    assert keys == {} and env is None
    assert "needs its access token" in capsys.readouterr().out


# ---------- security monitoring services ----------

def test_https_destination_token_goes_to_env_not_config(tmp_path, monkeypatch, capsys):
    token = "hec-token-do-not-store"
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, "https://siem.example.com/services/collector/raw"),
        (SIEM_TOKEN, token),
    )
    cfg, text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["audit"] == {"siem_dest": "https://siem.example.com/services/collector/raw"}
    assert keys == {"MAVERICK_SIEM_TOKEN": token}
    assert env is not None and f"MAVERICK_SIEM_TOKEN={token}" in env
    assert token not in text
    assert token not in capsys.readouterr().out


def test_https_destination_without_a_token_writes_only_the_address(tmp_path, monkeypatch):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, "https://siem.example.com/raw"),
        (SIEM_TOKEN, ""),
    )
    cfg, _text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["audit"] == {"siem_dest": "https://siem.example.com/raw"}
    assert keys == {}
    assert env is None


@pytest.mark.parametrize(("kind", "address", "stored"), [
    (KIND_TCP, "siem.example.com:514", "tcp://siem.example.com:514"),
    (KIND_UDP, "udp://siem.example.com:514", "udp://siem.example.com:514"),
])
def test_syslog_destinations_need_no_credentials(tmp_path, monkeypatch, kind, address, stored):
    # No credential question is scripted: asking for one would fail the test.
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, kind), (ADDRESS, address),
    )
    cfg, _text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["audit"] == {"siem_dest": stored}
    assert keys == {} and env is None


def test_datadog_site_and_key(tmp_path, monkeypatch, capsys):
    key = "dd-api-key-do-not-store"
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_DATADOG), (DD_SITE, "datadoghq.eu"),
        (DD_KEY, key),
    )
    cfg, text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["audit"] == {"siem_dest": "datadog://datadoghq.eu"}
    assert keys == {"MAVERICK_DATADOG_API_KEY": key}
    assert env is not None and f"MAVERICK_DATADOG_API_KEY={key}" in env
    assert key not in text
    assert key not in capsys.readouterr().out


def test_datadog_without_a_key_is_not_saved(tmp_path, monkeypatch, capsys):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_DATADOG), (DD_SITE, "datadoghq.com"),
        (DD_KEY, ""),
    )
    cfg, _text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert "audit" not in cfg
    assert keys == {} and env is None
    assert "Not saved" in capsys.readouterr().out


def test_sentinel_destination_and_credentials(tmp_path, monkeypatch, capsys):
    secret = "entra-client-secret-do-not-store"  # pragma: allowlist secret
    tenant = "11111111-2222-3333-4444-555555555555"
    client = "66666666-7777-8888-9999-aaaaaaaaaaaa"
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_SENTINEL), (ADDRESS, SENTINEL_ADDRESS),
        (TENANT, tenant), (CLIENT, client), (CLIENT_SECRET, secret),
    )
    cfg, text, env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    assert cfg["audit"] == {"siem_dest": SENTINEL_ADDRESS}
    assert keys == {
        "MAVERICK_SENTINEL_TENANT_ID": tenant,
        "MAVERICK_SENTINEL_CLIENT_ID": client,
        "MAVERICK_SENTINEL_CLIENT_SECRET": secret,
    }
    assert env is not None and f"MAVERICK_SENTINEL_CLIENT_SECRET={secret}" in env
    assert secret not in text and secret not in capsys.readouterr().out


def test_sentinel_id_in_the_wrong_form_is_reasked(monkeypatch, capsys):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_SENTINEL), (ADDRESS, SENTINEL_ADDRESS),
        (TENANT, "not a tenant id!"),
        (TENANT, "11111111-2222-3333-4444-555555555555"),
        (CLIENT, "66666666-7777-8888-9999-aaaaaaaaaaaa"), (CLIENT_SECRET, "s"),
    )
    assert keys["MAVERICK_SENTINEL_TENANT_ID"] == "11111111-2222-3333-4444-555555555555"
    assert "Enter the ID as Azure shows it" in capsys.readouterr().out


def test_sentinel_without_its_secret_is_not_saved(tmp_path, monkeypatch):
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_SENTINEL), (ADDRESS, SENTINEL_ADDRESS),
        (TENANT, "11111111-2222-3333-4444-555555555555"),
        (CLIENT, "66666666-7777-8888-9999-aaaaaaaaaaaa"), (CLIENT_SECRET, ""),
    )
    assert config == {}
    assert keys == {}


def test_sentinel_address_on_another_host_is_refused(monkeypatch, capsys):
    bad = "sentinel://evil.example.com/dcr-0123456789abcdef0123456789abcdef/Custom-X"
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_SENTINEL), (ADDRESS, bad), (ADDRESS, SENTINEL_ADDRESS),
        (TENANT, "11111111-2222-3333-4444-555555555555"),
        (CLIENT, "66666666-7777-8888-9999-aaaaaaaaaaaa"), (CLIENT_SECRET, "s"),
    )
    assert config["audit"] == {"siem_dest": SENTINEL_ADDRESS}
    assert "cannot send to that address" in capsys.readouterr().out


def test_an_address_of_another_kind_is_refused(monkeypatch, capsys):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, "tcp://siem.example.com:514"),
        (ADDRESS, "https://siem.example.com/raw"),
        (SIEM_TOKEN, ""),
    )
    assert config["audit"] == {"siem_dest": "https://siem.example.com/raw"}
    assert "not one of the kind you chose" in capsys.readouterr().out


def test_credentials_typed_into_an_address_are_refused_and_not_echoed(monkeypatch, capsys):
    leaked = "password-typed-into-the-address"
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, f"https://svc:{leaked}@siem.example.com/raw"),
        (ADDRESS, "https://siem.example.com/raw"),
        (SIEM_TOKEN, ""),
    )
    assert config["audit"] == {"siem_dest": "https://siem.example.com/raw"}
    assert leaked not in capsys.readouterr().out


def test_plain_http_is_accepted_only_when_the_operator_says_so(monkeypatch):
    config, _keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, "http://siem.internal.example.com/raw"),
        (PLAIN_HTTP, False),
        (ADDRESS, "http://siem.internal.example.com/raw"),
        (PLAIN_HTTP, True),
    )
    assert config["audit"] == {"siem_dest": "http://siem.internal.example.com/raw"}


def test_plain_http_is_not_offered_a_token(monkeypatch):
    # The kernel refuses to send a token over plain http, so no token question is asked.
    config, keys = _pick(
        monkeypatch,
        (TRACE, False), (KMS, _label(wizard._KMS_PROVIDERS, "local")),
        (SIEM, True), (KIND, KIND_HTTPS),
        (ADDRESS, "http://siem.internal.example.com/raw"),
        (PLAIN_HTTP, True),
    )
    assert config["audit"] == {"siem_dest": "http://siem.internal.example.com/raw"}
    assert keys == {}


# ---------- what reaches the config file ----------

def test_audit_table_is_written_once_with_signing_and_destination(tmp_path, monkeypatch):
    cfg, text, _env = _write(
        tmp_path, monkeypatch,
        monitoring={"audit": {"siem_dest": "https://siem.example.com/raw"}},
        advanced={"audit_sign": True},
    )
    assert cfg["audit"] == {"sign": True, "siem_dest": "https://siem.example.com/raw"}
    assert text.count("\n[audit]\n") == 1


def test_destination_alone_creates_the_audit_table(tmp_path, monkeypatch):
    cfg, text, _env = _write(
        tmp_path, monkeypatch,
        monitoring={"audit": {"siem_dest": "tcp://siem.example.com:514"}},
        advanced={},
    )
    assert cfg["audit"] == {"siem_dest": "tcp://siem.example.com:514"}
    assert text.count("[audit]") == 1


def test_answers_reach_the_kernel_readers(tmp_path, monkeypatch):
    """Each answer is read back by the runtime's own parser, as the api_keys step does."""
    from maverick import observability
    from maverick.audit.forwarder import parse_dest
    from maverick.kms_backends import _azure_key_parts

    config, keys = _pick(
        monkeypatch,
        (TRACE, True), (METRICS, True),
        (COLLECTOR, "http://localhost:4318/v1/traces"),
        (KMS, _label(wizard._KMS_PROVIDERS, "azure")),
        (KEY_ADDRESS, "https://acme-vault.vault.azure.net/keys/lightwork-kek/0123456789abcdef0123456789abcdef"),
        (SIEM, True), (KIND, KIND_DATADOG), (DD_SITE, "datadoghq.com"), (DD_KEY, "dd-key"),
    )
    cfg, _text, _env = _write(tmp_path, monkeypatch, monitoring=config, keys=keys)
    monkeypatch.setattr("maverick.config.load_config", lambda: cfg)
    assert observability._otel_enabled() is True
    assert observability._otlp_metrics_enabled() is True
    assert parse_dest(cfg["audit"]["siem_dest"])[0] == "datadog"
    assert _azure_key_parts(cfg["kms"]["key_id"]) is not None


def test_new_tables_are_known_sections():
    from maverick.migrate import KNOWN_SECTIONS

    assert {"observability", "kms", "audit"} <= set(KNOWN_SECTIONS)


# ---------- the step in the flow ----------

def test_step_is_listed_after_security_and_before_advanced():
    keys = [key for key, _label in wizard.STEPS]
    assert keys.index("monitoring") == keys.index("security_suite") + 1
    assert keys.index("advanced") == keys.index("monitoring") + 1
    assert dict(wizard.STEPS)["monitoring"] == "Monitoring and key management"


def test_run_keeps_credentials_out_of_partial_state(tmp_path, monkeypatch):
    """The credentials reach write_config's keys (and so .env), and never the partial state."""
    secret = "dd-key-that-must-not-be-saved"  # pragma: allowlist secret
    saved: list[str] = []
    written: dict = {}

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(wizard, "pick_mode", lambda: "advanced")
    monkeypatch.setattr(wizard, "preflight", lambda: True)
    monkeypatch.setattr(wizard, "pick_monitoring", lambda: (
        {"audit": {"siem_dest": "datadog://datadoghq.com"}}, {"MAVERICK_DATADOG_API_KEY": secret}))
    monkeypatch.setattr(wizard, "_save_partial", lambda state: saved.append(json.dumps(state, default=str)))
    monkeypatch.setattr(wizard, "_clear_partial", lambda: None)
    monkeypatch.setattr(wizard, "smoke_test", lambda: True)
    monkeypatch.setattr(wizard, "show_compliance_commands", lambda advanced: None)
    monkeypatch.setattr(wizard, "collect_api_keys", lambda providers, envs: {})
    monkeypatch.setattr(wizard, "pick_connectors", dict)
    monkeypatch.setattr(wizard, "pick_suites", dict)
    monkeypatch.setattr(wizard, "_q_confirm",
                        lambda message, *a, **k: message.startswith("Write config"))

    def _capture(*args, **kwargs):
        written["keys"] = args[6]
        written["monitoring"] = kwargs.get("monitoring")

    monkeypatch.setattr(wizard, "write_config", _capture)
    # Every other pick answers with its progress-test stub, so only this step is real.
    stubs = {
        "pick_deployment": lambda: "desktop",
        "pick_providers": lambda: ["anthropic"],
        "pick_models_per_role": lambda providers, provider_options=None: {},
        "pick_channels": lambda deployment: ({}, set()),
        "pick_safety": dict, "pick_signed_skills": dict, "pick_budget": dict,
        "pick_sandbox": dict,
        "pick_research_execution": lambda: {"enable": False},
        "pick_candidate_promotion": lambda: {"enable": False},
        "pick_knowledge_access": lambda: {"enable": True},
        "pick_capabilities": dict,
        "pick_ekko": lambda: {"enable": False},
        "pick_intent_value": lambda: {"enabled": True, "recommendations": True,
                                      "completion_confirmation": False},
        "pick_security_suite": dict, "pick_advanced": dict,
        "pick_web_search": lambda: (False, []),
        "pick_mcp_servers": dict, "pick_plugins": list,
        "pick_tool_acl": lambda channels: {}, "pick_rate_limits": lambda channels: {},
        "pick_retention": dict, "pick_analytics": dict, "pick_persona": dict,
        "pick_notifications": lambda: ({}, []), "pick_webhooks": lambda: ({}, []),
        "pick_a2a": lambda: ({}, []),
    }
    for name, stub in stubs.items():
        monkeypatch.setattr(wizard, name, stub)
    # Free-text and choice questions in unstubbed steps keep their defaults.
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: k.get("default", ""))
    monkeypatch.setattr(wizard, "_q_select",
                        lambda *a, **k: k.get("default") or (a[1][0] if len(a) > 1 and a[1] else ""))
    monkeypatch.setattr(wizard, "console", _quiet_console())

    assert wizard.run() == 0

    assert written["keys"]["MAVERICK_DATADOG_API_KEY"] == secret
    assert written["monitoring"] == {"audit": {"siem_dest": "datadog://datadoghq.com"}}
    assert saved, "the flow saved its partial state"
    assert all(secret not in text for text in saved)


def _quiet_console():
    import io

    from rich.console import Console

    return Console(file=io.StringIO(), force_terminal=False, no_color=True)
