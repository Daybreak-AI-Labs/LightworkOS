"""Settings > All settings: channels, integrations, notifications and billing.

Every row in ``settings_catalog_integrations`` saves and reads back through the
catalog API into what ``load_config`` returns, refuses values it cannot use,
never shows a sealed secret, needs confirmation to loosen a protection, leaves
one audit row per change, and changes what the kernel actually does.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_integrations as integrations
from maverick_dashboard.app import app

from test_support.channel_review import channel_review_token
from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
ROWS = integrations.entries(catalog.S, catalog.C, catalog.Column)
_KEY = "ab" * 32  # a publisher key in the stored (hex) form
_STRIPE_KEY = "sk_test_" + "a1B2c3D4e5F6g7H8"  # pragma: allowlist secret
_STRIPE_HOOK = "whsec_" + "Z9y8X7w6V5u4T3s2"  # pragma: allowlist secret
_PUSHOVER_USER = "u" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G"  # pragma: allowlist secret
_PUSHOVER_APP = "a" + "Z1x2C3v4B5n6M7q8W9e0R1t2Y3u4I"  # pragma: allowlist secret


def _first_specialist() -> str:
    from maverick.domain import enabled_domains

    return sorted(enabled_domains())[0]


_SPECIALIST = _first_specialist()
_RULE = {"any_keyword": ["invoice"], "urgency": "", "attachments": ["pdf"], "min_length": 0,
         "specialist": _SPECIALIST}
_ENV = sorted({name for row in ROWS for name in row.env} | {
    "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
    "MAVERICK_OAUTH_VAULT", "MAVERICK_CONNECTIONS", "MAVERICK_STRIPE_ENABLE",
    "MAVERICK_STRIPE_BILL_METERED", "MAVERICK_NOTIFY_BATCH_WINDOW",
    "MAVERICK_VOICE_AUTO_FETCH",
})

# id -> (value sent by the page, value the kernel then reads)
VALUES: dict[str, tuple[object, object]] = {
    "contact_centre.provider": ("zendesk", "zendesk"),
    "contact_centre.zendesk_subdomain": ("acme-support", "acme-support"),
    "contact_centre.zendesk_email": ("agent@acme.example", "agent@acme.example"),
    "contact_centre.zendesk_api_token": ("sample-zendesk-token-123", "sample-zendesk-token-123"),  # pragma: allowlist secret
    "contact_centre.webhook_url": ("https://hooks.acme.example/lightwork", "https://hooks.acme.example/lightwork"),
    "contact_centre.webhook_secret": ("sample-webhook-secret-123", "sample-webhook-secret-123"),  # pragma: allowlist secret
    "contact_centre.dashboard_url": ("https://lightwork.acme.example", "https://lightwork.acme.example"),
    "contact_centre.max_messages": (15, 15),
    "billing.enforce_plan_caps": (True, True),
    "image_edit.inpaint_model": ("stability-ai/stable-diffusion-inpainting:abc123",
                                 "stability-ai/stable-diffusion-inpainting:abc123"),
    "image_edit.variation_model": ("lambdal/stable-diffusion-image-variation",
                                   "lambdal/stable-diffusion-image-variation"),
    "image_edit.upscale_model": ("nightmareai/real-esrgan", "nightmareai/real-esrgan"),
    "billing.plans": (
        [{"name": "pro", "features": ["core", "channels"], "max_daily_dollars": 50,
          "max_concurrent_goals": 3}],
        {"pro": {"features": ["core", "channels"], "max_daily_dollars": 50.0,
                 "max_concurrent_goals": 3}},
    ),
    "billing.stripe.prices.pro": ("price_1ProSample", "price_1ProSample"),
    "billing.stripe.prices.enterprise": ("price_1EntSample", "price_1EntSample"),
    "commerce.stripe_refunds": (True, True),
    "email.disable": (True, True),
    "email.provider": ("ses", "ses"),
    "email.user": ("agent@example.com", "agent@example.com"),
    "email.app_password": ("sample-app-password", "sample-app-password"),  # pragma: allowlist secret
    "email.from": ("agent@example.com", "agent@example.com"),
    "email.smtp_host": ("smtp.example.com", "smtp.example.com"),
    "email.smtp_port": (587, 587),
    "email.imap_host": ("imap.example.com", "imap.example.com"),
    "calendar.url": ("https://caldav.example.com/dav", "https://caldav.example.com/dav"),
    "calendar.user": ("agent@example.com", "agent@example.com"),
    "calendar.password": ("sample-calendar-password", "sample-calendar-password"),  # pragma: allowlist secret
    "calendar.calendar": ("Team calendar", "Team calendar"),
    "erp.base_url": ("https://erp.example.com/api", "https://erp.example.com/api"),
    "erp.token": ("sample-erp-token", "sample-erp-token"),  # pragma: allowlist secret
    "erp.system": ("NetSuite", "NetSuite"),
    "github.token": ("sample-github-token", "sample-github-token"),  # pragma: allowlist secret
    "github.share_token": ("sample-gist-key", "sample-gist-key"),  # pragma: allowlist secret
    "github.trigger_labels": (["automate", "fix-me"], ["automate", "fix-me"]),
    "webhooks.linear_bot_id": ("bot@example.com", "bot@example.com"),
    "webhooks.jira_bot_id": ("5b10ac8d82e05b22cc7d4ef5", "5b10ac8d82e05b22cc7d4ef5"),
    "webhooks.gitlab_bot_username": ("lightwork-bot", "lightwork-bot"),
    "obsidian.vault_path": ("/srv/notes", "/srv/notes"),
    "notifications.batch_max": (25, 25),
    "alerts.enabled": (True, True),
    "webhooks.workers": (8, 8),
    "webhooks.max_inflight": (200, 200),
    "webhooks.max_age_seconds": (600, 600),
    "webhooks.body_limit": (2048, 2097152),
    "automation_import.max_steps": (400, 400),
    "tax.update_url": ("https://tax.example.com/constants.json",
                       "https://tax.example.com/constants.json"),
    "tax.trusted_constants_pubkeys": ([_KEY.upper()], [_KEY]),
    "channels.rich_render": (True, True),
    "channels.max_intake_records": (50000, 50000),
    "vendor_onboarding.safe_read_attempts": (5, 5),
    "vendor_onboarding.safe_read_backoff_seconds": (1.5, 1.5),
    "voice.stt_backend": ("local", "local"),
    "voice.stt_model": ("base", "base"),
    "voice.stt_openai_model": ("gpt-4o-transcribe", "gpt-4o-transcribe"),
    "voice.stt_groq_model": ("whisper-large-v3", "whisper-large-v3"),
    "voice.tts_openai_model": ("gpt-4o-mini-tts", "gpt-4o-mini-tts"),
    "voice.tts_elevenlabs_model": ("eleven-multilingual-v2", "eleven-multilingual-v2"),
    "voice.max_upload_bytes": (50, 52428800),
    "voice.transcribe_concurrency": (4, 4),
    "attachments.audio_max_bytes": (128, 134217728),
    "billing.stripe.secret_key": (_STRIPE_KEY, _STRIPE_KEY),
    "billing.stripe.webhook_secret": (_STRIPE_HOOK, _STRIPE_HOOK),
    "github.app_webhook_secret": ("sample-github-app-secret", "sample-github-app-secret"),  # pragma: allowlist secret
    "webhooks.gitlab_token": ("sample-gitlab-token", "sample-gitlab-token"),  # pragma: allowlist secret
    "data_map.graph_token": ("sample-graph-token", "sample-graph-token"),  # pragma: allowlist secret
    "voice.whisper_cpp_bin": ("whisper-cli", "whisper-cli"),
    "voice.whisper_cpp_model": ("ggml-custom.bin", "ggml-custom.bin"),
    "notifications.user_key": (_PUSHOVER_USER, _PUSHOVER_USER),
    "notifications.app_token": (_PUSHOVER_APP, _PUSHOVER_APP),
    "notifications.email.host": ("smtp.example.com", "smtp.example.com"),
    "notifications.email.port": (2525, 2525),
    "notifications.email.user": ("alerts@example.com", "alerts@example.com"),
    "notifications.email.password": ("sample-mail-password", "sample-mail-password"),  # pragma: allowlist secret
    "notifications.email.from_address": ("alerts@example.com", "alerts@example.com"),
    "notifications.email.tls": ("ssl", "ssl"),
    "notifications.email.to": ("ops@example.com", "ops@example.com"),
    "channels.slack.signing_secret": ("sample-slack-signing-secret", "sample-slack-signing-secret"),  # pragma: allowlist secret
    "channels.slack.approvals_channel": ("C0123ABCD", "C0123ABCD"),
    "my_work.digest_enable": (True, True),
    "my_work.digest_hour": (7, 7),
    "my_work.digest_poll_seconds": (120, 120),
    "my_work.send_when_empty": (True, True),
    "my_work.monthly_spend_limit_dollars": (250, 250),
    "channels.routing.rules": ([_RULE], [_RULE]),
    # finance operating profile
    "finance.framework": ("ifrs", "ifrs"),
    "finance.materiality": (50000, 50000),
    "finance.automation.default": ("approve", "approve"),
    "finance.automation.*": ([{"name": "send_invoice", "level": "straight_through"}],
                             {"send_invoice": "straight_through"}),
    "finance.sod.mode": ("warn", "warn"),
    "finance.approvals.timeout": ("fail_closed", "fail_closed"),
}

# id -> a value the server must refuse
INVALID: dict[str, object] = {
    "contact_centre.provider": "salesforce",
    "contact_centre.zendesk_subdomain": "Acme.Support",
    "contact_centre.zendesk_email": "not an email",
    "contact_centre.zendesk_api_token": "short",
    "contact_centre.webhook_url": "http://hooks.acme.example/lightwork",
    "contact_centre.webhook_secret": "x",
    "contact_centre.dashboard_url": "http://lightwork.acme.example",
    "contact_centre.max_messages": 0,
    "billing.enforce_plan_caps": "yes",
    # A web address, a path or a space is never a model name.
    "image_edit.inpaint_model": "https://replicate.com/stability-ai/stable-diffusion-inpainting",
    "image_edit.variation_model": "../models/variation",
    "image_edit.upscale_model": "nightmareai/real esrgan",
    "billing.plans": [{"name": "gold", "features": [], "max_daily_dollars": 1,
                       "max_concurrent_goals": 1}],
    "billing.stripe.prices.pro": "prod_123",
    "billing.stripe.prices.enterprise": "https://stripe.example",
    "commerce.stripe_refunds": 1,
    "email.disable": "on",
    "email.provider": "sendmail",
    "email.user": "has space",
    "email.app_password": "",
    "email.from": "not an address",
    "email.smtp_host": "https://smtp.example.com",
    "email.smtp_port": 70000,
    "email.imap_host": "bad host!",
    "calendar.url": "http://caldav.example.com",
    "calendar.user": "two words",
    "calendar.password": "",
    "calendar.calendar": "<script>",
    "erp.base_url": "ftp://erp.example.com",
    "erp.token": "",
    "erp.system": "{bad}",
    "github.token": "",
    "github.share_token": "",
    "github.trigger_labels": ["two words"],
    "webhooks.linear_bot_id": "has space",
    "webhooks.jira_bot_id": "a\nb",
    "webhooks.gitlab_bot_username": "bad name!",
    "obsidian.vault_path": "../etc",
    "notifications.batch_max": 0,
    "alerts.enabled": "true",
    "webhooks.workers": 0,
    "webhooks.max_inflight": 10001,
    "webhooks.max_age_seconds": 5,
    "webhooks.body_limit": 0,
    "automation_import.max_steps": 1.5,
    "tax.update_url": "http://tax.example.com",
    "tax.trusted_constants_pubkeys": ["not a key"],
    "channels.rich_render": None,
    "channels.max_intake_records": 500,
    "vendor_onboarding.safe_read_attempts": 6,
    "vendor_onboarding.safe_read_backoff_seconds": 6,
    "voice.stt_backend": "cloud",
    "voice.stt_model": "huge",
    "voice.stt_openai_model": "bad model",
    "voice.stt_groq_model": "x" * 200,
    "voice.tts_openai_model": "bad\tmodel",
    "voice.tts_elevenlabs_model": "a;b",
    "voice.max_upload_bytes": 201,
    "voice.transcribe_concurrency": 17,
    "attachments.audio_max_bytes": 0,
    "billing.stripe.secret_key": "pk_test_notasecretkey",  # pragma: allowlist secret
    "billing.stripe.webhook_secret": "not-a-signing-secret",  # pragma: allowlist secret
    "github.app_webhook_secret": "",
    "webhooks.gitlab_token": "",
    "data_map.graph_token": "",
    "voice.whisper_cpp_bin": "/usr/bin/python3",
    "voice.whisper_cpp_model": "ggml-escape.bin",
    "notifications.user_key": "too-short",
    "notifications.app_token": "a" * 31,
    "notifications.email.host": "not a host!",
    "notifications.email.port": 0,
    "notifications.email.user": "has space",
    "notifications.email.password": "",
    "notifications.email.from_address": "nope",
    "notifications.email.tls": "plain",
    "notifications.email.to": "nope",
    "channels.slack.signing_secret": "",
    "channels.slack.approvals_channel": "lowercase",
    "my_work.digest_enable": "yes",
    "my_work.digest_hour": 24,
    "my_work.digest_poll_seconds": 10,
    "my_work.send_when_empty": "on",
    "my_work.monthly_spend_limit_dollars": -1,
    "channels.routing.rules": [{**_RULE, "specialist": "no_such_pack"}],
    # finance operating profile (a payment below approve is a hard floor)
    "finance.framework": "local_gaap",
    "finance.materiality": 0,
    "finance.automation.default": "autopilot",
    "finance.automation.*": [{"name": "release_payment", "level": "straight_through"}],
    "finance.sod.mode": "block",
    "finance.approvals.timeout": "fail_open",
}

# id -> (value first set without confirmation or None, the loosening value)
LOOSENING: dict[str, tuple[object, object]] = {
    "billing.enforce_plan_caps": (True, False),
    "billing.plans": (None, VALUES["billing.plans"][0]),
    "billing.stripe.prices.pro": (None, "price_1Other"),
    "billing.stripe.prices.enterprise": (None, "price_1Other"),
    "commerce.stripe_refunds": (None, True),
    "email.disable": (True, False),
    "email.smtp_host": (None, "smtp.other.example"),
    "email.imap_host": (None, "imap.other.example"),
    "calendar.url": (None, "https://caldav.other.example"),
    "erp.base_url": (None, "https://erp.other.example"),
    "webhooks.linear_bot_id": (None, "someone@example.com"),
    "webhooks.jira_bot_id": (None, "someone@example.com"),
    "webhooks.gitlab_bot_username": (None, "someone"),
    "obsidian.vault_path": (None, "/home/me/notes"),
    "webhooks.max_inflight": (100, 300),
    "webhooks.max_age_seconds": (None, 900),
    "webhooks.body_limit": (None, 4096),
    "notifications.email.tls": (None, "none"),
    "automation_import.max_steps": (None, 1000),
    "tax.trusted_constants_pubkeys": (None, [_KEY]),
    "voice.stt_backend": (None, "openai"),
    "voice.max_upload_bytes": (None, 100),
    "attachments.audio_max_bytes": (None, 512),
    "voice.whisper_cpp_bin": (None, "whisper-cli"),
    "voice.whisper_cpp_model": (None, "ggml-custom.bin"),
    "channels.routing.rules": (None, [_RULE]),
    "channels.max_intake_records": (20000, 40000),
    # finance operating profile
    "finance.framework": (None, "ifrs"),
    "finance.materiality": (50000, 100000),
    "finance.automation.default": ("draft", "straight_through"),
    "finance.automation.*": (None, [{"name": "send_invoice", "level": "approve"}]),
    "finance.sod.mode": ("enforce", "warn"),
    "finance.approvals.timeout": ("fail_closed", ""),
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    _voice_engine_files(tmp_path)
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _link_for_qualification(path, target, *, required=False):
    try:
        path.symlink_to(target)
    except OSError as exc:
        if getattr(exc, "winerror", None) != 1314:
            raise
        if required:
            pytest.skip("Windows symlink qualification requires an executor privilege unavailable here")


def _voice_engine_files(tmp_path):
    """Lightwork's programs and speech model folders, with one approved entry
    each, entries that must never be offered (not executable, a link out, an
    unrecognised name) and a file outside both folders."""
    import os

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "tool").write_text("#!/bin/sh\necho outside\n")
    os.chmod(outside / "tool", 0o755)
    (outside / "ggml-escape.bin").write_bytes(b"outside")
    programs = tmp_path / "home" / "bin"
    programs.mkdir(parents=True)
    (programs / "whisper-cli").write_text("#!/bin/sh\necho ok\n")
    os.chmod(programs / "whisper-cli", 0o755)
    if os.name == "nt":
        # Windows does not expose POSIX executable bits: this invalid entry is
        # a directory. POSIX jobs retain the non-executable-file qualification.
        (programs / "whisper-cpp").mkdir()
    else:
        (programs / "whisper-cpp").write_text("not executable")
    _link_for_qualification(programs / "whisper.cpp", outside / "tool")
    (programs / "ffmpeg").write_text("#!/bin/sh\n")
    os.chmod(programs / "ffmpeg", 0o755)
    models = tmp_path / "home" / "models" / "whisper"
    models.mkdir(parents=True)
    (models / "ggml-custom.bin").write_bytes(b"model")
    _link_for_qualification(models / "ggml-escape.bin", outside / "ggml-escape.bin")
    return programs, models, outside


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _loaded() -> dict:
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False):
    return save_catalog(client, API, json={"changes": changes, "confirm": confirm})


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def test_every_row_has_a_sample_a_refusal_and_is_in_the_catalog():
    ids = {row.id for row in ROWS}
    assert ids == set(VALUES) == set(INVALID)
    assert set(LOOSENING) == {row.id for row in ROWS if row.warning}
    assert all(row.id in catalog.BY_ID for row in ROWS)


@pytest.mark.parametrize("setting_id", sorted(VALUES))
def test_each_row_saves_reads_back_and_resets(setting_id, audit_rows):
    setting = catalog.BY_ID[setting_id]
    sent, stored = VALUES[setting_id]
    r = _save([{"id": setting_id, "value": sent}], confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["changed"] == [setting_id]
    assert r.json()["restart"] is setting.restart
    present, value = catalog.lookup(_loaded(), setting.path)
    assert present and value == stored
    row = _row(setting_id)
    assert row["source"] == "here"
    if setting.secret:
        assert row["value"] is None and row["is_set"] is True
    assert [(a["section"], a["key"]) for a in audit_rows] == [(setting.section, setting.key)]
    assert audit_rows[0]["_global"] is True and audit_rows[0]["actor"]
    r = _save([{"id": setting_id, "reset": True}], confirm=True)
    assert r.status_code == 200, r.text
    present, value = catalog.lookup(_loaded(), setting.path)
    assert not present or value == setting.default


@pytest.mark.parametrize("setting_id", sorted(INVALID))
def test_each_row_refuses_values_it_cannot_use(setting_id, audit_rows):
    setting = catalog.BY_ID[setting_id]
    r = _save([{"id": setting_id, "value": INVALID[setting_id]}], confirm=True)
    assert r.status_code == 400, r.text
    message = r.json()["message"]
    # A key file that can't be read gets the shared plain sentence about key files.
    assert message.startswith(setting.label) or (setting.control == "keys" and "key" in message)
    assert not catalog.lookup(_loaded(), setting.path)[0]
    assert audit_rows == []


@pytest.mark.parametrize("setting_id", sorted(LOOSENING))
def test_loosening_needs_confirmation_on_the_server(setting_id, audit_rows):
    first, loosening = LOOSENING[setting_id]
    if first is not None:
        assert _save([{"id": setting_id, "value": first}]).status_code == 200
    r = _save([{"id": setting_id, "value": loosening}])
    assert r.status_code == 409, r.text
    assert r.json()["confirm"][0]["id"] == setting_id
    assert r.json()["confirm"][0]["warning"] == catalog.BY_ID[setting_id].warning
    r = _save([{"id": setting_id, "value": loosening}], confirm=True)
    assert r.status_code == 200, r.text
    assert audit_rows[-1]["confirmed"] is True


def test_tightening_needs_no_confirmation(audit_rows):
    for setting_id, value in (("webhooks.max_age_seconds", 60), ("webhooks.body_limit", 512),
                              ("voice.stt_backend", "local"), ("automation_import.max_steps", 50),
                              ("commerce.stripe_refunds", False)):
        r = _save([{"id": setting_id, "value": value}])
        assert r.status_code == 200, (setting_id, r.text)


def test_secrets_are_sealed_never_shown_and_audited_as_set(audit_rows):
    from maverick import config

    secrets = {row.id: VALUES[row.id][0] for row in ROWS if row.secret}
    assert set(secrets) == {"email.app_password", "calendar.password", "erp.token",
                            "github.token", "github.share_token", "billing.stripe.secret_key",
                            "billing.stripe.webhook_secret", "github.app_webhook_secret",
                            "webhooks.gitlab_token", "data_map.graph_token",
                            "notifications.user_key", "notifications.app_token",
                            "notifications.email.password", "channels.slack.signing_secret",
                            "contact_centre.zendesk_api_token", "contact_centre.webhook_secret"}
    r = _save([{"id": key, "value": value} for key, value in secrets.items()])
    assert r.status_code == 200, r.text
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    page = every_group(client)
    listing = client.get(API).text
    for value in secrets.values():
        assert value not in r.text and value not in stored
        assert value not in page and value not in listing and value not in repr(audit_rows)
    assert stored.count("MVKAR1:") >= len(secrets)
    assert {(a["old"], a["new"]) for a in audit_rows} == {("not set", "set")}
    cfg = _loaded()
    assert cfg["email"]["app_password"] == secrets["email.app_password"]
    assert cfg["github"]["token"] == secrets["github.token"]


def test_environment_overrides_lock_the_row(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_WEBHOOK_WORKERS", "2")
    row = _row("webhooks.workers")
    assert row["locked"] is True and row["source"] == "deployment"
    assert _save([{"id": "webhooks.workers", "value": 8}], confirm=True).status_code == 409
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "from-the-server")  # pragma: allowlist secret
    assert _row("email.app_password")["locked"] is True


def test_shared_channel_and_webhook_values_survive_other_saves(audit_rows):
    from maverick_dashboard import settings_store

    changes = [{"id": "channels.rich_render", "value": True},
               {"id": "webhooks.workers", "value": 6},
               {"id": "webhooks.linear_bot_id", "value": "bot@example.com"},
               {"id": "webhooks.outbound", "value": ["https://hooks.example/run"]}]
    assert _save(changes, confirm=True).status_code == 200
    settings_store.set_channel("telegram", True, {"bot_token": "123:abc"})  # pragma: allowlist secret
    settings_store.set_toggle("features", "skills", False)
    cfg = _loaded()
    assert cfg["channels"]["rich_render"] is True
    assert cfg["channels"]["telegram"]["enabled"] is True
    assert cfg["webhooks"]["workers"] == 6
    assert cfg["webhooks"]["linear_bot_id"] == "bot@example.com"
    assert cfg["webhooks"]["outbound"] == ["https://hooks.example/run"]
    from maverick import config

    assert config.config_source_errors() == {}


# ------------------------------------------------ saved values take effect
def _set(setting_id, value):
    r = _save([{"id": setting_id, "value": value}], confirm=True)
    assert r.status_code == 200, r.text
    _loaded()


def test_email_block_stops_the_email_tool_and_platform_email(monkeypatch, audit_rows):
    from maverick import mailer
    from maverick.tools.email_tool import email_tool

    assert mailer.sending_disabled() is False
    _set("email.disable", True)
    assert mailer.sending_disabled() is True and mailer.configured() is False
    assert "disabled" in email_tool().fn({"op": "send", "to": "a@b.co", "subject": "s"})
    monkeypatch.setenv("MAVERICK_EMAIL_DISABLE", "0")
    assert mailer.sending_disabled() is False


def test_saved_accounts_reach_the_email_calendar_erp_github_and_notes_tools(tmp_path,
                                                                           audit_rows):
    from maverick.tools import calendar_tool, email_tool, erp_tool, github_search, obsidian

    for key in ("email.user", "email.app_password", "email.smtp_host", "calendar.url",
                "calendar.password", "erp.base_url", "erp.token", "erp.system",
                "github.token"):
        _set(key, VALUES[key][0])
    _set("obsidian.vault_path", str(tmp_path / "notes"))
    assert email_tool._cfg("smtp_host", "EMAIL_SMTP_HOST") == "smtp.example.com"
    assert email_tool._cfg("app_password", "EMAIL_APP_PASSWORD") == "sample-app-password"  # pragma: allowlist secret
    assert calendar_tool._cfg("url", "CALDAV_URL") == "https://caldav.example.com/dav"
    assert erp_tool._config() == ("https://erp.example.com/api", "sample-erp-token", "NetSuite")
    assert github_search._token() == "sample-github-token"  # pragma: allowlist secret
    assert obsidian._vault() == tmp_path / "notes"


def test_billing_rows_change_plans_prices_and_caps(audit_rows):
    from maverick import billing, config
    from maverick.tenant import registry

    assert billing.entitlements_for("pro").max_daily_dollars == 100.0
    _set("billing.plans", VALUES["billing.plans"][0])
    pro = billing.entitlements_for("pro")
    assert pro.max_daily_dollars == 50.0 and pro.max_concurrent_goals == 3
    assert pro.features == frozenset({"core", "channels"})
    _set("billing.enforce_plan_caps", True)
    assert registry._enforce_plan_caps() is True
    _set("billing.stripe.prices.pro", "price_1ProSample")
    assert config.get_billing_stripe()["prices"] == {"pro": "price_1ProSample"}


def test_refunds_follow_the_saved_choice_and_the_environment_wins(monkeypatch, audit_rows):
    from maverick.tools import stripe_tool

    assert stripe_tool._refunds_allowed() is False
    _set("commerce.stripe_refunds", True)
    assert stripe_tool._refunds_allowed() is True
    monkeypatch.setenv("MAVERICK_STRIPE_ENABLE_REFUNDS", "false")
    assert stripe_tool._refunds_allowed() is False


def test_webhook_and_tracker_rows_reach_their_readers(monkeypatch, audit_rows):
    from maverick import github_app, issue_webhooks, webhooks
    from maverick_channels import base

    for key in ("webhooks.workers", "webhooks.max_inflight", "webhooks.max_age_seconds",
                "webhooks.body_limit", "webhooks.linear_bot_id", "webhooks.jira_bot_id",
                "webhooks.gitlab_bot_username", "github.trigger_labels"):
        _set(key, VALUES[key][0])
    assert webhooks._pool_size() == 8 and webhooks._max_inflight() == 200
    assert webhooks._default_max_age() == 600
    assert base.webhook_body_limit() == 2097152
    assert issue_webhooks._bot_id("linear") == "bot@example.com"
    assert issue_webhooks._bot_id("gitlab") == "lightwork-bot"
    assert issue_webhooks._is_bot(["5B10AC8D82E05B22CC7D4EF5"], "jira") is True  # pragma: allowlist secret
    assert github_app._trigger_labels() == {"automate", "fix-me"}
    monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", "env-bot")
    monkeypatch.setenv("MAVERICK_WEBHOOK_BODY_LIMIT", "4096")
    assert issue_webhooks._bot_id("linear") == "env-bot"
    assert base.webhook_body_limit() == 4096


def test_alert_batching_import_and_rendering_rows_take_effect(audit_rows):
    from maverick import notification_batcher, ops_alert
    from maverick.automation_import import ir
    from maverick_channels import rich_render

    for key in ("notifications.batch_max", "alerts.enabled", "automation_import.max_steps",
                "channels.rich_render"):
        _set(key, VALUES[key][0])
    assert notification_batcher.policy_from_config().max_batch == 25
    assert ops_alert.alerts_enabled() is True
    assert ir._max_render_steps() == 400
    assert rich_render.enabled() is True


def test_tax_update_rows_reach_the_tax_channel(audit_rows):
    from maverick import config, tax_constants

    _set("tax.update_url", "https://tax.example.com/constants.json")
    _set("tax.trusted_constants_pubkeys", [_KEY])
    assert config.get_tax()["update_url"] == "https://tax.example.com/constants.json"
    assert tax_constants.trusted_pubkeys() == [_KEY]


def test_voice_rows_reach_the_voice_tools(monkeypatch, audit_rows):
    from maverick.tools import audio_understanding, voice
    from maverick_dashboard import api

    for key in ("voice.stt_backend", "voice.stt_model", "voice.stt_openai_model",
                "voice.tts_elevenlabs_model", "voice.transcribe_concurrency",
                "voice.max_upload_bytes", "attachments.audio_max_bytes"):
        _set(key, VALUES[key][0])
    assert voice._default_stt_backend() == "local"
    assert voice.local_stt_model() == "base"
    assert voice._hosted_model("MAVERICK_WHISPER_OPENAI_MODEL", "whisper-1",
                               "stt_openai_model") == "gpt-4o-transcribe"
    assert voice._hosted_model("MAVERICK_TTS_ELEVENLABS_MODEL", "x",
                               "tts_elevenlabs_model") == "eleven-multilingual-v2"
    assert api._voice_transcribe_concurrency_limit() == 4
    assert api._voice_setting("max_upload_bytes") == 52428800
    assert audio_understanding._audio_limit() == 134217728
    monkeypatch.setenv("MAVERICK_WHISPER_MODEL", "tiny")
    assert voice.local_stt_model() == "tiny"


def test_vendor_read_retries_apply_to_a_saved_workspace_binding(monkeypatch, audit_rows):
    from maverick import vendor_onboarding_setup as setup

    binding = {"enable": True, "resource_owner": "user:owner", "ticket_connection": "jira",
               "document_connection": "drive", "reviewed_uploads": True,
               "safe_read_attempts": 3, "safe_read_backoff_seconds": 0.25}
    monkeypatch.setattr(setup, "current", lambda: {"binding": binding})
    _set("vendor_onboarding.safe_read_attempts", 5)
    _set("vendor_onboarding.safe_read_backoff_seconds", 1.5)
    chosen = setup.settings(_loaded())
    assert chosen.safe_read_attempts == 5 and chosen.safe_read_backoff_seconds == 1.5
    assert chosen.ticket_connection == "jira" and chosen.resource_owner == "user:owner"


# ------------------------------------------ sealed secrets from the server
def test_saved_stripe_keys_are_used_when_the_server_has_none(monkeypatch, audit_rows):
    from maverick import billing_stripe

    assert billing_stripe.status().has_secret_key is False
    _set("billing.stripe.secret_key", _STRIPE_KEY)
    _set("billing.stripe.webhook_secret", _STRIPE_HOOK)
    assert billing_stripe._secret_key() == _STRIPE_KEY
    status = billing_stripe.status()
    assert status.has_secret_key is True and status.has_webhook_secret is True
    assert _STRIPE_KEY not in repr(status.to_dict())
    monkeypatch.setenv("MAVERICK_STRIPE_SECRET_KEY", "sk_test_fromtheserver")  # pragma: allowlist secret
    assert billing_stripe._secret_key() == "sk_test_fromtheserver"  # pragma: allowlist secret


def test_saved_gist_key_shares_task_histories_and_the_environment_wins(monkeypatch, audit_rows):
    from maverick import run_share

    sent = []

    class Reply:
        def raise_for_status(self):
            return None

        def json(self):
            return {"html_url": "https://gist.github.com/example/1"}

    def post(url, *, content, headers, timeout):
        assert __import__("json").loads(content) == {"files": {}}
        sent.append(headers["Authorization"])
        return Reply()

    import httpx

    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(run_share, "build_gist_payload", lambda goal_id: {"files": {}})
    with pytest.raises(RuntimeError):
        run_share.share_run(1)
    _set("github.share_token", VALUES["github.share_token"][0])
    assert run_share.share_run(1) == "https://gist.github.com/example/1"
    assert sent == ["Bearer " + VALUES["github.share_token"][0]]
    monkeypatch.setenv("GITHUB_TOKEN", "server-gist-key")  # pragma: allowlist secret
    run_share.share_run(1)
    assert sent[-1] == "Bearer server-gist-key"


def test_saved_github_app_secret_verifies_github_messages(monkeypatch, audit_rows):
    import hashlib
    import hmac

    from maverick import github_app

    body = b'{"zen": "Keep it logically awesome."}'
    secret = VALUES["github.app_webhook_secret"][0]
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    headers = {"X-Hub-Signature-256": signature, "X-GitHub-Event": "ping",
               "X-GitHub-Delivery": "delivery-1", "Content-Type": "application/json"}
    assert client.post("/webhook/github", content=body, headers=headers).status_code == 401
    _set("github.app_webhook_secret", secret)
    assert github_app.webhook_secret() == secret
    r = client.post("/webhook/github", content=body, headers=headers)
    assert r.status_code == 200 and r.json() == {"status": "ignored"}
    monkeypatch.setenv("MAVERICK_GH_APP_WEBHOOK_SECRET", "server-secret")  # pragma: allowlist secret
    assert client.post("/webhook/github", content=body, headers=headers).status_code == 401


def test_saved_gitlab_token_admits_gitlab_messages(monkeypatch, audit_rows):
    from maverick import issue_webhooks

    token = VALUES["webhooks.gitlab_token"][0]
    headers = {"X-Gitlab-Token": token, "X-Gitlab-Event-UUID": "gitlab-delivery-1"}
    assert client.post("/webhook/gitlab", json={}, headers=headers).status_code == 401
    _set("webhooks.gitlab_token", token)
    assert issue_webhooks.gitlab_webhook_token() == token
    assert client.post("/webhook/gitlab", json={}, headers=headers).status_code not in {401, 403}
    wrong = {**headers, "X-Gitlab-Token": "wrong"}
    assert client.post("/webhook/gitlab", json={}, headers=wrong).status_code == 403


def test_saved_graph_token_reaches_the_data_map_and_data_requests(monkeypatch, audit_rows):
    from maverick import data_map

    assert data_map.graph_token() == ""
    _set("data_map.graph_token", "sample-graph-token")
    assert data_map.graph_token() == "sample-graph-token"  # pragma: allowlist secret
    assert data_map.graph_token("CUSTOM_GRAPH_TOKEN") == "sample-graph-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_GRAPH_TOKEN", "server-token")
    assert data_map.graph_token() == "server-token"


# ------------------------------------------- voice engine from checked lists
def test_only_checked_programs_and_model_files_are_offered(audit_rows):
    row = _row("voice.whisper_cpp_bin")
    assert [c["value"] for c in row["choices"]] == ["", "whisper-cli"]
    assert "/" not in repr(row["choices"])
    row = _row("voice.whisper_cpp_model")
    assert [c["value"] for c in row["choices"]] == ["", "ggml-custom.bin"]
    assert "/" not in repr(row["choices"])


@pytest.mark.parametrize("value", ["/usr/bin/python3", "whisper.cpp", "whisper-cpp", "ffmpeg",
                                   "../outside/tool"])
def test_programs_outside_the_list_are_refused(value, audit_rows):
    r = _save([{"id": "voice.whisper_cpp_bin", "value": value}], confirm=True)
    assert r.status_code == 400, r.text
    assert "voice" not in _loaded()


def test_a_chosen_program_runs_and_is_checked_again_before_it_runs(tmp_path, monkeypatch,
                                                                    audit_rows):
    import shutil

    from maverick import voice_models
    from maverick.tools import voice

    monkeypatch.setattr(shutil, "which", lambda name: None)
    r = _save([{"id": "voice.whisper_cpp_bin", "value": "whisper-cli"}])
    assert r.status_code == 409
    _set("voice.whisper_cpp_bin", "whisper-cli")
    program = tmp_path / "home" / "bin" / "whisper-cli"
    assert voice._find_whisper_cpp() == str(program)
    assert audit_rows[-1]["key"] == "whisper_cpp_bin" and audit_rows[-1]["new"] == "whisper-cli"
    # The file is swapped for a link out of the folder after it was chosen.
    program.unlink()
    _link_for_qualification(program, tmp_path / "outside" / "tool", required=True)
    assert voice_models.checked_program("whisper-cli") is None
    assert voice._find_whisper_cpp() is None
    monkeypatch.setenv("MAVERICK_WHISPER_CPP", str(tmp_path / "outside" / "tool"))
    monkeypatch.setattr(shutil, "which", lambda name: name if name.endswith("tool") else None)
    assert voice._find_whisper_cpp() == str(tmp_path / "outside" / "tool")


def test_a_chosen_model_file_loads_and_a_link_out_is_refused(tmp_path, audit_rows):
    from maverick import voice_models

    _set("voice.whisper_cpp_model", "ggml-custom.bin")
    chosen = tmp_path / "home" / "models" / "whisper" / "ggml-custom.bin"
    assert voice_models.locate_model() == chosen
    assert all(p.name != "ggml-escape.bin" for p in voice_models.installed_models())
    chosen.unlink()
    _link_for_qualification(chosen, tmp_path / "outside" / "ggml-escape.bin", required=True)
    assert voice_models.checked_model_file("ggml-custom.bin") is None
    assert voice_models.locate_model() is None


def test_saved_pushover_keys_send_alerts_and_the_environment_wins(monkeypatch, audit_rows):
    import httpx
    from maverick import notifications

    sent: list[dict] = []

    class Reply:
        status_code = 200

        def json(self):
            return {"status": 1}

    def post(url, data=None, **kwargs):
        sent.append(dict(data or {}))
        return Reply()

    monkeypatch.setattr(httpx, "post", post)
    for name in ("PUSHOVER_USER_KEY", "PUSHOVER_APP_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert notifications._send_pushover("Title", "Body", "default") is False
    _set("notifications.user_key", _PUSHOVER_USER)
    _set("notifications.app_token", _PUSHOVER_APP)
    assert notifications._send_pushover("Title", "Body", "default") is True
    assert sent[-1]["user"] == _PUSHOVER_USER and sent[-1]["token"] == _PUSHOVER_APP
    monkeypatch.setenv("PUSHOVER_USER_KEY", "server-user-key")
    assert notifications._send_pushover("Title", "Body", "high") is True
    assert sent[-1]["user"] == "server-user-key" and sent[-1]["token"] == _PUSHOVER_APP


# ------------------------------------------------------- Mattermost channel
def test_mattermost_is_set_up_on_the_channels_page_with_a_sealed_token(monkeypatch, audit_rows):
    from maverick import config

    token = "sample-mattermost-bot-token"  # pragma: allowlist secret
    page = client.get("/channels")
    assert page.status_code == 200 and "Mattermost" in page.text
    refused = client.post("/channels/save", follow_redirects=False, data={
        "review_token": channel_review_token(client),
        "channel": "mattermost", "enabled": "on", "url": "http://chat.example.com",
        "bot_token": token})
    assert refused.status_code == 400
    saved = client.post("/channels/save", follow_redirects=False, data={
        "review_token": channel_review_token(client),
        "channel": "mattermost", "enabled": "on", "url": "https://chat.example.com/",
        "bot_token": token})
    assert saved.status_code == 303
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert token not in stored and "MVKAR1:" in stored
    table = _loaded()["channels"]["mattermost"]
    assert table == {"enabled": True, "url": "https://chat.example.com", "bot_token": token}
    assert token not in client.get("/channels").text
    _set("channels.mattermost.allowed_user_ids", ["alice"])
    assert _loaded()["channels"]["mattermost"]["allowed_user_ids"] == ["alice"]
    monkeypatch.setenv("MATTERMOST_BOT_TOKEN", "server-token")
    from maverick_dashboard import settings_store

    (row,) = [c for c in settings_store.channels_state() if c["name"] == "mattermost"]
    token_field = next(f for f in row["fields"] if f["key"] == "bot_token")
    assert token_field["hint"] == "on the server" and token_field["value"] == ""


def test_a_saved_routing_rule_changes_which_specialist_handles_a_message(audit_rows):
    from maverick.channel_autorouting import specialist_for

    class Message:
        channel = "slack"
        text = "please pay this invoice"
        attachments = [{"mime": "application/pdf"}]

    assert specialist_for(Message()) == ""
    row = _row("channels.routing.rules")
    specialist_column = next(c for c in row["grid"]["columns"] if c["key"] == "specialist")
    assert any(choice["value"] == _SPECIALIST for choice in specialist_column["choices"])
    _set("channels.routing.rules", [_RULE])
    assert specialist_for(Message()) == _SPECIALIST
    Message.text = "what is on my calendar"
    assert specialist_for(Message()) == ""
    page = client.get("/channels")
    assert page.status_code == 200 and "Routing" not in page.text
