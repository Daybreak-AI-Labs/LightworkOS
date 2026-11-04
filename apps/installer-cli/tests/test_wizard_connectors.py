"""pick_connectors collects connector credentials into the .env keys.

Connectors are always registered in the kernel; the wizard's only job is to
collect their BASE_URL/TOKEN env vars (merged into ~/.maverick/.env). The
catalog is the single source of truth shared with docs/connectors.md.
"""
from __future__ import annotations


def _fake_catalog():
    return [
        {"name": "servicenow", "label": "ServiceNow",
         "env": [("SERVICENOW_INSTANCE_URL", False), ("SERVICENOW_TOKEN", True)]},
        {"name": "snowflake", "label": "Snowflake",
         "env": [("SNOWFLAKE_ACCOUNT", False), ("SNOWFLAKE_TOKEN", True)]},
    ]


def _drive(monkeypatch, *, enable, names, texts, secrets):
    """Run pick_connectors with scripted prompt answers."""
    # Patch the catalog import target (function lives in maverick-core).
    import maverick.tools.enterprise_connectors as ec
    from maverick_installer import wizard
    monkeypatch.setattr(ec, "connector_catalog", _fake_catalog)

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: enable)
    text_iter = iter([names, *texts])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(text_iter))
    secret_iter = iter(secrets)
    monkeypatch.setattr(wizard, "_q_secret", lambda *a, **k: next(secret_iter))
    return wizard.pick_connectors()


def test_declined_returns_empty(monkeypatch):
    keys = _drive(monkeypatch, enable=False, names="", texts=[], secrets=[])
    assert keys == {}


def test_collects_url_and_secret(monkeypatch):
    keys = _drive(
        monkeypatch,
        enable=True,
        names="servicenow",
        texts=["https://acme.service-now.com"],  # SERVICENOW_INSTANCE_URL (url)
        secrets=["tok-123"],                      # SERVICENOW_TOKEN (secret)
    )
    assert keys == {
        "SERVICENOW_INSTANCE_URL": "https://acme.service-now.com",
        "SERVICENOW_TOKEN": "tok-123",
    }


def test_unknown_name_skipped(monkeypatch):
    keys = _drive(
        monkeypatch,
        enable=True,
        names="servicenow, not_a_real_system",
        texts=["https://acme.service-now.com"],
        secrets=["tok-123"],
    )
    # The bogus name contributes nothing; the valid one is still collected.
    assert keys == {
        "SERVICENOW_INSTANCE_URL": "https://acme.service-now.com",
        "SERVICENOW_TOKEN": "tok-123",
    }


def test_blank_values_are_not_written(monkeypatch):
    keys = _drive(
        monkeypatch, enable=True, names="snowflake",
        texts=[""],     # SNOWFLAKE_ACCOUNT left blank
        secrets=[""],   # SNOWFLAKE_TOKEN left blank
    )
    assert keys == {}


def test_catalog_is_the_source_of_truth():
    """The real catalog is well-formed and covers headline systems."""
    from maverick.tools.enterprise_connectors import connector_catalog

    cat = connector_catalog()
    names = [e["name"] for e in cat]
    assert len(names) == len(set(names)), "connector names must be unique"
    assert len(cat) >= 150
    for headline in ("servicenow", "salesforce", "snowflake", "sap", "workday",
                     "datadog", "stripe"):
        assert headline in names, headline
    # Shape: each entry has a label and (env_name, is_secret) pairs.
    for e in cat:
        assert e["label"] and isinstance(e["env"], list) and e["env"]
        for pair in e["env"]:
            assert len(pair) == 2 and isinstance(pair[1], bool)
