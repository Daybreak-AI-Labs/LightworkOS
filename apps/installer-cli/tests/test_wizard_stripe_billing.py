"""Wizard step for Stripe platform billing ([billing.stripe]).

Parity: the wizard offers the capability (rule 6), writes a section the kernel
reads back, config-lint does not false-flag it, and it is OFF unless opted in.
"""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]


def _write_full_config(tmp_path: Path, monkeypatch, **overrides) -> dict:
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    base = dict(
        providers=["anthropic"],
        role_models={},
        channels={},
        safety={"profile": "balanced", "block_threshold": "high",
                "scan_input": True, "scan_tool_calls": True, "scan_output": True},
        budget={"max_dollars": 5.0, "max_wall_seconds": 3600.0, "max_tool_calls": 500},
        sandbox={"backend": "local", "workdir": str(tmp_path / "ws"), "timeout": 60},
        keys={},
        capabilities={"computer_use": False, "browser": False},
    )
    base.update(overrides)
    wizard.write_config(**base)
    return tomllib.loads((tmp_path / "config.toml").read_text())


def test_pick_advanced_includes_stripe_billing(monkeypatch):
    # Off by default, like commerce/fleet_memory: an explicit money decision.
    monkeypatch.setattr("maverick_installer.wizard._q_confirm", lambda *a, **kw: False)
    monkeypatch.setattr("maverick_installer.wizard._q_text",
                        lambda *a, **kw: kw.get("default", ""))
    monkeypatch.setattr("maverick_installer.wizard._q_select",
                        lambda *a, **kw: kw.get("default", a[1][0]) if len(a) > 1 else "")
    monkeypatch.setattr("maverick_installer.wizard._q_checkbox",
                        lambda *a, **kw: kw.get("default", []))
    from maverick_installer.wizard import pick_advanced
    adv = pick_advanced()
    assert "stripe_billing" in adv
    assert adv["stripe_billing"] is False


def test_write_config_emits_billing_stripe(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"stripe_billing": True})
    stripe = parsed["billing"]["stripe"]
    assert stripe["enable"] is True
    # bill_metered_usage ships OFF (platform fee only until an operator turns it on).
    assert stripe["bill_metered_usage"] is False
    assert stripe["currency"] == "usd"
    # The prices sub-table exists (commented example ids -> empty table).
    assert stripe.get("prices", {}) == {}
    # The secret NEVER lands in the config file.
    body = (tmp_path / "config.toml").read_text()
    assert "MAVERICK_STRIPE_SECRET_KEY" in body  # only as a comment/reminder
    assert "sk_" not in body

    # The kernel reads back exactly what the wizard wrote.
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    resolved = config.get_billing_stripe()
    assert resolved["enable"] is True
    assert resolved["bill_metered_usage"] is False
    assert resolved["currency"] == "usd"


def test_write_config_omits_billing_stripe_when_off(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "billing" not in parsed


def test_billing_stripe_section_passes_config_lint(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"stripe_billing": True})
    from maverick.config_lint import lint_config
    findings = lint_config(parsed)
    # config-lint must not false-flag the wizard's own [billing.stripe] output.
    assert not [f for f in findings if f.section == "billing"], findings
