"""Governance profiles: business-shaped onboarding levels.

One early wizard question maps a business type to a preset bundle of
existing knobs: every level gets the self-learning/self-improvement
lifecycle; what escalates is the governance posture around it
(essentials -> standard -> regulated).
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]


def _stub_wizard_io(monkeypatch, tmp_path: Path, key: str = "sk-ant-test"):
    """Wire the IO primitives the consumer/express flows touch (mirrors the
    helper in test_wizard_consumer_mode; tests dir is not an importable
    package, so it lives here too)."""
    from maverick_installer import wizard

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    answers = iter([
        "Alex",                        # user_name
        str(tmp_path / "workspace"),   # workdir
    ])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    monkeypatch.setattr(wizard, "_q_secret", lambda *a, **kw: key)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: "$5")

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path / ".maverick")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / ".maverick" / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".maverick" / ".env")
    monkeypatch.setattr(
        wizard, "VALIDATION_CACHE_PATH",
        tmp_path / ".maverick" / "validation-cache.json",
    )
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH",
                        tmp_path / ".maverick" / "wizard-partial.json")
    monkeypatch.setattr(wizard, "preflight", lambda: True)
    monkeypatch.setattr(wizard, "_docker_available", lambda: False)
    monkeypatch.setattr(
        wizard, "_validate_anthropic_key", lambda k: (True, "validated"),
    )
    return wizard


def _select_stub(profile_answer: str):
    """A _q_select stub that answers the business-type question with
    ``profile_answer`` and every other select (budget) with its default."""
    def fake_select(message, choices, default=None):
        if "kind of business" in message:
            return profile_answer
        return "$5"
    return fake_select


def _load_config(tmp_path: Path) -> dict:
    return tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())


# ---------- the preset data ----------

def test_profiles_are_exactly_the_three_levels():
    from maverick_installer import wizard
    assert set(wizard.GOVERNANCE_PROFILES) == {"essentials", "standard", "regulated"}
    assert wizard.DEFAULT_GOVERNANCE_PROFILE in wizard.GOVERNANCE_PROFILES


def test_levels_escalate_cumulatively():
    """standard is essentials plus governance; regulated is standard plus
    more -- never a different product, always a stricter wrapper."""
    from maverick_installer import wizard
    ess = wizard.GOVERNANCE_PROFILES["essentials"]["advanced"]
    std = wizard.GOVERNANCE_PROFILES["standard"]["advanced"]
    reg = wizard.GOVERNANCE_PROFILES["regulated"]["advanced"]
    assert set(ess.items()) < set(std.items())
    assert set(std.items()) < set(reg.items())


def test_every_level_gets_the_learning_lifecycle():
    from maverick_installer import wizard
    for name, preset in wizard.GOVERNANCE_PROFILES.items():
        for key in ("reflexion", "dreaming", "self_harness", "data_engine",
                    "evaluator_evolution"):
            assert preset["advanced"].get(key) is True, (name, key)
        assert preset["self_learning"]["enable"] is True, name
        # The two higher-trust autonomy switches stay OFF at every level.
        assert preset["self_learning"]["create_tools"] is False, name
        assert preset["self_learning"]["allow_mcp_acquisition"] is False, name
        assert "self_modify" not in preset["advanced"], name


def test_profiles_never_carry_budget():
    """Budget caps are collected separately and are never optional; a
    profile must not smuggle one in (or override one away)."""
    from maverick_installer import wizard
    for preset in wizard.GOVERNANCE_PROFILES.values():
        assert set(preset) == {"advanced", "self_learning", "retention"}
        assert "budget" not in preset["advanced"]


def test_governance_split_by_level():
    from maverick_installer import wizard
    ess = wizard.GOVERNANCE_PROFILES["essentials"]["advanced"]
    std = wizard.GOVERNANCE_PROFILES["standard"]["advanced"]
    reg = wizard.GOVERNANCE_PROFILES["regulated"]["advanced"]
    # Essentials: learning without the ceremony.
    for key in ("audit_sign", "enforce_quotas", "signed_approval", "audit_worm"):
        assert key not in ess
    # Standard: signed audit, but no human-signature gate and no spending
    # caps (administrators set those in the dashboard).
    assert std["audit_sign"] is True
    assert "enforce_quotas" not in std
    assert "signed_approval" not in std
    # Regulated: everything, signed and immutable.
    assert reg["signed_approval"] is True
    assert reg["audit_worm"] is True
    assert reg["audit_rewards"] is True


# ---------- the picker ----------

def test_pick_defaults_to_essentials(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_prior_governance_profile", lambda: None)
    monkeypatch.setattr(wizard, "_q_select",
                        lambda m, c, default=None: default)
    assert wizard.pick_governance_profile() == "essentials"


def test_pick_unrecognised_answer_falls_back(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_prior_governance_profile", lambda: None)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: "$5")
    assert wizard.pick_governance_profile() == "essentials"


def test_pick_each_level_selectable(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_prior_governance_profile", lambda: None)
    for choice in wizard.GOVERNANCE_CHOICES:
        monkeypatch.setattr(wizard, "_q_select", lambda *a, c=choice, **kw: c)
        assert wizard.pick_governance_profile() == choice.split()[0]


def test_pick_defaults_to_prior_level_on_rerun(monkeypatch, tmp_path: Path):
    """Re-running init must NOT silently downgrade a regulated install:
    the picker defaults to the previously recorded level, and even an
    unrecognised answer falls back to the prior, not to essentials."""
    from maverick_installer import wizard
    cfg = tmp_path / ".maverick" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('[governance]\nprofile = "regulated"\n')
    monkeypatch.setattr(wizard, "CONFIG_FILE", cfg)
    seen = {}
    def fake_select(message, choices, default=None):
        seen["default"] = default
        return default
    monkeypatch.setattr(wizard, "_q_select", fake_select)
    assert wizard.pick_governance_profile() == "regulated"
    assert seen["default"].split()[0] == "regulated"
    # Unrecognised answer -> prior, never a silent downgrade to essentials.
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: "$5")
    assert wizard.pick_governance_profile() == "regulated"


# ---------- consumer flow, end to end per level ----------

def test_consumer_default_is_essentials(monkeypatch, tmp_path: Path):
    """Default consumer run: learning ON, no signing/quota ceremony."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    assert wizard.run_consumer() == 0
    config = _load_config(tmp_path)
    assert config["governance"]["profile"] == "essentials"
    # The lifecycle is on...
    assert config["self_learning"]["enable"] is True
    assert config["self_learning"]["create_tools"] is False
    assert config["self_learning"]["allow_mcp_acquisition"] is False
    assert "self_modify" not in config
    assert config["reflexion"]["enable"] is True
    assert config["dreaming"]["enable"] is True
    # The promotion ladder the lifecycle rides is actually ON.
    assert config["self_improvement"]["enable"] is True
    # ...without the governance ceremony.
    assert "audit" not in config
    assert "quotas" not in config
    assert config["retention"]["audit_days"] == 30
    assert config["retention"]["messages_days"] == 30
    # Safety seat unchanged at every level.
    assert config["safety"]["profile"] == "strict"
    assert config["budget"]["max_dollars"] == 5.0


def test_consumer_standard_level(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(
        wizard, "_q_select",
        _select_stub("standard   - growing company: + signed audit trail, fairness "
                     "and memory checks (a manufacturer, an agency)"))
    assert wizard.run_consumer() == 0
    config = _load_config(tmp_path)
    assert config["governance"]["profile"] == "standard"
    assert config["audit"]["sign"] is True
    # No spending caps by default; administrators set them in the dashboard.
    assert "quotas" not in config
    assert config["retention"]["audit_days"] == 90
    assert config["retention"]["messages_days"] == 90
    # Ladder on; still no human-signature gate and no WORM at standard.
    assert config["self_improvement"]["enable"] is True
    assert not config["self_improvement"].get("require_signed_approval")
    assert "worm" not in config.get("audit", {})
    # The lifecycle is identical to essentials.
    assert config["self_learning"]["enable"] is True
    assert config["dreaming"]["enable"] is True


def test_consumer_regulated_level(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(
        wizard, "_q_select",
        _select_stub("regulated  - bank / clinic / government: + human "
                     "sign-off, immutable audit, long retention"))
    assert wizard.run_consumer() == 0
    config = _load_config(tmp_path)
    assert config["governance"]["profile"] == "regulated"
    assert config["audit"]["sign"] is True
    assert config["audit"]["worm"]["provider"] == "local"
    assert "quotas" not in config
    assert config["self_improvement"]["enable"] is True
    assert config["self_improvement"]["require_signed_approval"] is True
    assert config["retention"]["audit_days"] == 365
    assert config["retention"]["messages_days"] == 365
    # Learning still on -- regulated is a stricter wrapper, not a lobotomy.
    assert config["self_learning"]["enable"] is True
    assert config["reflexion"]["enable"] is True


# ---------- express flow layers the profile on top ----------

def test_express_regulated_adds_governance(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(
        wizard, "_q_select",
        _select_stub("regulated  - bank / clinic / government: + human "
                     "sign-off, immutable audit, long retention"))
    assert wizard.run_express() == 0
    config = _load_config(tmp_path)
    assert config["governance"]["profile"] == "regulated"
    # Express features intact...
    assert config["flows"]["enable"] is True
    assert config["self_learning"]["enable"] is True
    # ...plus the regulated posture on top.
    assert "quotas" not in config
    assert config["self_improvement"]["enable"] is True
    assert config["self_improvement"]["require_signed_approval"] is True
    assert config["retention"]["audit_days"] == 365
    assert config["retention"]["messages_days"] == 365


# ---------- reading the saved profile back ----------

@pytest.fixture
def windows_default_encoding(monkeypatch):
    """Windows' default text encoding is the ANSI code page (cp1252). pathlib
    takes its default from io.text_encoding(None), which follows UTF-8 mode
    where it is on, so this makes that default cp1252 on any platform."""
    def ansi_default(encoding=None, stacklevel=2):
        return "cp1252" if encoding is None else encoding

    monkeypatch.setattr(io, "text_encoding", ansi_default)


def test_a_saved_profile_is_read_as_utf8_where_the_default_is_cp1252(
        monkeypatch, tmp_path: Path, windows_default_encoding):
    from maverick_installer import wizard
    cfg = tmp_path / "config.toml"
    # The wizard writes config.toml as UTF-8. "ō" is C5 8D and 0x8D is
    # undefined in cp1252, so a read with the wrong encoding fails outright.
    cfg.write_bytes('# Site: Tōkyō\n[governance]\nprofile = "regulated"\n'.encode())
    monkeypatch.setattr(wizard, "CONFIG_FILE", cfg)
    assert wizard._prior_governance_profile() == "regulated"


@pytest.mark.parametrize("content", [
    b'[governance]\nprofile = "regulated"\n# Site: T\xf4kyo\n',  # Latin-1 bytes, not UTF-8
    b'[governance\nprofile = "regulated"\n',  # invalid TOML
])
def test_an_unreadable_config_is_said_out_loud_not_silently_defaulted(monkeypatch, tmp_path: Path, content):
    """A saved regulated level must never turn into the essentials default
    without anyone being told: the person is asked to pick it again."""
    from maverick_installer import wizard
    cfg = tmp_path / "config.toml"
    cfg.write_bytes(content)
    monkeypatch.setattr(wizard, "CONFIG_FILE", cfg)
    said = []
    monkeypatch.setattr(wizard.console, "print", lambda *a, **k: said.append(" ".join(map(str, a))))
    assert wizard._prior_governance_profile() is None
    assert any("could not be read" in line and "Pick it again" in line for line in said)


def test_no_saved_config_means_no_prior_and_no_warning(monkeypatch, tmp_path: Path):
    from maverick_installer import wizard
    cfg = tmp_path / "config.toml"
    monkeypatch.setattr(wizard, "CONFIG_FILE", cfg)
    said = []
    monkeypatch.setattr(wizard.console, "print", lambda *a, **k: said.append(" ".join(map(str, a))))
    assert wizard._prior_governance_profile() is None
    assert said == []
    cfg.write_text("[governance\nprofile = \"regulated\"\n", encoding="utf-8")
    assert wizard._prior_governance_profile() is None
