"""maverick migrate: advisories, unknown-section lint, dry-run safety."""
from __future__ import annotations

from click.testing import CliRunner
from maverick.migrate import KNOWN_SECTIONS, migrate, render


def _cfg(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_apply_with_no_rewrites_reads_differently_from_dry_run(tmp_path):
    # A lint finding but no mechanical rewrites: --apply must not print the
    # same "(dry run …)" line as a plain dry run, or an operator can't tell
    # their --apply was accepted.
    p = _cfg(tmp_path, "[budgets]\nmax = 5\n")  # unknown section -> lint, no rewrite
    dry = render(migrate(p, apply=False))
    applied = render(migrate(p, apply=True))
    assert "dry run" in dry and "dry run" not in applied
    assert "--apply" in applied


def test_apply_rewrites_renames_key(monkeypatch):
    # The rewrite machinery ships with REWRITES empty (no key renamed yet), so
    # its apply path was untested. Exercise it directly with a temporary rename
    # so a future 2.0 rename lands on validated code, not shipped-blind.
    import maverick.migrate as m
    monkeypatch.setattr(m, "REWRITES", [("old_section.key", "new_section.key")])
    cfg = {"old_section": {"key": "v", "other": 1}}
    findings = m._apply_rewrites(cfg)
    assert cfg == {"old_section": {"other": 1}, "new_section": {"key": "v"}}
    assert findings and findings[0].kind == "rewrite" and findings[0].applied


def test_apply_rewrites_noop_when_key_absent(monkeypatch):
    import maverick.migrate as m
    monkeypatch.setattr(m, "REWRITES", [("a.b", "c.d")])
    cfg = {"unrelated": {"x": 1}}
    assert m._apply_rewrites(cfg) == []
    assert cfg == {"unrelated": {"x": 1}}


def test_clean_config(tmp_path):
    p = _cfg(tmp_path, "[budget]\nmax_dollars = 5.0\n")
    report = migrate(p)
    assert report.clean
    assert "config is current" in render(report)


def test_whatsapp_twilio_advisory(tmp_path):
    p = _cfg(tmp_path, "[channels.whatsapp]\nenabled = true\n")
    report = migrate(p)
    ids = [f.id for f in report.findings]
    assert "whatsapp-twilio-to-cloud" in ids
    assert "ADVISE" in render(report)
    # Already on cloud -> no advisory.
    p2 = _cfg(tmp_path / "sub" if (tmp_path / "sub").mkdir() or True else tmp_path,
              "[channels.whatsapp]\nenabled = true\n[channels.whatsapp_cloud]\nenabled = true\n")
    assert migrate(p2).clean


def test_unknown_section_lint_with_suggestion(tmp_path):
    p = _cfg(tmp_path, "[budgets]\nmax_dollars = 5.0\n")
    report = migrate(p)
    f = report.findings[0]
    assert f.kind == "lint" and "did you mean [budget]" in f.message


def test_known_sections_cover_real_config_surface():
    for section in (
        "budget", "channels", "safety", "tools", "world_model",
        "plugins", "compliance", "routing", "grpc_dispatch",
        "models", "capabilities", "features", "security", "mcp_servers",
        "tenancy",
    ):
        assert section in KNOWN_SECTIONS


def test_runtime_sections_do_not_lint_as_unknown(tmp_path):
    p = _cfg(tmp_path, """
[models]
planner = "openai:gpt-5"
[capabilities]
web_search = true
[features]
skills = true
[security]
allowed_tools = ["read"]
[mcp_servers]
[tenancy]
by_user = true
""")
    assert migrate(p).clean


def test_default_config_uses_active_runtime_path(tmp_path, monkeypatch):
    home = tmp_path / "home"
    default_dir = home / ".maverick"
    default_dir.mkdir(parents=True)
    (default_dir / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")

    active = tmp_path / "etc" / "maverick" / "config.toml"
    active.parent.mkdir(parents=True)
    active.write_text("[channels.whatsapp]\nenabled = true\n", encoding="utf-8")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(active))

    report = migrate()
    assert [f.id for f in report.findings] == ["whatsapp-twilio-to-cloud"]


def test_dry_run_never_writes(tmp_path):
    p = _cfg(tmp_path, "[mystery]\nx = 1\n")
    before = p.read_text()
    report = migrate(p)
    assert p.read_text() == before
    assert not report.wrote and report.backup_path is None
    assert "(dry run" in render(report)


def test_missing_and_unparseable_config(tmp_path):
    report = migrate(tmp_path / "nope.toml")
    assert report.findings[0].id == "no-config"
    bad = _cfg(tmp_path, "not [valid toml")
    assert migrate(bad).findings[0].id == "unparseable"


def test_cli(tmp_path):
    from maverick import cli as cli_mod
    p = _cfg(tmp_path, "[channels.whatsapp]\nenabled = true\n")
    r = CliRunner().invoke(cli_mod.main, ["migrate", "--config", str(p)])
    assert r.exit_code == 0, r.output
    assert "ADVISE" in r.output and "dry run" in r.output
