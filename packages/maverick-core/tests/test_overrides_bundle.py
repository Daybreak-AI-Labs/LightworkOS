"""Portable customization bundle: export a workspace's overrides and load them
into another, validating each item on the way in."""
from __future__ import annotations

from maverick.domain import available_domains
from maverick.overrides_bundle import export_overrides, load_overrides
from maverick.role_edit import role_addendum, write_role_override

VALID_PACK = (
    'name = "client_fin"\n'
    'allow_tools = ["read_file"]\n'
    'max_risk = "low"\n'
    'persona = "A finance specialist tuned for this client."\n'
)


def _use_workspace(monkeypatch, root):
    """Point the active workspace (domains dir + roles file) at ``root``."""
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(root / "domains"))
    monkeypatch.setenv("MAVERICK_ROLES_FILE", str(root / "roles.toml"))


class TestRoundTrip:
    def test_export_then_load_into_another_workspace(self, tmp_path, monkeypatch):
        src, dest, bundle = tmp_path / "src", tmp_path / "dest", tmp_path / "bundle"

        # Source workspace: one domain override + one role addendum.
        _use_workspace(monkeypatch, src)
        (src / "domains").mkdir(parents=True)
        (src / "domains" / "client_fin.toml").write_text(VALID_PACK)
        write_role_override("coder", {"system_addendum": "Prefer small diffs."})

        n = export_overrides(bundle)
        assert n == {"domains": 1, "roles": 1}
        assert (bundle / "domains" / "client_fin.toml").is_file()
        assert (bundle / "roles.toml").is_file()

        # A fresh workspace starts without them...
        _use_workspace(monkeypatch, dest)
        assert "client_fin" not in available_domains()
        assert role_addendum("coder") == ""

        # ...then the bundle brings them in.
        loaded = load_overrides(bundle)
        assert loaded["domains"] == 1 and loaded["roles"] == 1 and loaded["skipped"] == []
        assert "client_fin" in available_domains()
        assert role_addendum("coder") == "Prefer small diffs."


class TestValidationOnLoad:
    def test_invalid_pack_is_skipped(self, tmp_path, monkeypatch):
        _use_workspace(monkeypatch, tmp_path / "ws")
        bundle = tmp_path / "bundle"
        (bundle / "domains").mkdir(parents=True)
        # Empty allow_tools => lint error => must be skipped, not written.
        (bundle / "domains" / "bad.toml").write_text('name = "bad"\nallow_tools = []\nmax_risk = "low"\n')
        (bundle / "domains" / "client_fin.toml").write_text(VALID_PACK)

        out = load_overrides(bundle)
        assert out["domains"] == 1                       # only the good one
        assert any("domains/bad.toml" in s for s in out["skipped"])
        assert "client_fin" in available_domains()
        assert "bad" not in available_domains()

    def test_pack_name_mismatch_is_skipped(self, tmp_path, monkeypatch):
        _use_workspace(monkeypatch, tmp_path / "ws")
        bundle = tmp_path / "bundle"
        (bundle / "domains").mkdir(parents=True)
        (bundle / "domains" / "ok.toml").write_text(VALID_PACK)

        out = load_overrides(bundle)
        assert out["domains"] == 0
        assert any("domains/ok.toml" in s for s in out["skipped"])
        assert not (tmp_path / "ws" / "domains" / "ok.toml").exists()
        assert "client_fin" not in available_domains()

    def test_unknown_role_is_skipped(self, tmp_path, monkeypatch):
        _use_workspace(monkeypatch, tmp_path / "ws")
        bundle = tmp_path / "bundle"
        bundle.mkdir(parents=True)
        (bundle / "roles.toml").write_text(
            '[coder]\nsystem_addendum = "ok"\n'
            '[not_a_role]\nsystem_addendum = "nope"\n'
        )
        out = load_overrides(bundle)
        assert out["roles"] == 1
        assert any("not_a_role" in s for s in out["skipped"])
        assert role_addendum("coder") == "ok"

    def test_empty_bundle_is_a_noop(self, tmp_path, monkeypatch):
        _use_workspace(monkeypatch, tmp_path / "ws")
        empty = tmp_path / "empty"
        empty.mkdir()
        assert load_overrides(empty) == {"domains": 0, "roles": 0, "skipped": []}


class TestExportEdges:
    def test_export_empty_workspace(self, tmp_path, monkeypatch):
        _use_workspace(monkeypatch, tmp_path / "ws")
        assert export_overrides(tmp_path / "bundle") == {"domains": 0, "roles": 0}


class TestNewSpecialistSwitch:
    def test_a_new_specialist_in_a_bundle_waits_while_the_switch_is_on(self, tmp_path, monkeypatch):
        from maverick import config

        _use_workspace(monkeypatch, tmp_path / "ws")
        monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
        (tmp_path / "config.toml").write_text("[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
        config.reset_config_cache()
        bundle = tmp_path / "bundle"
        (bundle / "domains").mkdir(parents=True)
        (bundle / "domains" / "client_fin.toml").write_text(VALID_PACK)
        try:
            held = load_overrides(bundle)
            assert held["domains"] == 0
            assert any(item.startswith("domains/client_fin.toml") and "saved check" in item for item in held["skipped"])
            assert "client_fin" not in available_domains()
            assert not (tmp_path / "ws" / "domains" / "client_fin.toml").exists()

            # With the switch off the same bundle loads, and a changed specialist that already exists loads with it on.
            (tmp_path / "config.toml").write_text("", encoding="utf-8")
            config.reset_config_cache()
            assert load_overrides(bundle)["domains"] == 1
            assert "client_fin" in available_domains()
            (tmp_path / "config.toml").write_text("[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
            config.reset_config_cache()
            (bundle / "domains" / "client_fin.toml").write_text(VALID_PACK.replace("tuned for this client", "tuned for a client"))
            changed = load_overrides(bundle)
            assert changed["domains"] == 1 and changed["skipped"] == []
        finally:
            config.reset_config_cache()
