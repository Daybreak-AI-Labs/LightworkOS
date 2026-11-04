"""Per-client role customization: the editable system-prompt addendum, its
validation, persistence, and the merged view the dashboard renders."""
from __future__ import annotations

import pytest
from maverick.role_edit import (
    ROLES,
    list_roles,
    override_effort,
    override_model,
    remove_role_override,
    resolved_role,
    role_addendum,
    validate_role,
    write_role_override,
)


@pytest.fixture(autouse=True)
def _roles_file(tmp_path, monkeypatch):
    """Redirect role overrides at a temp file (never touch the real workspace)."""
    monkeypatch.setenv("MAVERICK_ROLES_FILE", str(tmp_path / "roles.toml"))
    return tmp_path / "roles.toml"


class TestAddendum:
    def test_absent_by_default(self):
        assert role_addendum("orchestrator") == ""

    def test_write_then_read_round_trips(self, _roles_file):
        write_role_override("orchestrator", {"system_addendum": "Lead with risk."})
        assert role_addendum("orchestrator") == "Lead with risk."
        assert _roles_file.is_file()

    def test_multiple_roles_coexist(self):
        write_role_override("coder", {"system_addendum": "Prefer small diffs."})
        write_role_override("writer", {"system_addendum": "Use plain English."})
        assert role_addendum("coder") == "Prefer small diffs."
        assert role_addendum("writer") == "Use plain English."

    def test_unknown_role_has_no_addendum(self):
        # A domain specialist (role = pack name) never matches a known role.
        assert role_addendum("finance_ap_recon") == ""


class TestValidation:
    def test_unknown_role_rejected(self):
        assert validate_role("not_a_role", {"system_addendum": "x"})
        with pytest.raises(ValueError):
            write_role_override("not_a_role", {"system_addendum": "x"})

    def test_overlong_addendum_rejected(self):
        errors = validate_role("coder", {"system_addendum": "x" * 5000})
        assert any("too long" in e for e in errors)
        with pytest.raises(ValueError):
            write_role_override("coder", {"system_addendum": "x" * 5000})

    def test_valid_addendum_passes(self):
        assert validate_role("coder", {"system_addendum": "ok"}) == []


class TestLifecycle:
    def test_empty_addendum_clears_override(self):
        write_role_override("analyst", {"system_addendum": "temp"})
        assert role_addendum("analyst") == "temp"
        write_role_override("analyst", {"system_addendum": "   "})  # whitespace = clear
        assert role_addendum("analyst") == ""

    def test_remove_reverts(self):
        write_role_override("revisor", {"system_addendum": "double-check math"})
        assert remove_role_override("revisor") is True
        assert role_addendum("revisor") == ""
        assert remove_role_override("revisor") is False  # already gone


class TestViews:
    def test_resolved_role_unknown_is_none(self):
        assert resolved_role("nope") is None

    def test_resolved_role_reports_provenance_and_model(self):
        view = resolved_role("orchestrator")
        assert view["role"] == "orchestrator"
        assert view["is_override"] is False
        assert view["model"]  # a default model resolves
        write_role_override("orchestrator", {"system_addendum": "ACME first."})
        view = resolved_role("orchestrator")
        assert view["is_override"] is True
        assert view["system_addendum"] == "ACME first."

    def test_list_roles_covers_known_roles_and_flags_overrides(self):
        names = {r["role"] for r in list_roles()}
        assert {"orchestrator", "coder", "researcher"} <= names
        assert names == set(ROLES)
        write_role_override("coder", {"system_addendum": "small diffs"})
        flagged = {r["role"]: r["is_override"] for r in list_roles()}
        assert flagged["coder"] is True
        assert flagged["orchestrator"] is False


class TestModelEffortOverride:
    def test_override_round_trips(self):
        write_role_override("coder", {"model": "anthropic:claude-opus-4-8", "effort": "high"})
        assert override_model("coder") == "anthropic:claude-opus-4-8"
        assert override_effort("coder") == "high"

    def test_get_role_model_prefers_override(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text('[models]\ncoder = "global:sonnet"\n')
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        from maverick.config import get_role_model
        assert get_role_model("coder") == "global:sonnet"      # global config default
        write_role_override("coder", {"model": "tenant:opus"})
        assert get_role_model("coder") == "tenant:opus"        # per-tenant override wins

    def test_effort_for_role_prefers_override(self, monkeypatch):
        from maverick.effort import effort_for_role
        for v in ("MAVERICK_EFFORT", "MAVERICK_EFFORT_WRITER", "MAVERICK_EFFORT_ENABLED"):
            monkeypatch.delenv(v, raising=False)
        # Effort is off by default (no config), so writer resolves to None...
        assert effort_for_role("writer", "claude-opus-4-8") is None
        # ...and a per-tenant override both enables and sets it.
        write_role_override("writer", {"effort": "high"})
        assert effort_for_role("writer", "claude-opus-4-8") == "high"

    def test_validation(self):
        assert validate_role("coder", {"effort": "bogus"})         # unknown level
        assert validate_role("coder", {"model": "x" * 999})        # too long
        assert validate_role("coder", {"effort": "high", "model": "ok"}) == []

    def test_resolved_role_exposes_overrides(self):
        write_role_override("writer", {"model": "tenant:m", "effort": "low"})
        view = resolved_role("writer")
        assert view["model_override"] == "tenant:m"
        assert view["effort_override"] == "low"
        assert view["model"] == "tenant:m"          # effective reflects the override
        assert view["is_override"] is True

    def test_clearing_all_fields_removes_override(self):
        write_role_override("analyst", {"model": "m", "effort": "high"})
        assert override_model("analyst") == "m"
        write_role_override("analyst", {"model": "", "effort": "", "system_addendum": ""})
        assert override_model("analyst") is None
        assert resolved_role("analyst")["is_override"] is False
