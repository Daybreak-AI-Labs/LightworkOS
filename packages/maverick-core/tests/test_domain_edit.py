"""Per-client pack customization: serialize/validate/persist overrides + the
merged provenance view the dashboard editor renders."""
from __future__ import annotations

import os

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

import pytest
from maverick.domain import (
    DomainProfile,
    WorkflowStep,
    available_domains,
    builtin_dir,
    lint_profile,
    load_domains,
)
from maverick.domain_edit import (
    list_agents,
    overlay_toml,
    read_override,
    remove_override,
    resolved_view,
    validate_override,
    workflow_readiness,
    write_override,
)


def test_workflow_readiness_names_missing_actions_without_claiming_live_service():
    profile = DomainProfile(
        name="example", allow_tools=["read_file", "web_search", "ledger_read"],
        workflow=[WorkflowStep(name="research", tools=["web_search"])],
    )
    blocked = workflow_readiness(profile, frozenset({"read_file"}))
    assert blocked["state"] == "needs_setup"
    assert blocked["missing_tools"] == ["web_search"]
    assert blocked["fix_url"] == "/settings/all?id=capabilities.web_search"
    assert blocked["missing_optional_tools"] == ["ledger_read"]

    can_start = workflow_readiness(profile, frozenset({"read_file", "web_search"}))
    assert can_start["state"] == "action_ready"
    assert can_start["missing_optional_tools"] == ["ledger_read"]
    assert workflow_readiness(profile, None)["state"] == "unknown"


def test_workflow_readiness_does_not_call_a_turned_off_department_ready():
    profile = DomainProfile(name="gtm_example", allow_tools=["read_file"])
    blocked = workflow_readiness(
        profile, frozenset({"read_file"}), disabled_suites=frozenset({"sales_gtm"}),
    )
    assert blocked["state"] == "needs_setup"
    assert blocked["label"] == "Department turned off"
    assert "suites.%2A" in blocked["fix_url"]


def _clean_builtin():
    for name, prof in sorted(load_domains(builtin_dir()).items()):
        if not lint_profile(prof)[0]:
            return name, prof
    raise AssertionError("no lint-error-clean built-in pack found")


@pytest.fixture
def tenant_dir(tmp_path, monkeypatch):
    """Point the workspace domains dir (where overrides live) at a temp dir."""
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    return tmp_path


class TestOverlayToml:
    def test_autonomy_policy_round_trips_before_workflow_tables(self):
        loaded = tomllib.loads(overlay_toml({
            "name": "p",
            "autonomy": {"default": "request", "low": "auto", "medium": None,
                         "high": "suggest", "onboarding": False},
            "workflow": [{"name": "review", "tools": ["read_file"]}],
        }))
        assert loaded["autonomy"] == {
            "default": "request", "low": "auto", "high": "suggest",
            "onboarding": False,
        }
        assert loaded["workflow"][0]["name"] == "review"

    def test_round_trips_through_loader(self):
        patch = {
            "name": "p",
            "persona": "Multi-line\npersona with \"quotes\".",
            "allow_tools": ["read_file", "sql_query"],
            "models": {"coder": "anthropic:claude-sonnet-4-6"},
            "workflow": [
                {"name": "gather", "instruction": "Collect.", "tools": ["read_file"]},
                {"name": "draft", "gate": "review"},
            ],
        }
        loaded = tomllib.loads(overlay_toml(patch))
        assert loaded["name"] == "p"
        assert loaded["persona"] == 'Multi-line\npersona with "quotes".'
        assert loaded["allow_tools"] == ["read_file", "sql_query"]
        assert loaded["models"] == {"coder": "anthropic:claude-sonnet-4-6"}
        assert [s["name"] for s in loaded["workflow"]] == ["gather", "draft"]
        assert loaded["workflow"][1]["gate"] == "review"

    def test_only_present_keys_written(self):
        loaded = tomllib.loads(overlay_toml({"name": "p", "description": "d"}))
        assert set(loaded) == {"name", "description"}

    def test_nameless_workflow_step_skipped(self):
        loaded = tomllib.loads(overlay_toml({"name": "p", "workflow": [{"instruction": "x"}]}))
        assert "workflow" not in loaded

    def test_output_contract_round_trips_through_loader(self):
        patch = {"name": "p", "output": {
            "shape": "forecast", "deliverable": "13-week cash forecast",
            "consumers": ["fpa_analyst", "treasurer"], "cadence": "weekly",
            "gate": "review"}}
        loaded = tomllib.loads(overlay_toml(patch))
        assert loaded["output"]["shape"] == "forecast"
        assert loaded["output"]["deliverable"] == "13-week cash forecast"
        assert loaded["output"]["consumers"] == ["fpa_analyst", "treasurer"]
        assert loaded["output"]["gate"] == "review"


class TestWriteOverride:
    def test_partial_override_inherits_base(self, tenant_dir):
        name, base = _clean_builtin()
        write_override(name, {"description": "Client ACME tuning."})
        merged = available_domains()[name]
        assert merged.description == "Client ACME tuning."   # patched
        assert merged.allow_tools == base.allow_tools         # inherited
        assert (tenant_dir / f"{name}.toml").is_file()

    def test_rejects_override_that_fails_lint(self, tenant_dir):
        # A brand-new standalone pack with no allow_tools / no max_risk: the
        # merged result has lint errors, so the write must be refused.
        with pytest.raises(ValueError):
            write_override("nope", {"persona": "x" * 250})

    def test_workflow_edit_persists_and_drives_view(self, tenant_dir):
        name, _ = _clean_builtin()
        write_override(name, {"workflow": [
            {"name": "intake", "instruction": "Read the request."},
            {"name": "answer", "instruction": "Ground in docs and cite."},
        ]})
        view = resolved_view(name)
        assert [s["name"] for s in view["workflow"]] == ["intake", "answer"]
        assert "workflow" in view["overridden"]

    @pytest.mark.parametrize("name", ["../escaped", r"..\escaped", "a/b", r"a\b", "."])
    def test_path_like_names_cannot_escape_override_directory(self, tenant_dir, name):
        escaped = tenant_dir.parent / "escaped.toml"
        escaped.write_text("sentinel", encoding="utf-8")

        with pytest.raises(ValueError, match="agent name"):
            write_override(name, {"description": "overwrite"})
        with pytest.raises(ValueError, match="agent name"):
            remove_override(name)

        assert escaped.read_text(encoding="utf-8") == "sentinel"

    def test_override_is_size_bounded(self, tenant_dir):
        name, _ = _clean_builtin()
        with pytest.raises(ValueError, match="too large"):
            write_override(name, {"description": "x" * (300 * 1024)})
        assert not (tenant_dir / f"{name}.toml").exists()

    def test_argument_name_is_authoritative_over_payload_name(self, tenant_dir):
        name, _ = _clean_builtin()
        write_override(name, {"name": "different_identity", "description": "tuned"})
        raw = tomllib.loads((tenant_dir / f"{name}.toml").read_text(encoding="utf-8"))
        assert raw["name"] == name

    def test_atomic_write_replaces_symlink_without_touching_target(self, tenant_dir):
        name, _ = _clean_builtin()
        target = tenant_dir.parent / "target.toml"
        original = 'name = "target"\ndescription = "sentinel"\n'
        target.write_text(original, encoding="utf-8")
        link = tenant_dir / f"{name}.toml"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            pytest.skip("symlink creation is not available")

        write_override(name, {"description": "safe replacement"})

        assert target.read_text(encoding="utf-8") == original
        assert not link.is_symlink()
        assert "safe replacement" in link.read_text(encoding="utf-8")
        if os.name != "nt":
            assert link.stat().st_mode & 0o777 == 0o600


class TestResolvedView:
    def test_builtin_has_no_override(self, tenant_dir):
        name, _ = _clean_builtin()
        view = resolved_view(name)
        assert view["is_override"] is False
        assert view["overridden"] == []

    def test_override_marks_provenance(self, tenant_dir):
        name, _ = _clean_builtin()
        write_override(name, {"persona": "x" * 250})
        view = resolved_view(name)
        assert view["is_override"] is True
        assert view["overridden"] == ["persona"]

    def test_unknown_pack_returns_none(self, tenant_dir):
        assert resolved_view("does_not_exist_anywhere") is None

    def test_view_exposes_output_contract(self, tenant_dir):
        # The merged view carries the deliverable so the editor/API can render it.
        view = resolved_view("finance_cash13w")
        assert view["output"]["shape"] == "forecast"
        assert view["output"]["deliverable"] == "13-week cash forecast"
        assert "fpa_analyst" in view["output"]["consumers"]


class TestValidateAndList:
    def test_validate_surfaces_errors_without_writing(self, tenant_dir):
        errors, _ = validate_override("nope", {"persona": "x" * 250})
        assert errors                               # empty allow_tools etc.
        assert read_override("nope") == {}          # nothing was written

    def test_inherited_path_and_host_scopes_cannot_be_removed(self, tenant_dir):
        from maverick.domain import rejected_workspace_domains

        write_override("a_parent", {
            "allow_tools": ["read_file"], "max_risk": "low",
            "allow_paths": ["C:/approved/*"],
            "allow_hosts": ["approved.example"],
        })
        patch = {"extends": "a_parent", "allow_paths": [], "allow_hosts": []}
        errors, _ = validate_override("z_child", patch)
        assert any("allow_paths cannot broaden" in e for e in errors)
        assert any("allow_hosts cannot broaden" in e for e in errors)

        (tenant_dir / "z_child.toml").write_text(
            'name = "z_child"\nextends = "a_parent"\n'
            'allow_paths = []\nallow_hosts = []\n', encoding="utf-8",
        )
        assert "z_child" not in available_domains()
        assert rejected_workspace_domains()["z_child"]

    def test_list_agents_flags_overrides(self, tenant_dir):
        name, _ = _clean_builtin()
        before = {a["name"]: a for a in list_agents()}
        assert before[name]["is_override"] is False
        write_override(name, {"description": "tuned"})
        after = {a["name"]: a for a in list_agents()}
        assert after[name]["is_override"] is True

    def test_remove_override_reverts_to_builtin(self, tenant_dir):
        name, base = _clean_builtin()
        write_override(name, {"description": "temporary tuning"})
        assert resolved_view(name)["is_override"] is True
        assert remove_override(name) is True
        assert resolved_view(name)["is_override"] is False
        assert available_domains()[name].description == base.description

def test_override_compare_and_swap_keeps_newer_agent(tenant_dir):
    from maverick.domain_edit import OverrideConflict
    name, _ = _clean_builtin()
    generation = resolved_view(name)["generation"]
    saved = write_override(name, {"description": "first editor"}, expected_generation=generation, return_view=True)
    assert saved["description"] == "first editor" and saved["generation"] != generation
    with pytest.raises(OverrideConflict):
        write_override(name, {"description": "stale recovery"}, expected_generation=generation)
    assert resolved_view(name)["description"] == "first editor"


def test_new_override_cannot_replace_existing_agent(tenant_dir):
    from maverick.domain_edit import OverrideConflict
    name, _ = _clean_builtin()
    with pytest.raises(OverrideConflict):
        write_override(name, {"description": "unreviewed replacement"}, expected_generation="new")
    assert not (tenant_dir / (name + ".toml")).exists()


def test_concurrent_agent_edits_compare_inside_write_lock(tenant_dir):
    from concurrent.futures import ThreadPoolExecutor

    from maverick.domain_edit import OverrideConflict
    name, _ = _clean_builtin()
    generation = resolved_view(name)["generation"]
    def attempt(description):
        try:
            return write_override(name, {"description": description}, expected_generation=generation, return_view=True)
        except OverrideConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["first editor", "second editor"]))
    assert sum(result is not None for result in results) == 1
    winner = next(result for result in results if result is not None)
    assert resolved_view(name)["generation"] == winner["generation"]


def test_a_name_without_a_builtin_pack_resolves_without_parsing_the_catalogue(monkeypatch):
    """A new specialist has no built-in file. Its base lookup must answer from the
    file layout, not parse all ~2,000 built-in packs; every guard of an answer
    check repeats that lookup, so the full parse made a 25-answer check take minutes."""
    from maverick import domain_edit

    parsed = []
    real_load_domains = domain_edit.load_domains
    monkeypatch.setattr(domain_edit, "load_domains", lambda *args, **kwargs: parsed.append(args) or real_load_domains(*args, **kwargs))
    for _ in range(3):
        assert domain_edit._fresh_builtin_base("acme_po_helper") is None
    assert parsed == []
    name, base = _clean_builtin()
    assert domain_edit._fresh_builtin_base(name).description == base.description
    assert parsed == []
