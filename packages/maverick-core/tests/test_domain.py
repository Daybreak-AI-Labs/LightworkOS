"""Domain packs: schema, loader, and capability derivation (agent factory)."""
from __future__ import annotations

import json
import os

import pytest
from maverick.capability import Capability
from maverick.domain import (
    DomainProfile,
    WorkflowStep,
    available_domains,
    builtin_dir,
    domain_capability,
    lint_profile,
    load_domain,
    load_domains,
    overlay_profile,
    overridden_fields,
    rejected_workspace_domains,
    render_workflow_prompt,
)


def _clean_builtin():
    """A built-in pack with no lint *errors*, to overlay in tests (built-ins
    are shipped lint-clean, but pick dynamically so the test is robust)."""
    for name, prof in sorted(load_domains(builtin_dir()).items()):
        if not lint_profile(prof)[0]:
            return name, prof
    raise AssertionError("no lint-error-clean built-in pack found")


class TestDomainProfile:
    def test_compartment_defaults_to_name(self):
        assert DomainProfile(name="finance").compartment == "finance"

    def test_explicit_compartment_kept(self):
        p = DomainProfile(name="finance-ops", compartment="finance")
        assert p.compartment == "finance"

    def test_capability_envelope_from_profile(self):
        p = DomainProfile(
            name="finance", allow_tools=["read_file"],
            deny_tools=["create_order_instruction"], max_risk="medium",
        )
        cap = p.capability("agent:finance-1")
        assert cap.principal == "agent:finance-1"
        assert cap.permits("read_file") is True
        assert cap.permits("create_order_instruction") is False  # deny wins
        assert cap.permits("some_unlisted_tool") is False         # whitelist


class TestLoader:
    def test_load_domain_from_toml(self, tmp_path):
        f = tmp_path / "legal.toml"
        f.write_text(
            'name = "legal"\n'
            'persona = "You are a legal specialist."\n'
            'allow_tools = ["read_file", "web_search"]\n'
            'knowledge_sources = ["legal"]\n'
        )
        prof = load_domain(f)
        assert prof.name == "legal"
        assert "legal specialist" in prof.persona
        assert prof.allow_tools == ["read_file", "web_search"]
        assert prof.knowledge_sources == ["legal"]

    def test_unknown_keys_are_ignored(self, tmp_path):
        f = tmp_path / "x.toml"
        f.write_text('name = "x"\nfuture_key = "ignored"\n')
        assert load_domain(f).name == "x"  # must not raise

    def test_load_domains_skips_malformed(self, tmp_path):
        (tmp_path / "ok.toml").write_text('name = "ok"\n')
        (tmp_path / "bad.toml").write_text("not = valid = toml [[[")
        domains = load_domains(tmp_path)
        assert "ok" in domains
        assert "bad" not in domains

    def test_missing_dir_returns_empty(self, tmp_path):
        assert load_domains(tmp_path / "nope") == {}

    def test_safe_content_identity_remains_authoritative(self, tmp_path):
        pack = tmp_path / "expected.toml"
        pack.write_text('name = "other"\n', encoding="utf-8")

        assert load_domain(pack).name == "other"
        assert list(load_domains(tmp_path)) == ["other"]

    def test_oversized_pack_is_rejected(self, tmp_path):
        pack = tmp_path / "large.toml"
        pack.write_text(
            'name = "large"\npersona = "' + ("x" * (257 * 1024)) + '"\n',
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="file-size limit"):
            load_domain(pack)
        assert load_domains(tmp_path) == {}

    def test_symlinked_pack_cannot_escape_catalog(self, tmp_path):
        outside = tmp_path.parent / "outside-domain.toml"
        outside.write_text('name = "escaped"\n', encoding="utf-8")
        link = tmp_path / "escaped.toml"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError):
            pytest.skip("symlink creation is not available")

        with pytest.raises(ValueError, match="private regular file"):
            load_domain(link)
        assert load_domains(tmp_path) == {}

    def test_hardlinked_pack_cannot_cross_catalog_boundary(self, tmp_path):
        outside = tmp_path.parent / "linked.toml"
        outside.write_text('name = "linked"\n', encoding="utf-8")
        link = tmp_path / "linked.toml"
        try:
            os.link(outside, link)
        except (NotImplementedError, OSError):
            pytest.skip("hard-link creation is not available")

        with pytest.raises(ValueError, match="private regular file"):
            load_domain(link)
        assert load_domains(tmp_path) == {}


class TestBuiltinPacks:
    def test_finance_reference_pack_ships(self):
        domains = available_domains()
        assert "finance" in domains
        fin = domains["finance"]
        assert fin.compartment == "finance"
        assert "Interactive_Brokers_IBKR" in fin.mcp_servers
        # The derived capability denies order placement (deny wins).
        assert fin.capability("agent:f1").permits("create_order_instruction") is False

    def test_all_four_reference_packs_ship(self):
        domains = available_domains()
        for name in ("finance", "legal", "privacy_compliance", "generic"):
            assert name in domains, f"missing built-in pack: {name}"
            assert domains[name].persona  # each carries specialist instructions

    def test_builtin_knowledge_domains_permit_knowledge_search(self):
        domains = available_domains()
        for name in ("finance", "legal", "privacy_compliance", "generic"):
            prof = domains[name]
            assert prof.knowledge_sources, f"{name} should bind a knowledge collection"
            assert prof.capability(f"agent:{name}-0").permits("knowledge_search") is True

    def test_healthcare_packs_deny_web_search(self):
        domains = available_domains()
        healthcare = {
            name: prof for name, prof in domains.items()
            if name.startswith("hc_")
        }
        assert healthcare
        for name, prof in healthcare.items():
            assert "web_search" not in prof.allow_tools, name
            assert "web_search" in prof.deny_tools, name
            for step in prof.workflow:
                assert "web_search" not in step.tools, f"{name}: {step.name}"


class TestDomainCapability:
    def test_mints_envelope_without_parent(self):
        p = DomainProfile(name="finance", allow_tools=["read_file"],
                          deny_tools=["shell"], max_risk="medium")
        cap = domain_capability(p, None, "agent:finance-0")
        assert cap.permits("read_file") is True
        assert cap.permits("shell") is False     # deny wins
        assert cap.permits("browser") is False    # whitelist excludes it

    def test_attenuates_parent_never_broadens(self):
        parent = Capability(principal="user:local",
                            allow_tools=frozenset({"read_file", "web_search"}))
        # Profile asks for a tool the parent never granted.
        p = DomainProfile(name="finance", allow_tools=["read_file", "shell"])
        cap = domain_capability(p, parent, "agent:finance-0")
        assert cap.permits("read_file") is True
        assert cap.permits("shell") is False        # can't gain what the parent lacked
        assert cap.permits("web_search") is False    # narrowed to the profile's set

    def test_empty_profile_fields_inherit_parent_scope(self):
        parent = Capability(principal="user:local",
                            allow_tools=frozenset({"read_file"}))
        p = DomainProfile(name="x")  # no scopes specified
        cap = domain_capability(p, parent, "agent:x-0")
        # Empty allow inherits the parent's whitelist rather than emptying it
        # (an empty allow-set means "all", which would broaden).
        assert cap.permits("read_file") is True
        assert cap.permits("shell") is False


class TestWorkflowSchema:
    def test_loads_workflow_steps_from_toml(self, tmp_path):
        f = tmp_path / "p.toml"
        f.write_text(
            'name = "p"\n'
            'allow_tools = ["read_file"]\n'
            '[[workflow]]\n'
            'name = "gather"\n'
            'instruction = "Collect the source documents."\n'
            'tools = ["read_file"]\n'
            '[[workflow]]\n'
            'name = "draft"\n'
            'instruction = "Write the summary."\n'
            'gate = "review"\n'
        )
        prof = load_domain(f)
        assert [s.name for s in prof.workflow] == ["gather", "draft"]
        assert prof.workflow[0].tools == ["read_file"]
        assert prof.workflow[1].gate == "review"

    def test_malformed_workflow_steps_dropped_not_raised(self, tmp_path):
        f = tmp_path / "p.toml"
        f.write_text(
            'name = "p"\n'
            '[[workflow]]\n'
            'instruction = "nameless step is skipped"\n'
            '[[workflow]]\n'
            'name = "kept"\n'
        )
        prof = load_domain(f)  # must not raise
        assert [s.name for s in prof.workflow] == ["kept"]

    def test_render_empty_workflow_is_blank(self):
        assert render_workflow_prompt([]) == ""

    def test_render_workflow_lists_ordered_steps(self):
        steps = [
            WorkflowStep(name="gather", instruction="Collect docs."),
            WorkflowStep(name="review", instruction="Check it.", gate="approval"),
        ]
        out = render_workflow_prompt(steps)
        assert "1. gather: Collect docs." in out
        assert "2. review: Check it." in out
        assert "[gate: approval]" in out


class TestOverlay:
    def test_overlay_patches_only_present_fields(self):
        base = DomainProfile(
            name="finance", persona="Base persona long enough to be real.",
            allow_tools=["read_file", "sql_query"], max_risk="low",
            knowledge_sources=["finance"],
        )
        merged = overlay_profile(base, {"description": "Tailored for ACME."})
        assert merged.description == "Tailored for ACME."     # patched
        assert merged.allow_tools == ["read_file", "sql_query"]  # inherited
        assert merged.max_risk == "low"                          # inherited
        assert merged.name == "finance"                          # identity kept

    def test_overlay_coerces_workflow_patch(self):
        base = DomainProfile(name="x", allow_tools=["read_file"])
        merged = overlay_profile(base, {"workflow": [{"name": "step1"}]})
        assert [s.name for s in merged.workflow] == ["step1"]

    def test_overlay_inherits_base_autonomy(self):
        # An overlay that doesn't set [autonomy] must inherit the base pack's
        # autonomy, not silently drop it to the default (None).
        from maverick.agent_autonomy import AutonomyProfile
        base = DomainProfile(name="x", allow_tools=["read_file"],
                             autonomy=AutonomyProfile.from_toml({"default": "auto"}))
        merged = overlay_profile(base, {"description": "d"})
        assert merged.autonomy == base.autonomy
        assert merged.autonomy is not None

    def test_overlay_coerces_autonomy_patch(self):
        # A patched [autonomy] table must be coerced to an AutonomyProfile the
        # same way the load path does -- not stored as a raw dict.
        from maverick.agent_autonomy import AutonomyProfile, parse_level
        base = DomainProfile(name="x", allow_tools=["read_file"])
        merged = overlay_profile(base, {"autonomy": {"default": "auto"}})
        assert isinstance(merged.autonomy, AutonomyProfile)
        assert merged.autonomy.default == parse_level("auto")

    def test_overridden_fields_reports_patched_keys(self):
        assert overridden_fields(
            {"name": "x", "persona": "p", "allow_tools": ["read_file"]}
        ) == {"persona", "allow_tools"}  # name is identity, not an override


class TestAvailableDomainsOverlay:
    @pytest.mark.parametrize("body", [
        'name = "unsafe"\npersona = "A specialist."\n',
        'name = "unsafe"\nallow_tools = ["read_file"]\n',
        'name = "unsafe"\nallow_tools = []\nmax_risk = "low"\n',
        'name = "unsafe"\nallow_tools = ["read_file"]\nmax_risk = "unlimited"\n',
    ])
    def test_incomplete_workspace_pack_is_not_activated(self, tmp_path, monkeypatch, body):
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / "unsafe.toml").write_text(body, encoding="utf-8")

        assert "unsafe" not in available_domains()
        assert rejected_workspace_domains()["unsafe"]

    def test_incomplete_override_cannot_replace_builtin(self, tmp_path, monkeypatch):
        name, base = _clean_builtin()
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / f"{name}.toml").write_text(
            f'name = "{name}"\nallow_tools = []\n', encoding="utf-8",
        )

        assert name not in available_domains()
        assert rejected_workspace_domains()[name]
        (tmp_path / f"{name}.toml").unlink()
        assert available_domains()[name] == base

    def test_workspace_override_cannot_expand_builtin_tools(self, tmp_path, monkeypatch):
        name = "aero_avionics"
        base = load_domains(builtin_dir())[name]
        assert not lint_profile(base)[0]
        assert "web_search" not in base.allow_tools
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / f"{name}.toml").write_text(
            f'name = "{name}"\n'
            f'allow_tools = {json.dumps([*base.allow_tools, "web_search"])}\n',
            encoding="utf-8",
        )

        assert name not in available_domains()
        assert any("allow_tools cannot add" in e for e in rejected_workspace_domains()[name])

    def test_malformed_deny_list_cannot_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / "unsafe.toml").write_text(
            'name = "unsafe"\nallow_tools = ["shell"]\n'
            'deny_tools = "shell"\nmax_risk = "high"\n', encoding="utf-8",
        )

        assert "unsafe" not in available_domains()
        assert any("deny_tools" in e for e in rejected_workspace_domains()["unsafe"])

    def test_unparseable_builtin_override_blocks_until_removed(self, tmp_path, monkeypatch):
        name, base = _clean_builtin()
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        path = tmp_path / f"{name}.toml"
        path.write_text('allow_tools = [', encoding="utf-8")

        assert name not in available_domains()
        assert rejected_workspace_domains()[name]
        path.unlink()
        assert available_domains()[name] == base

    def test_domains_lint_reports_rejected_workspace_pack(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from maverick.cli import main

        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / "unsafe.toml").write_text('name = "unsafe"\n', encoding="utf-8")

        result = CliRunner().invoke(main, ["domains-lint", "--ci"])

        assert result.exit_code != 0
        assert "ERROR  unsafe: allow_tools is empty" in result.output
        assert "ERROR  unsafe: max_risk is unset" in result.output

    def test_domains_lint_reports_unparseable_builtin_pack(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from maverick import domain
        from maverick.cli import main

        (tmp_path / "broken.toml").write_text('allow_tools = [', encoding="utf-8")
        monkeypatch.setattr(domain, "builtin_dir", lambda: tmp_path)
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "workspace"))

        result = CliRunner().invoke(main, ["domains-lint", "--ci"])

        assert result.exit_code != 0
        assert "ERROR  broken: pack does not load" in result.output

    def test_same_name_override_inherits_base(self, tmp_path, monkeypatch):
        name, base = _clean_builtin()
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / f"{name}.toml").write_text(
            f'name = "{name}"\ndescription = "Customized for this client."\n'
        )
        merged = available_domains()[name]
        assert merged.description == "Customized for this client."  # patched
        assert merged.allow_tools == base.allow_tools                # inherited
        assert merged.persona == base.persona                        # inherited

    def test_extends_forks_a_new_named_pack(self, tmp_path, monkeypatch):
        name, base = _clean_builtin()
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / "client_fork.toml").write_text(
            f'name = "client_fork"\nextends = "{name}"\n'
            'persona = "Forked persona, long enough to be a real instruction."\n'
        )
        domains = available_domains()
        assert name in domains                       # base still present
        fork = domains["client_fork"]
        assert fork.allow_tools == base.allow_tools   # inherited from base
        assert "Forked persona" in fork.persona       # patched

    def test_new_standalone_pack_added_as_is(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / "brand_new.toml").write_text(
            'name = "brand_new"\nallow_tools = ["read_file"]\nmax_risk = "low"\n'
        )
        assert "brand_new" in available_domains()


class TestLintEffort:
    def _pack(self, effort):
        return DomainProfile(
            name="x", persona="x" * 250, allow_tools=["read_file"],
            deny_tools=["shell", "write_file"], max_risk="low",
            knowledge_sources=["x"], description="d", effort=effort,
        )

    def test_unset_effort_is_clean(self):
        errors, _ = lint_profile(self._pack(None))
        assert not any("effort" in e for e in errors)

    def test_valid_effort_tier_is_clean(self):
        for tier in ("low", "medium", "high", "xhigh", "max"):
            errors, _ = lint_profile(self._pack(tier))
            assert not any("effort" in e for e in errors), tier

    def test_unknown_effort_tier_is_error(self):
        errors, _ = lint_profile(self._pack("turbo"))
        assert any("effort" in e and "turbo" in e for e in errors)


class TestLintWorkflow:
    def _ok_base(self, **kw):
        return DomainProfile(
            name="x", persona="x" * 250, allow_tools=["read_file"],
            deny_tools=["shell"], max_risk="low", knowledge_sources=["x"],
            description="d", **kw,
        )

    def test_duplicate_step_name_is_error(self):
        p = self._ok_base(workflow=[WorkflowStep("a"), WorkflowStep("a")])
        errors, _ = lint_profile(p)
        assert any("duplicate workflow step" in e for e in errors)

    def test_nameless_step_is_error(self):
        p = self._ok_base(workflow=[WorkflowStep(name="")])
        errors, _ = lint_profile(p)
        assert any("no name" in e for e in errors)

    def test_unknown_gate_warns(self):
        p = self._ok_base(workflow=[WorkflowStep("a", gate="bogus")])
        _, warnings = lint_profile(p)
        assert any("unknown gate" in w for w in warnings)

    def test_step_tool_outside_allowlist_warns(self):
        p = self._ok_base(workflow=[WorkflowStep("a", tools=["shell"])])
        _, warnings = lint_profile(p)
        assert any("not in allow_tools" in w for w in warnings)


class TestLintReadOnlyDenyFloor:
    """A read-only pack must explicitly deny the state mutators its allowlist
    already excludes, so a later allowlist change can't silently grant them."""

    def _pack(self, allow, deny):
        return DomainProfile(
            name="x", persona="x" * 250, allow_tools=allow, deny_tools=deny,
            max_risk="low", knowledge_sources=["x"], description="d",
        )

    def test_readonly_missing_write_file_deny_warns(self):
        p = self._pack(["read_file"], ["shell"])
        _, warnings = lint_profile(p)
        assert any("write_file" in w and "defense-in-depth" in w for w in warnings)

    def test_readonly_missing_shell_deny_warns(self):
        p = self._pack(["read_file"], ["write_file"])
        _, warnings = lint_profile(p)
        assert any("shell" in w and "defense-in-depth" in w for w in warnings)

    def test_readonly_denying_floor_has_no_floor_warning(self):
        p = self._pack(["read_file"], ["shell", "write_file"])
        _, warnings = lint_profile(p)
        assert not any("defense-in-depth" in w for w in warnings)

    def test_builder_pack_is_exempt_from_floor(self):
        # A coding agent legitimately allows shell; the floor rule must not fire.
        p = self._pack(["read_file", "shell"], ["self_edit"])
        _, warnings = lint_profile(p)
        assert not any("defense-in-depth" in w for w in warnings)


class TestBuiltinCatalogCache:
    """The built-in catalog parse (2,000+ packs) is memoised so it is paid once
    per process, not on every available_domains() call (e.g. each /agents and
    /workflows render). Tenant overrides must still apply live."""

    def test_builtin_catalog_is_memoised(self):
        from maverick import domain as d
        first = d.builtin_domains()
        second = d.builtin_domains()
        # Same cached dict object: not re-parsed from disk on the second call.
        assert first is second
        info = d._load_builtin_domains.cache_info()
        before = info.hits
        d.builtin_domains()
        assert d._load_builtin_domains.cache_info().hits == before + 1

    def test_available_domains_matches_uncached_builtin_load(self):
        # Caching must not change *what* the catalog contains.
        fresh = load_domains(builtin_dir())
        assert set(fresh) <= set(available_domains())

    def test_overrides_apply_live_despite_builtin_cache(self, tmp_path, monkeypatch):
        # An override written after the builtin cache is warm must still show up:
        # only the built-in bases are cached, never the tenant overlay.
        available_domains()  # warm the builtin cache
        name = sorted(load_domains(builtin_dir()))[0]
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
        (tmp_path / f"{name}.toml").write_text(
            f'name = "{name}"\ndescription = "overridden-in-test"\n'
        )
        assert available_domains()[name].description == "overridden-in-test"
