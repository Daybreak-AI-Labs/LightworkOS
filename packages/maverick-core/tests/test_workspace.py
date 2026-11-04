"""Workspaces (tenants): per-business isolation of the factory's data."""

from __future__ import annotations

from pathlib import Path

from maverick.paths import reset_tenant, set_tenant
from maverick.workspace import Workspace, _sanitize_tenant


class TestWorkspacePaths:
    def test_single_tenant_uses_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
        ws = Workspace.current()
        assert ws.tenant is None
        assert ws.root == tmp_path
        assert ws.domains_dir == tmp_path / "domains"

    def test_tenant_gets_its_own_root(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.setenv("MAVERICK_TENANT", "Acme Co")
        ws = Workspace.current()
        assert ws.tenant == "Acme Co"
        assert ws.root == tmp_path / "tenants" / "Acme%20Co"
        assert ws.domains_dir == tmp_path / "tenants" / "Acme%20Co" / "domains"
        assert ws.knowledge_path == tmp_path / "tenants" / "Acme%20Co" / "knowledge.db"
        assert ws.slug == "Acme%20Co"

    def test_two_tenants_are_separate(self):
        assert Workspace("alpha").root != Workspace("beta").root


class TestTenantSanitization:
    def test_path_traversal_cannot_escape(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        ws = Workspace("../../etc")
        assert (tmp_path / "tenants") in ws.root.parents  # stays under the root
        assert ".." not in ws.root.parts  # no traversal

    def test_sanitize_examples(self):
        assert _sanitize_tenant("Acme Co.") == "Acme%20Co."
        assert _sanitize_tenant("../../etc") == "..%2F..%2Fetc"
        assert _sanitize_tenant("a/b\\c") == "a%2Fb%5Cc"
        assert _sanitize_tenant("") == ""

    def test_collision_prone_tenant_ids_get_distinct_roots(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        assert Workspace("ac/me").root != Workspace("ac_me").root
        assert Workspace("Ac Me").root != Workspace("ac_me").root
        assert Workspace("../../etc").root != Workspace("etc").root


class TestPerTenantDomainIsolation:
    def test_domains_are_walled_off_by_tenant(self, tmp_path, monkeypatch):
        # A domain saved under tenant 'alpha' must not appear for tenant 'beta'.
        from maverick.domain import DomainProfile, available_domains
        from maverick.intake import save_profile

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.delenv("MAVERICK_DOMAINS_DIR", raising=False)

        monkeypatch.setenv("MAVERICK_TENANT", "alpha")
        save_profile(DomainProfile(name="alpha_only", persona="x",
                                   allow_tools=["read_file"], max_risk="low"), approved=True)
        assert "alpha_only" in available_domains()  # visible to its own business

        monkeypatch.setenv("MAVERICK_TENANT", "beta")
        assert "alpha_only" not in available_domains()  # walled off from another

    def test_save_lands_under_the_tenant_root(self, tmp_path, monkeypatch):
        from maverick.domain import DomainProfile
        from maverick.intake import save_profile

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.delenv("MAVERICK_DOMAINS_DIR", raising=False)
        monkeypatch.setenv("MAVERICK_TENANT", "gamma")
        path = Path(save_profile(DomainProfile(name="g1", persona="x"), approved=True))
        assert (tmp_path / "tenants" / "gamma" / "domains") in path.parents

    def test_domains_follow_context_tenant_scope(self, tmp_path, monkeypatch):
        from maverick.domain import DomainProfile, available_domains
        from maverick.intake import save_profile

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
        monkeypatch.delenv("MAVERICK_DOMAINS_DIR", raising=False)

        token = set_tenant("slack:alice")
        try:
            save_profile(DomainProfile(name="alice_only", persona="x",
                                       allow_tools=["read_file"], max_risk="low"), approved=True)
            assert "alice_only" in available_domains()
        finally:
            reset_tenant(token)

        token = set_tenant("slack:bob")
        try:
            assert "alice_only" not in available_domains()
        finally:
            reset_tenant(token)


class TestPerTenantKnowledgeIsolation:
    def test_default_knowledge_path_follows_context_tenant_scope(self, tmp_path, monkeypatch):
        import sys
        import types

        from maverick.orchestrator import _build_knowledge

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
        monkeypatch.setattr(
            "maverick.config.get_knowledge", lambda: {"enable": True}, raising=False
        )

        fake_knowledge = types.ModuleType("maverick_knowledge")

        class FakeKnowledgeBase:
            def __init__(self, *, store, embedder):
                self.store = store
                self.embedder = embedder

        fake_knowledge.KnowledgeBase = FakeKnowledgeBase
        fake_knowledge.build_store = lambda cfg: cfg["path"]
        fake_knowledge.build_embedder = lambda cfg: None
        monkeypatch.setitem(sys.modules, "maverick_knowledge", fake_knowledge)

        token = set_tenant("slack:alice")
        try:
            kb = _build_knowledge()
        finally:
            reset_tenant(token)

        assert kb is not None
        assert kb.store == str(tmp_path / "tenants" / "slack%3Aalice" / "knowledge.db")
