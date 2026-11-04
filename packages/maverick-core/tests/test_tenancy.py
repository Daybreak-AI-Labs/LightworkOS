"""Multi-tenancy: tenant-aware paths + per-tenant memory.

A tenant namespaces on-disk state. With no tenant active, paths resolve to the
legacy ~/.maverick locations (single-tenant unchanged). With a tenant, the
cross-session memory store is isolated so one tenant cannot read another's.
"""
import maverick.paths as paths
import pytest
from maverick.paths import current_tenant, data_dir, reset_tenant, set_tenant

# --- tenant resolution -----------------------------------------------------

def test_no_tenant_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    assert current_tenant() is None


def test_tenant_from_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    assert current_tenant() == "acme"


def test_explicit_scope_beats_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    tok = set_tenant("globex")
    try:
        assert current_tenant() == "globex"
    finally:
        reset_tenant(tok)
    assert current_tenant() == "acme"  # restored


def test_tenant_encoding_prevents_traversal_without_collisions(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tok = set_tenant("../../etc")  # path-traversal attempt
    try:
        t = current_tenant()
        assert t == "..%2F..%2Fetc"
        assert "/" not in t  # remains a single safe path segment
        # The real invariant: the resolved data path can't escape the tenants root.
        resolved = data_dir("x").resolve()
        assert (paths.maverick_home() / "tenants").resolve() in resolved.parents
    finally:
        reset_tenant(tok)


def test_tenant_encoding_is_collision_resistant(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    assert data_dir("memory", tenant="ac/me") != data_dir("memory", tenant="ac_me")
    assert data_dir("memory", tenant="/") != data_dir("memory", tenant="default")
    # Win32 aliases and non-portable trailing-dot identities are rejected at
    # admission rather than merely percent-encoded.
    with pytest.raises(paths.InvalidTenantError):
        data_dir("memory", tenant=".")


def test_tenant_segment_nfc_normalised(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    import unicodedata
    nfc = unicodedata.normalize("NFC", "josé")   # "josé" precomposed
    nfd = unicodedata.normalize("NFD", "josé")   # "josé" decomposed
    assert nfc != nfd  # distinct byte sequences pre-normalisation
    # ...but the same on-disk namespace, so one tenant's data isn't split in two.
    assert data_dir("memory", tenant=nfc) == data_dir("memory", tenant=nfd)


def test_data_dir_refuses_case_alias_before_any_store_access(monkeypatch):
    from maverick.paths import TenantNamespaceCollision

    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    owner_path = data_dir("memory", tenant="Acme")
    with pytest.raises(TenantNamespaceCollision, match="aliases namespace owned"):
        data_dir("memory", tenant="acme")
    assert owner_path == paths.maverick_home() / "tenants" / "Acme" / "memory"


# --- data_dir --------------------------------------------------------------

def test_data_dir_no_tenant(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    p = data_dir("memory")
    assert p == paths.maverick_home() / "memory"
    assert "tenants" not in p.parts


def test_data_dir_with_tenant(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tok = set_tenant("acme")
    try:
        p = data_dir("memory")
        assert p == paths.maverick_home() / "tenants" / "acme" / "memory"
    finally:
        reset_tenant(tok)


def test_data_dir_force_shared(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tok = set_tenant("acme")
    try:
        # tenant=None forces the shared location even when a tenant is active.
        assert data_dir("audit", tenant=None) == paths.maverick_home() / "audit"
    finally:
        reset_tenant(tok)


# --- memory store honours the tenant + stays isolated ----------------------

def test_memory_root_follows_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_MEMORY_DIR", raising=False)
    from maverick.tools.memory import _memory_root

    shared = _memory_root()
    assert shared.parent == paths.data_dir("memory") / "owned"
    assert len(shared.name) == 64
    tok = set_tenant("acme")
    try:
        assert _memory_root().parent == paths.data_dir("memory") / "owned"
        assert _memory_root() != shared
    finally:
        reset_tenant(tok)


def test_explicit_memory_dir_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_MEMORY_DIR", str(tmp_path / "mem"))
    tok = set_tenant("acme")
    try:
        from maverick.tools.memory import _memory_root
        assert _memory_root().parent == tmp_path / "mem" / "owned"
        assert len(_memory_root().name) == 64
    finally:
        reset_tenant(tok)


def test_memory_isolated_across_tenants(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_MEMORY_DIR", raising=False)
    from maverick.tools.memory import _run

    tok = set_tenant("tenant-a")
    try:
        assert "wrote" in _run({"command": "create", "path": "notes.md",
                                "file_text": "a-secret"})
        assert "notes.md" in _run({"command": "view", "path": ""})
    finally:
        reset_tenant(tok)

    # A different tenant sees an empty memory -- no cross-tenant leakage.
    tok = set_tenant("tenant-b")
    try:
        assert _run({"command": "view", "path": ""}) == "(memory is empty)"
    finally:
        reset_tenant(tok)

    # Back to tenant-a: the note is still there.
    tok = set_tenant("tenant-a")
    try:
        out = _run({"command": "view", "path": "notes.md"})
        assert "a-secret" in out
    finally:
        reset_tenant(tok)


def test_memory_store_cannot_be_reopened_through_case_alias(monkeypatch, tmp_path):
    from maverick.tools.memory import _run

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_MEMORY_DIR", raising=False)
    owner = set_tenant("Acme")
    try:
        assert "wrote" in _run(
            {"command": "create", "path": "private.md", "file_text": "secret"}
        )
    finally:
        reset_tenant(owner)

    alias = set_tenant("acme")
    try:
        result = _run({"command": "view", "path": "private.md"})
        assert result == "ERROR: Current memory ownership could not be verified."
        assert "secret" not in result
    finally:
        reset_tenant(alias)


def test_memory_isolated_for_previously_colliding_tenants(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_MEMORY_DIR", raising=False)
    from maverick.tools.memory import _run

    tok = set_tenant("ac/me")
    try:
        assert "wrote" in _run({"command": "create", "path": "secrets.md",
                                "file_text": "SECRET123"})
    finally:
        reset_tenant(tok)

    tok = set_tenant("ac_me")
    try:
        assert _run({"command": "view", "path": ""}) == "(memory is empty)"
    finally:
        reset_tenant(tok)

    tok = set_tenant("ac/me")
    try:
        assert "SECRET123" in _run({"command": "view", "path": "secrets.md"})
    finally:
        reset_tenant(tok)


# --- per-user tenant scope (server wiring) ---------------------------------

def test_tenant_by_user_disabled_by_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    from maverick.paths import tenant_by_user_enabled
    assert tenant_by_user_enabled() is False


def test_tenant_by_user_via_env(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    from maverick.paths import tenant_by_user_enabled
    assert tenant_by_user_enabled() is True


def test_tenant_scope_noop_when_disabled(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.paths import tenant_scope
    with tenant_scope(channel="tg", user_id="42"):
        assert current_tenant() is None  # disabled -> no isolation


def test_tenant_scope_sets_and_restores(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.paths import tenant_scope
    assert current_tenant() is None
    with tenant_scope(channel="tg", user_id="42"):
        assert current_tenant() == "tg%3A42"  # ':' is percent-encoded
    assert current_tenant() is None  # restored after the block


def test_tenant_scope_explicit_tenant_ignores_flag(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    from maverick.paths import tenant_scope
    with tenant_scope(tenant="acme"):
        assert current_tenant() == "acme"  # explicit tenant works even when flag off


def test_server_tenant_scope_uses_authenticated_principal(monkeypatch):
    import asyncio

    import maverick.server as server_mod

    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)

    class _World:
        def __init__(self):
            self.seen_tenants = []
            self.created_goal = None

        def latest_artifacts(self, goal_id):
            return []  # the goal saved no output files

        def open_channel_questions(self, conversation_id, owner, execution_principal):
            return []  # no blocked question awaits a reply

        def get_or_create_conversation(self, channel, user_id):
            self.seen_tenants.append(current_tenant())
            self.conversation_key = (channel, user_id)
            return type("Conversation", (), {"id": 1})()

        def append_turn(self, conversation_id, role, text, *, goal_id=None):
            self.seen_tenants.append(current_tenant())
            self.turn_goal_id = goal_id
            return None

        def create_goal(
            self, title, text, *, owner="", execution_principal="",
        ):
            self.seen_tenants.append(current_tenant())
            self.created_goal = (title, text, owner, execution_principal)
            return 7

        def set_goal_status(self, *args, **kwargs):
            self.seen_tenants.append(current_tenant())
            return None

        def get_goal(self, goal_id):
            self.seen_tenants.append(current_tenant())
            return type("Goal", (), {"result": "ok", "status": "done"})()

    captured = {}

    async def _fake_dispatch(*args, **kwargs):
        captured["kwargs"] = kwargs
        captured["tenant"] = current_tenant()
        return "done"

    monkeypatch.setattr(
        "maverick.runner.run_goal_in_background_async", _fake_dispatch,
    )
    world = _World()
    # With per-user tenancy on, _handle_message routes through world_for_tenant
    # (a real per-tenant world.db); point it at the stub so we can assert the
    # routing keys off the authenticated principal, not the reply target.
    monkeypatch.setattr(server_mod, "world_for_tenant", lambda _tenant: world)
    srv = server_mod.Server(world=world, llm=object(), sandbox=object())

    class _RoomMessage:
        channel = "slack"
        user_id = "CROOM"  # reply target, not the human sender
        principal_id = "UALICE"
        text = "hello"

    assert _answer(asyncio.run(srv._handle_message(_RoomMessage()))) == "ok"
    assert world.conversation_key == ("slack", "UALICE")
    assert captured["kwargs"]["user_id"] == "slack:UALICE"
    assert captured["tenant"] == "slack%3AUALICE"
    assert world.created_goal == (
        "hello", "hello", "user:slack:UALICE", "user:slack:UALICE",
    )
    # Every world read/write (conversation, turn, goal, status and the reply's
    # result reads) happens inside the authenticated principal's tenant.
    assert len(world.seen_tenants) >= 4
    assert set(world.seen_tenants) == {"slack%3AUALICE"}
    assert world.turn_goal_id == 7
    assert current_tenant() is None


def test_server_per_user_postgres_reuses_backend_and_scopes_all_writes(monkeypatch):
    import asyncio

    import maverick.server as server_mod
    from maverick.world_model_backends import PostgresWorldModel

    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.compliance.first_turn_disclosure", lambda *a, **k: None)

    class _PostgresStub(PostgresWorldModel):
        def __init__(self):
            # Deliberately skip the real psycopg connection.
            self.seen_tenants = []
            self.created_goal = None

        def latest_artifacts(self, goal_id):
            return []  # the goal saved no output files

        def open_channel_questions(self, conversation_id, owner, execution_principal):
            return []  # no blocked question awaits a reply

        def get_or_create_conversation(self, channel, user_id):
            self.seen_tenants.append(("conversation", current_tenant()))
            return type("Conversation", (), {"id": 1})()

        def append_turn(self, conversation_id, role, text, *, goal_id=None):
            self.seen_tenants.append(("turn", current_tenant()))
            self.turn_goal_id = goal_id

        def create_goal(
            self, title, text, *, owner="", execution_principal="",
        ):
            self.seen_tenants.append(("goal", current_tenant()))
            self.created_goal = (title, text, owner, execution_principal)
            return 7

        def set_goal_status(self, *args, **kwargs):
            self.seen_tenants.append(("status", current_tenant()))

        def get_goal(self, goal_id):
            self.seen_tenants.append(("result", current_tenant()))
            return type("Goal", (), {"result": "ok", "status": "done"})()

    def _sqlite_must_not_open(_tenant):
        raise AssertionError("configured Postgres path opened a tenant SQLite world")

    monkeypatch.setattr(server_mod, "world_for_tenant", _sqlite_must_not_open)
    dispatch_tenants = []

    async def _fake_dispatch(*args, **kwargs):
        dispatch_tenants.append(current_tenant())
        return "done"

    monkeypatch.setattr(
        "maverick.runner.run_goal_in_background_async", _fake_dispatch,
    )
    world = _PostgresStub()
    srv = server_mod.Server(world=world, llm=object(), sandbox=object())

    class _Message:
        channel = "slack"
        user_id = "UALICE"
        principal_id = "UALICE"
        text = "hello"

    assert _answer(asyncio.run(srv._handle_message(_Message()))) == "ok"
    expected_tenant = "slack%3AUALICE"
    assert world.seen_tenants == [
        ("conversation", expected_tenant),
        ("goal", expected_tenant),
        ("turn", expected_tenant),
        ("result", expected_tenant),
        # The reply re-reads the finished goal to attach its saved output.
        ("result", expected_tenant),
    ]
    assert world.turn_goal_id == 7
    assert world.created_goal == (
        "hello", "hello", "user:slack:UALICE", "user:slack:UALICE",
    )
    assert dispatch_tenants == [expected_tenant]
    assert current_tenant() is None


def test_lazy_default_paths_follow_active_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CHROMA_PATH", raising=False)
    monkeypatch.delenv("MAVERICK_QDRANT_PATH", raising=False)

    from maverick.paths import tenant_scope
    from maverick.vector_store import chroma_store, qdrant_store

    with tenant_scope(tenant="tenant-a"):
        # Simulate a lazy import/use while tenant-a is active.
        assert chroma_store._default_path() == tmp_path / "tenants" / "tenant-a" / "vector_store"
        assert qdrant_store._default_path() == tmp_path / "tenants" / "tenant-a" / "qdrant"

    with tenant_scope(tenant="tenant-b"):
        assert chroma_store._default_path() == tmp_path / "tenants" / "tenant-b" / "vector_store"
        assert qdrant_store._default_path() == tmp_path / "tenants" / "tenant-b" / "qdrant"


def test_lazy_skill_distillation_store_follows_active_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))

    from maverick.paths import tenant_scope
    from maverick.skill import distillation, distillation_local

    skill = {
        "name": "tenant-skill",
        "triggers": ["tenant skill"],
        "tools_needed": [],
        "summary": "tenant skill",
        "n_examples": 1,
    }

    with tenant_scope(tenant="tenant-a"):
        path_a = distillation_local.save_skill(skill)
        assert path_a.parent == tmp_path / "tenants" / "tenant-a" / "learned-skills"
        assert distillation.signatures_from_store()

    with tenant_scope(tenant="tenant-b"):
        path_b = distillation_local.save_skill(skill)
        assert path_b.parent == tmp_path / "tenants" / "tenant-b" / "learned-skills"
        assert distillation.signatures_from_store()
        assert not (tmp_path / "tenants" / "tenant-b" / "learned-skills" / "missing.md").exists()


def _answer(reply):
    """The goal's answer, without the agent-written label channels append."""
    answer, label = reply.rsplit("\n\n", 1)
    assert label.startswith("-- Written by an agent in Lightwork.")
    return answer
