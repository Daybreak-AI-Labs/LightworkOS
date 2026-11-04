"""Agent Control Plane: one roster, verbs that land in real enforcement, and
outcomes that report only what was confirmed."""
from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from maverick import agent_control_plane as acp


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, killswitch, revocation
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.setenv("MAVERICK_CONTROL_PLANE", "1")
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.reset_config_cache()
    revocation.reset_shared()
    # No world by default: the native roster comes only from revocations.
    monkeypatch.setattr("maverick.world_model.open_world",
                        lambda *a, **k: SimpleNamespace(list_goals=lambda **kw: []))
    yield
    try:
        killswitch.clear()
    except Exception:
        pass
    config.reset_config_cache()
    revocation.reset_shared()


def _capture(monkeypatch):
    seen: list[tuple[str, dict]] = []

    def _record(kind, **kw):
        seen.append((str(kind), kw))
        return True
    monkeypatch.setattr("maverick.audit.record", _record)
    monkeypatch.setattr("maverick.audit.record_global", _record)
    return seen


def _world(*owners):
    goals = [SimpleNamespace(owner=o) for o in owners]
    return SimpleNamespace(list_goals=lambda **kw: goals if kw.get("status") == "active" else [])


def _enroll(agent_id="vega", **fields):
    from maverick.agent_trust import put_agent
    entry = {"id": agent_id, "direction": "both", "max_risk": "medium",
             "max_dollars": 5.0, "deny_tools": ["shell"]}
    entry.update(fields)
    return put_agent(entry)


def _gateway_enroll(agent_id="vega", *, contained=False):
    from maverick import external_agents as xa
    with xa._sidecar_locked():
        sidecar = xa._load_sidecar()
        sidecar[agent_id] = {"contained": bool(contained), "denials": []}
        xa._save_sidecar(sidecar)


# ---- gate ---------------------------------------------------------------------

def test_the_plane_is_off_by_default_and_refuses_verbs_but_serves_reads(monkeypatch):
    from maverick import config
    monkeypatch.delenv("MAVERICK_CONTROL_PLANE")
    config.reset_config_cache()
    assert acp.enabled() is False
    assert acp.roster() == []
    assert acp.status()["enabled"] is False
    with pytest.raises(acp.ControlPlaneDisabled):
        acp.suspend("user:local", reason="x")
    with pytest.raises(acp.ControlPlaneDisabled):
        acp.halt_all("x")
    from maverick.revocation import is_revoked
    assert not is_revoked("user:local")


def test_the_config_knob_arms_the_plane(monkeypatch, tmp_path):
    from maverick import config
    monkeypatch.delenv("MAVERICK_CONTROL_PLANE")
    cfg = tmp_path / "config.toml"
    cfg.write_text("[control_plane]\nenable = true\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    assert acp.enabled() is True


def test_status_and_mutations_refuse_unreadable_control_plane_config(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "get_control_plane", lambda: {"enable": False})
    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda: {"private-config-path": "sentinel parse failure"},
    )
    source = acp.ControlPlaneSnapshot(rows=(), captured_at=123.0)

    assert acp.enabled() is False
    with pytest.raises(
        acp.ControlPlaneDependencyError,
        match="control-plane configuration authority is unavailable",
    ) as status_error:
        acp.status(source=source)
    with pytest.raises(acp.ControlPlaneDependencyError) as mutation_error:
        acp.suspend("user:local", reason="incident")
    assert "sentinel" not in str(status_error.value)
    assert "sentinel" not in str(mutation_error.value)


def test_status_refuses_unreadable_halt_authority(monkeypatch):
    from maverick import killswitch

    def _unavailable(**_kwargs):
        raise killswitch.Halted("sentinel secret", "file-error")

    monkeypatch.setattr(killswitch, "check", _unavailable)
    source = acp.ControlPlaneSnapshot(rows=(), captured_at=123.0)

    with pytest.raises(
        acp.ControlPlaneDependencyError,
        match="halt authority is unavailable",
    ) as exc:
        acp.status(source=source)
    assert "sentinel" not in str(exc.value)


# ---- roster -------------------------------------------------------------------

def test_roster_joins_native_runs_and_external_trust_entries(monkeypatch):
    monkeypatch.setattr("maverick.world_model.open_world",
                        lambda *a, **k: _world("user:alice", "user:alice", ""))
    _enroll("vega")
    rows = {r.principal: r for r in acp.roster()}
    assert rows["user:alice"].kind == acp.KIND_NATIVE
    assert rows["user:alice"].running_goals == 2
    assert rows["user:alice"].state == "running"
    # An unowned goal runs under the root grant's principal.
    assert rows["user:local"].running_goals == 1
    assert rows["agent:vega"].kind == acp.KIND_EXTERNAL
    assert rows["agent:vega"].state == "active"
    assert rows["agent:vega"].max_risk == "medium"
    assert rows["agent:vega"].deny_tools == ("shell",)


def test_native_roster_uses_real_active_status_and_preserves_opaque_subjects(
    monkeypatch,
):
    principal = "user:auth0|North America/María 李"
    seen = {}

    class _World:
        def list_goals(self, **kwargs):
            seen.update(kwargs)
            return [
                SimpleNamespace(
                    owner="user:human-owner",
                    execution_principal=principal,
                )
            ]

    monkeypatch.setattr("maverick.world_model.open_world", lambda: _World())

    rows = acp.roster()

    assert seen["status"] == "active"
    assert rows == [
        acp.AgentPrincipal(
            principal=principal,
            kind=acp.KIND_NATIVE,
            label=principal,
            state="running",
            running_goals=1,
        )
    ]


def test_opaque_principal_round_trips_without_becoming_a_path():
    from maverick.revocation import is_revoked

    principal = "user:urn:example:tenant/a|María 李"

    result = acp.suspend(principal, reason="identity incident")

    assert result.ok is True
    assert result.principal == principal
    assert is_revoked(principal)
    assert acp.lookup(principal).principal == principal


@pytest.mark.parametrize("principal", ["", " user:x", "user:x ", "user:x\nadmin"])
def test_principal_domain_rejects_blank_padded_or_control_text(principal):
    with pytest.raises(ValueError, match="invalid principal"):
        acp.suspend(principal, reason="incident")


def test_snapshot_reuses_one_authority_scan_for_status_roster_and_page(monkeypatch):
    calls = []
    world = _world("user:alice")

    def _open_world(*args, **kwargs):
        calls.append("world")
        return world

    monkeypatch.setattr("maverick.world_model.open_world", _open_world)
    view = acp.snapshot()
    assert acp.status(source=view)["native"]["running_goals"] == 1
    assert [row.principal for row in acp.roster(source=view)] == ["user:alice"]
    page = view.page(limit=1)
    assert page["total"] == 1 and page["items"][0]["principal"] == "user:alice"
    assert calls == ["world"]


def test_an_unreadable_world_refuses_a_healthy_empty_roster(monkeypatch):
    def _boom(*a, **k):
        raise OSError("db locked")
    monkeypatch.setattr("maverick.world_model.open_world", _boom)
    _enroll("vega")
    with pytest.raises(acp.ControlPlaneDependencyError, match="world model authority") as exc:
        acp.roster()
    assert "db locked" not in str(exc.value)


@pytest.mark.parametrize(
    ("dependency", "patch_target", "message"),
    [
        ("revocation registry", "maverick.revocation.shared", "secret revocation path"),
        ("agent trust registry", "maverick.agent_trust.load_registry_strict", "secret config"),
        ("external-agent sidecar", "maverick.external_agents.roster", "secret sidecar"),
    ],
)
def test_roster_dependency_outages_raise_sanitized_errors(
    monkeypatch, dependency, patch_target, message,
):
    def _boom(*args, **kwargs):
        raise OSError(message)

    monkeypatch.setattr(patch_target, _boom)
    with pytest.raises(acp.ControlPlaneDependencyError, match=dependency) as exc:
        acp.roster()
    assert message not in str(exc.value)


def test_native_goal_roster_scan_is_bounded(monkeypatch):
    seen = {}

    class _World:
        def list_goals(self, **kwargs):
            seen.update(kwargs)
            return [SimpleNamespace(owner="user:x")] * (acp._MAX_NATIVE_GOALS + 1)

    monkeypatch.setattr("maverick.world_model.open_world", lambda: _World())
    with pytest.raises(acp.ControlPlaneDependencyError, match="bounded native-goal"):
        acp.roster()
    assert seen["limit"] == acp._MAX_NATIVE_GOALS + 1


def test_a_revoked_external_principal_without_a_trust_entry_stays_on_the_roster():
    """Found by driving the console: containing `agent:ghost` (no registry
    entry) revoked it, then the roster dropped it, so nothing could release
    it. The revocation is live either way; the roster must say so."""
    from maverick.revocation import is_revoked
    assert acp.contain("agent:ghost", reason="honeytoken").ok
    assert is_revoked("agent:ghost")
    row = acp.lookup("agent:ghost")
    assert row is not None and row.kind == acp.KIND_EXTERNAL
    assert row.state == "suspended" and row.revoked
    assert row.platform == "not in trust registry"
    assert acp.release("agent:ghost").ok
    assert not is_revoked("agent:ghost") and acp.lookup("agent:ghost") is None


# ---- suspend / resume ---------------------------------------------------------

def test_suspend_lands_in_the_revocation_registry_and_resume_lifts_it(monkeypatch):
    from maverick.revocation import is_revoked
    seen = _capture(monkeypatch)
    result = acp.suspend("user:local", reason="runaway spend", actor="ops@x")
    assert result.ok and result.verb == "suspend"
    assert is_revoked("user:local")
    row = acp.lookup("user:local")
    assert row is not None and row.state == "suspended" and row.revoked
    assert "runaway spend" in row.revoked_reason
    assert acp.status()["native"]["suspended"] == 1

    back = acp.resume("user:local", actor="ops@x")
    assert back.ok
    assert not is_revoked("user:local")
    assert acp.lookup("user:local") is None  # nothing running, nothing revoked
    kinds = [(k, kw["verb"], kw["ok"]) for k, kw in seen if k == "control_plane_action"]
    assert kinds == [("control_plane_action", "suspend", True),
                     ("control_plane_action", "resume", True)]
    assert all(kw["actor"] == "ops@x" for k, kw in seen if k == "control_plane_action")


def test_suspending_an_external_agent_flips_its_trust_entry_too():
    from maverick.agent_trust import load_registry
    from maverick.revocation import is_revoked
    _enroll("vega")
    assert acp.suspend("agent:vega", reason="key leaked").ok
    assert is_revoked("agent:vega")
    assert load_registry()["vega"].revoked is True
    assert load_registry()["vega"].is_active() == (False, "revoked")
    assert acp.lookup("agent:vega").state == "suspended"

    assert acp.resume("agent:vega").ok
    assert not is_revoked("agent:vega")
    assert load_registry()["vega"].revoked is False


def test_a_config_only_trust_entry_gets_a_managed_overlay(monkeypatch, tmp_path):
    """The TOML entry cannot be edited; the managed overlay overrides it by id."""
    from maverick import config
    from maverick.agent_trust import load_registry
    cfg = tmp_path / "config.toml"
    cfg.write_text('[control_plane]\nenable = true\n[agent_trust]\nagents = [\n'
                   '  { id = "toml-only", direction = "both", max_risk = "low" },\n]\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    assert load_registry()["toml-only"].revoked is False
    result = acp.suspend("agent:toml-only", reason="x")
    assert result.ok
    assert any("managed overlay" in n for n in result.notes)
    assert load_registry()["toml-only"].revoked is True
    assert load_registry()["toml-only"].max_risk == "low"  # nothing else changed


def test_a_revocation_that_does_not_persist_is_reported_as_failure(monkeypatch):
    import maverick.revocation as rev

    class _Fake:
        def revoke(self, principal, *, reason="", now=None):
            return None

        def is_revoked(self, principal):
            return False

    monkeypatch.setattr(rev, "shared", lambda: _Fake())
    result = acp.suspend("user:local", reason="x")
    assert not result.ok
    assert result.code == "not_applied"
    assert "did not persist" in result.detail


@pytest.mark.parametrize(
    "verb",
    ["suspend", "resume", "contain", "release", "attenuate", "halt", "clear-halt"],
)
def test_mutation_dependency_failures_are_stable_and_sanitized(
    monkeypatch, verb,
):
    """Backend paths and exception text never become operator/API payloads."""

    sentinel = "sentinel-secret-C:/private/authority/token"

    def _boom(*_args, **_kwargs):
        raise OSError(sentinel)

    if verb in {"suspend", "resume"}:
        monkeypatch.setattr("maverick.revocation.shared", _boom)
        result = (
            acp.suspend("user:local", reason="incident")
            if verb == "suspend"
            else acp.resume("user:local")
        )
    elif verb == "contain":
        monkeypatch.setattr("maverick.agent_edr.contain", _boom)
        result = acp.contain("user:local", reason="incident")
    elif verb == "release":
        monkeypatch.setattr("maverick.agent_edr.release", _boom)
        result = acp.release("user:local")
    elif verb == "attenuate":
        monkeypatch.setattr("maverick.agent_trust.attenuate_agent", _boom)
        result = acp.attenuate("agent:vega", max_risk="low")
    elif verb == "halt":
        monkeypatch.setattr("maverick.file_lock.atomic_write_text", _boom)
        result = acp.halt_all("incident")
    else:
        from maverick import killswitch

        killswitch._halt_file_path().write_text("incident\n", encoding="utf-8")
        monkeypatch.setattr(killswitch, "clear", _boom)
        result = acp.clear_halt()

    serialized = json.dumps(result.to_dict(), sort_keys=True)
    assert result.ok is False
    assert result.code == "dependency_unavailable"
    assert "authority is unavailable" in result.detail
    assert sentinel not in serialized


def test_control_result_reports_fail_soft_audit_outage(monkeypatch):
    monkeypatch.setattr("maverick.audit.record", lambda *a, **k: False)
    result = acp.suspend("user:local", reason="incident")
    assert result.ok
    assert result.audit_written is False
    assert "audit row was not written" in " ".join(result.notes)


# ---- contain / release --------------------------------------------------------

def test_contain_uses_the_security_plane_and_release_undoes_it(monkeypatch):
    from maverick.revocation import is_revoked
    seen = _capture(monkeypatch)
    _enroll("vega")
    result = acp.contain("agent:vega", reason="honeytoken tripped", actor="soc")
    assert result.ok
    assert is_revoked("agent:vega")
    assert any("not sealed" in n for n in result.notes)  # out-of-band: no live swarm
    row = acp.lookup("agent:vega")
    assert row.revoked and row.contained and row.state == "contained"
    refused = acp.resume("agent:vega", actor="operator")
    assert not refused.ok and "use release" in refused.detail
    assert refused.code == "protected_containment"
    assert refused.to_dict()["code"] == "protected_containment"
    assert is_revoked("agent:vega")
    # The security plane's own containment row is written alongside ours.
    assert any(k == "agent_edr_containment" for k, _ in seen)
    assert [kw["verb"] for k, kw in seen if k == "control_plane_action"] == [
        "contain", "resume",
    ]

    back = acp.release("agent:vega", actor="soc")
    assert back.ok
    assert not is_revoked("agent:vega")
    assert any("not enrolled in the gateway" in n for n in back.notes)


def test_external_contain_and_release_verify_gateway_post_state():
    from maverick import external_agents as xa
    _enroll("vega")
    _gateway_enroll("vega")
    contained = acp.contain("agent:vega", reason="incident", actor="soc")
    assert contained.ok and xa.containment_state("vega") is True
    released = acp.release("agent:vega", actor="soc")
    assert released.ok and xa.containment_state("vega") is False


@pytest.mark.parametrize("mode", ["false", "exception", "unchanged"])
def test_external_gateway_containment_failure_is_not_reported_as_success(
    monkeypatch, mode,
):
    from maverick import external_agents as xa
    from maverick.revocation import shared
    _enroll("vega")
    _gateway_enroll("vega")

    if mode == "false":
        monkeypatch.setattr(xa, "contain", lambda *a, **k: False)
    elif mode == "exception":
        def _boom(*args, **kwargs):
            raise OSError("gateway secret")
        monkeypatch.setattr(xa, "contain", _boom)
    else:
        monkeypatch.setattr(xa, "contain", lambda *a, **k: True)

    result = acp.contain("agent:vega", reason="incident", actor="soc")
    assert not result.ok
    assert "gateway" in result.detail
    assert shared().revoked()["agent:vega"].protected is True


@pytest.mark.parametrize("mode", ["false", "exception", "unchanged"])
def test_external_gateway_release_failure_retains_other_containment(
    monkeypatch, mode,
):
    from maverick import agent_trust
    from maverick import external_agents as xa
    from maverick.quarantine import QuarantineRegistry
    from maverick.revocation import is_revoked
    _enroll("vega")
    _gateway_enroll("vega")
    live = QuarantineRegistry()
    assert acp.contain(
        "agent:vega", reason="incident", actor="soc", registry=live,
    ).ok
    assert live.is_sealed("agent:vega")

    if mode == "false":
        monkeypatch.setattr(xa, "release", lambda *a, **k: False)
    elif mode == "exception":
        def _boom(*args, **kwargs):
            raise OSError("gateway secret")
        monkeypatch.setattr(xa, "release", _boom)
    else:
        monkeypatch.setattr(xa, "release", lambda *a, **k: True)

    result = acp.release("agent:vega", actor="soc", registry=live)
    assert not result.ok
    assert "gateway" in result.detail
    assert is_revoked("agent:vega")
    assert agent_trust.load_registry()["vega"].revoked is True
    assert xa.containment_state("vega") is True
    assert live.is_sealed("agent:vega")


def test_release_cannot_delete_generation_between_containment_projections(
    monkeypatch,
):
    from maverick import agent_trust
    from maverick import external_agents as xa
    from maverick.quarantine import QuarantineRegistry
    from maverick.revocation import shared

    _capture(monkeypatch)
    _enroll("vega")
    _gateway_enroll("vega")
    live = QuarantineRegistry()
    registry = shared()
    projection_reached = threading.Event()
    continue_containment = threading.Event()
    release_read_attempted = threading.Event()
    release_finished = threading.Event()
    contain_results = []
    release_results = []
    failures: list[BaseException] = []
    real_set_revoked = agent_trust.set_revoked
    real_revoked = registry.revoked

    def _pause_first_restrictive_projection(agent_id: str, revoked: bool) -> bool:
        if revoked and not projection_reached.is_set():
            published = real_revoked()["agent:vega"]
            assert published.protected is True
            assert published.generation
            assert live.is_sealed("agent:vega")
            projection_reached.set()
            assert continue_containment.wait(timeout=5)
        return real_set_revoked(agent_id, revoked)

    def _observe_release_read():
        if threading.current_thread().name == "release-during-containment":
            release_read_attempted.set()
        return real_revoked()

    monkeypatch.setattr(agent_trust, "set_revoked", _pause_first_restrictive_projection)
    monkeypatch.setattr(registry, "revoked", _observe_release_read)

    def _contain() -> None:
        try:
            contain_results.append(acp.contain(
                "agent:vega", reason="new incident", actor="soc", registry=live,
            ))
        except BaseException as exc:  # captured for the assertion thread
            failures.append(exc)

    def _release() -> None:
        try:
            release_results.append(
                acp.release("agent:vega", actor="soc", registry=live)
            )
        except BaseException as exc:  # captured for the assertion thread
            failures.append(exc)
        finally:
            release_finished.set()

    contain_thread = threading.Thread(target=_contain)
    contain_thread.start()
    assert projection_reached.wait(timeout=5)

    release_thread = threading.Thread(
        target=_release,
        name="release-during-containment",
    )
    release_thread.start()
    assert release_read_attempted.wait(timeout=5)
    # The generation is already published, but release cannot observe/delete it
    # until the live, trust, and gateway projections finish under the same lock.
    assert not release_finished.wait(timeout=0.1)

    continue_containment.set()
    contain_thread.join(timeout=5)
    release_thread.join(timeout=5)
    assert not contain_thread.is_alive()
    assert not release_thread.is_alive()
    assert failures == []
    assert len(contain_results) == 1 and contain_results[0].ok
    assert len(release_results) == 1 and release_results[0].ok
    # Release linearized after the completed containment, so every projection
    # is coherently clear rather than leaving a mixed successful containment.
    assert "agent:vega" not in registry.revoked()
    assert agent_trust.load_registry()["vega"].revoked is False
    assert xa.containment_state("vega") is False
    assert live.is_sealed("agent:vega") is False


def test_stale_release_cannot_clear_a_newer_external_containment(monkeypatch):
    from maverick import agent_trust
    from maverick import external_agents as xa
    from maverick.revocation import shared

    _capture(monkeypatch)
    _enroll("vega")
    _gateway_enroll("vega")
    assert acp.contain(
        "agent:vega", reason="incident one", actor="soc",
    ).ok

    registry = shared()
    first = registry.revoked()["agent:vega"]
    release_reached_cas = threading.Event()
    continue_release = threading.Event()
    observed_generations: list[str | None] = []
    release_results = []
    failures: list[BaseException] = []
    real_unrevoke = registry.unrevoke

    def _paused_unrevoke(*args, **kwargs):
        observed_generations.append(kwargs.get("expected_generation"))
        release_reached_cas.set()
        assert continue_release.wait(timeout=5)
        return real_unrevoke(*args, **kwargs)

    monkeypatch.setattr(registry, "unrevoke", _paused_unrevoke)

    def _release() -> None:
        try:
            release_results.append(acp.release("agent:vega", actor="soc"))
        except BaseException as exc:  # captured for the assertion thread
            failures.append(exc)

    thread = threading.Thread(target=_release)
    thread.start()
    assert release_reached_cas.wait(timeout=5)

    replacement = acp.contain(
        "agent:vega", reason="incident two", actor="soc",
    )
    assert replacement.ok
    second = registry.revoked()["agent:vega"]
    assert second.generation != first.generation

    continue_release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert failures == []
    assert observed_generations == [first.generation]
    assert len(release_results) == 1
    stale = release_results[0]
    assert stale.ok is False
    assert stale.code == "concurrent_containment"
    assert registry.revoked()["agent:vega"] == second
    assert agent_trust.load_registry()["vega"].revoked is True
    assert xa.containment_state("vega") is True


def test_unenrolled_external_gateway_is_truthfully_noted():
    _enroll("vega")
    result = acp.contain("agent:vega", reason="incident", actor="soc")
    assert result.ok
    assert "not enrolled" in " ".join(result.notes)


def test_contain_revokes_the_whole_subtree():
    from maverick.revocation import is_revoked
    result = acp.contain("user:alice", reason="x",
                         edges={"user:alice": ["agent:alice-child"]})
    assert result.ok
    assert is_revoked("user:alice") and is_revoked("agent:alice-child")


# ---- attenuate ----------------------------------------------------------------

def test_attenuate_narrows_and_never_widens():
    from maverick.agent_trust import load_registry
    _enroll("vega")  # medium risk, $5, deny shell
    ok = acp.attenuate("agent:vega", deny_tools=["email"], max_risk="low", max_dollars=2)
    assert ok.ok
    agent = load_registry()["vega"]
    assert agent.deny_tools == frozenset({"shell", "email"})
    assert agent.max_risk == "low" and agent.max_dollars == 2.0
    assert agent.direction == "both"  # untouched fields survive
    for widen in ({"max_risk": "high"}, {"max_dollars": 3}, {"max_dollars": 0}):
        with pytest.raises(ValueError):
            acp.attenuate("agent:vega", **widen)
    assert load_registry()["vega"].max_risk == "low"  # refused whole, nothing moved


def test_attenuate_is_external_only_and_needs_a_trust_entry():
    with pytest.raises(ValueError, match="external"):
        acp.attenuate("user:local", max_risk="low")
    with pytest.raises(LookupError):
        acp.attenuate("agent:ghost", max_risk="low")


def test_concurrent_attenuation_denies_union_without_lost_update(monkeypatch):
    from maverick.agent_trust import load_registry
    monkeypatch.setattr("maverick.audit.record", lambda *a, **k: True)
    _enroll("vega")
    start = threading.Barrier(3)
    results = []
    failures = []

    def _worker(tool):
        try:
            start.wait(timeout=5)
            results.append(acp.attenuate("agent:vega", deny_tools=[tool]))
        except BaseException as exc:
            failures.append(exc)

    threads = [
        threading.Thread(target=_worker, args=("email",)),
        threading.Thread(target=_worker, args=("payments",)),
    ]
    for thread in threads:
        thread.start()
    start.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert failures == []
    assert len(results) == 2 and all(result.ok for result in results)
    assert load_registry()["vega"].deny_tools == frozenset({
        "shell", "email", "payments",
    })


def test_empty_or_unchanged_attenuation_does_not_write(monkeypatch):
    from maverick import agent_trust
    _enroll("vega")
    writes = []
    monkeypatch.setattr(
        agent_trust, "_save_managed", lambda entries: writes.append(entries),
    )
    with pytest.raises(ValueError, match="at least one"):
        acp.attenuate("agent:vega")
    with pytest.raises(ValueError, match="does not tighten"):
        acp.attenuate("agent:vega", deny_tools=["shell"])
    with pytest.raises(ValueError, match="does not tighten"):
        acp.attenuate("agent:vega", max_risk="medium", max_dollars=5.0)
    assert writes == []


# ---- halt ---------------------------------------------------------------------

def test_halt_and_clear_use_a_verified_durable_local_file(monkeypatch):
    from maverick import killswitch
    seen = _capture(monkeypatch)
    result = acp.halt_all("prompt-injection wave", actor="ops")
    assert result.ok and killswitch.is_active()
    path = killswitch._halt_file_path()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["scope"] == "local-deployment"
    assert isinstance(payload["generation"], str) and payload["generation"]
    assert "local HALT" in result.detail
    assert acp.status()["halted"] is True
    with pytest.raises(killswitch.Halted):
        killswitch.check()
    cleared = acp.clear_halt(actor="ops")
    assert cleared.ok and not killswitch.is_active()
    assert not path.exists()
    assert [kw["verb"] for k, kw in seen if k == "control_plane_action"] == [
        "halt", "clear-halt-request", "clear-halt",
    ]
    assert all(k != "halt" for k, _ in seen)


def test_halt_uses_prepare_contract_for_caller_selected_parent(monkeypatch):
    from maverick import file_lock, killswitch

    calls = []
    real_prepare = file_lock.prepare_private_directory

    def _prepare(path):
        calls.append(path)
        return real_prepare(path)

    monkeypatch.setattr(file_lock, "prepare_private_directory", _prepare)

    result = acp.halt_all("incident", actor="ops")

    assert result.ok is True
    assert calls == [killswitch._halt_file_path().parent]


def test_local_clear_barrier_failure_leaves_durable_stop(monkeypatch):
    from maverick import killswitch

    path = killswitch._halt_file_path()
    path.write_text("incident\n", encoding="utf-8")

    def _refuse_clear():
        raise OSError("sentinel-barrier-secret")

    monkeypatch.setattr(killswitch, "clear", _refuse_clear)

    result = acp.clear_halt(actor="ops")

    assert result.ok is False
    assert result.code == "dependency_unavailable"
    assert path.read_text(encoding="utf-8") == "incident\n"
    assert "sentinel" not in json.dumps(result.to_dict())


def test_local_clear_preserves_a_generation_armed_while_waiting_for_lock(
    monkeypatch,
):
    from maverick import file_lock, killswitch

    assert acp.halt_all("first incident", actor="ops").ok is True
    path = killswitch._halt_file_path()
    first = path.read_text(encoding="utf-8")
    real_lock = file_lock.cross_process_lock
    authority = killswitch._halt_authority_lock_path(path)
    replacement = json.dumps(
        {
            "reason": "new incident",
            "source": "concurrent-arm",
            "generation": "new-local-generation",
            "scope": "local-deployment",
        },
        sort_keys=True,
    )

    @contextmanager
    def _arm_before_clear_lock(target, *, strict=False):
        if target == authority:
            assert strict is True
            file_lock.atomic_write_text(path, replacement, mode=0o600)
            yield
            return
        with real_lock(target, strict=strict):
            yield

    monkeypatch.setattr(file_lock, "cross_process_lock", _arm_before_clear_lock)

    result = acp.clear_halt(actor="ops")

    assert result.ok is False
    assert result.code == "concurrent_halt"
    assert "newer local HALT generation" in result.detail
    assert path.read_text(encoding="utf-8") == replacement
    assert path.read_text(encoding="utf-8") != first


def test_local_clear_preserves_a_concurrent_in_process_halt(monkeypatch):
    from maverick import file_lock, killswitch

    killswitch.halt("first incident", source="operator")
    path = killswitch._halt_file_path()
    authority = killswitch._halt_authority_lock_path(path)
    real_lock = file_lock.cross_process_lock

    @contextmanager
    def _halt_before_clear_lock(target, *, strict=False):
        if target == authority:
            assert strict is True
            killswitch.halt("new incident", source="concurrent-arm")
            yield
            return
        with real_lock(target, strict=strict):
            yield

    monkeypatch.setattr(file_lock, "cross_process_lock", _halt_before_clear_lock)

    result = acp.clear_halt(actor="ops")

    assert result.ok is False
    assert result.code == "concurrent_halt"
    with pytest.raises(killswitch.Halted) as concurrent:
        killswitch.check(force_refresh=True)
    assert concurrent.value.reason == "new incident"
    assert concurrent.value.source == "concurrent-arm"


def test_local_clear_refuses_a_degraded_cross_process_lock(monkeypatch):
    from maverick import file_lock, killswitch

    assert acp.halt_all("incident", actor="ops").ok is True
    path = killswitch._halt_file_path()
    before = path.read_bytes()
    authority = killswitch._halt_authority_lock_path(path)
    sidecar = authority.parent / f"{authority.name}.lock"
    canonical = file_lock._canonical_lock_path(sidecar)
    prior = getattr(file_lock._THREAD_LOCK_STATE, "held", None)
    file_lock._THREAD_LOCK_STATE.held = {canonical: (1, False)}
    try:
        result = acp.clear_halt(actor="ops")
    finally:
        if prior is None:
            delattr(file_lock._THREAD_LOCK_STATE, "held")
        else:
            file_lock._THREAD_LOCK_STATE.held = prior

    assert result.ok is False
    assert result.code == "dependency_unavailable"
    assert "authority is unavailable" in result.detail
    assert path.read_bytes() == before


# ---- validation ---------------------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    ["", " user:x", "user:x ", "user:x\nadmin", "x" * 513, None, 3],
)
def test_invalid_principals_are_refused_before_anything_lands(bad):
    with pytest.raises(ValueError):
        acp.suspend(bad, reason="x")
    assert not acp.valid_principal(bad)


def test_a_reason_is_required_and_bounded():
    with pytest.raises(ValueError):
        acp.suspend("user:local", reason="  ")
    with pytest.raises(ValueError):
        acp.suspend("user:local", reason="r" * 501)
    with pytest.raises(ValueError):
        acp.halt_all("")


def test_ledger_reads_the_principals_timeline(monkeypatch):
    from maverick import agent_edr
    monkeypatch.setattr(agent_edr, "timeline", lambda subject, since=None: [
        agent_edr.Detection(ts=1.0, kind="k", severity="low", subject=subject,
                            detail="d", source_event="e"),
        agent_edr.Detection(ts=2.0, kind="k", severity="low", subject=subject,
                            detail="d2", source_event="e")])
    rows = acp.ledger("user:local", limit=1)
    assert rows == [{"ts": 2.0, "kind": "k", "severity": "low", "subject": "user:local",
                     "detail": "d2", "source_event": "e", "day": "", "evidence": {}}]


# ---- CLI ----------------------------------------------------------------------

def test_the_cli_group_drives_the_plane(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick.revocation import is_revoked
    _capture(monkeypatch)
    runner = CliRunner()
    out = runner.invoke(main, ["control-plane", "status", "--json"])
    assert out.exit_code == 0, out.output
    assert '"enabled": true' in out.output
    out = runner.invoke(main, ["control-plane", "suspend", "user:local", "--reason", "cli test"])
    assert out.exit_code == 0, out.output
    assert is_revoked("user:local")
    out = runner.invoke(main, ["control-plane", "list"])
    assert out.exit_code == 0 and "user:local" in out.output and "suspended" in out.output
    out = runner.invoke(main, ["control-plane", "resume", "user:local"])
    assert out.exit_code == 0 and not is_revoked("user:local")
    out = runner.invoke(main, ["control-plane", "attenuate", "user:local", "--max-risk", "low"])
    assert out.exit_code != 0 and "external" in out.output
    monkeypatch.delenv("MAVERICK_CONTROL_PLANE")
    from maverick import config
    config.reset_config_cache()
    out = runner.invoke(main, ["control-plane", "halt", "--reason", "x"])
    assert out.exit_code != 0 and "control plane is off" in out.output


def test_capability_cli_cannot_unrevoke_security_containment(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick.revocation import is_revoked
    _capture(monkeypatch)
    assert acp.contain("user:local", reason="incident", actor="soc").ok
    out = CliRunner().invoke(main, ["capability", "unrevoke", "user:local"])
    assert out.exit_code != 0
    assert "security-contained" in out.output
    assert is_revoked("user:local")


def test_trust_cli_restore_linearizes_before_concurrent_containment(monkeypatch):
    from click.testing import CliRunner
    from maverick import agent_trust
    from maverick.cli import main
    from maverick.revocation import shared

    _capture(monkeypatch)
    _enroll("vega")
    assert agent_trust.set_revoked("vega", True)

    registry = shared()
    contain_reached_authority = threading.Event()
    contain_finished = threading.Event()
    contain_results = []
    failures: list[BaseException] = []
    real_authority = registry.containment_authority
    real_set_revoked = agent_trust.set_revoked
    started = False

    @contextmanager
    def _observed_authority(principal):
        if threading.current_thread().name == "contain-during-restore":
            contain_reached_authority.set()
        with real_authority(principal):
            yield

    monkeypatch.setattr(registry, "containment_authority", _observed_authority)

    def _contain() -> None:
        try:
            contain_results.append(
                acp.contain("agent:vega", reason="incident", actor="soc")
            )
        except BaseException as exc:  # captured for the assertion thread
            failures.append(exc)
        finally:
            contain_finished.set()

    thread = threading.Thread(target=_contain, name="contain-during-restore")

    def _restore_then_race(agent_id: str, revoked: bool) -> bool:
        nonlocal started
        if not revoked and not started:
            started = True
            thread.start()
            assert contain_reached_authority.wait(timeout=5)
            # run_if_unprotected still owns the revocation authority lock, so
            # the competing contain cannot publish until this restore returns.
            assert not contain_finished.is_set()
        return real_set_revoked(agent_id, revoked)

    monkeypatch.setattr(agent_trust, "set_revoked", _restore_then_race)
    out = CliRunner().invoke(main, ["trust", "unrevoke", "vega"])
    assert out.exit_code == 0, out.output

    thread.join(timeout=5)
    assert not thread.is_alive()
    assert failures == []
    assert len(contain_results) == 1 and contain_results[0].ok
    current = registry.revoked()["agent:vega"]
    assert current.protected is True
    assert current.generation
    assert agent_trust.load_registry()["vega"].revoked is True


# ---- fleet-scale bulk actions / time-boxed containment ----------------------

def _enroll_on_platform(agent_id: str, platform: str = "openai") -> None:
    from maverick import external_agents as xa

    _enroll(agent_id)
    with xa._sidecar_locked():
        sidecar = xa._load_sidecar()
        sidecar[agent_id] = {"platform": platform, "contained": False}
        xa._save_sidecar(sidecar)


def test_bulk_platform_selection_is_snapshot_pinned_before_containment():
    from maverick.revocation import is_revoked

    _enroll_on_platform("vega")
    _enroll_on_platform("nova")
    view = acp.snapshot()
    selection = acp.select_bulk(platform="OpenAI Agents", source=view)
    slug_selection = acp.select_bulk(platform="openai", source=view)

    assert selection.principals == ("agent:nova", "agent:vega")
    assert slug_selection.principals == selection.principals
    result = acp.bulk_action(selection, verb="contain", reason="incident", actor="soc")

    assert result.ok is True
    assert [row.principal for row in result.results] == list(selection.principals)
    assert is_revoked("agent:vega") and is_revoked("agent:nova")


def test_bulk_refuses_unscoped_empty_and_stale_selections(monkeypatch):
    monkeypatch.setattr("maverick.world_model.open_world", lambda *a, **k: _world("user:alice"))
    view = acp.snapshot()

    with pytest.raises(ValueError, match="explicit tenant or platform"):
        acp.select_bulk(source=view)
    with pytest.raises(LookupError, match="matched no"):
        acp.select_bulk(platform="OpenAI Agents", source=view)

    selection = acp.select_bulk(tenant="", source=view)
    assert acp.suspend("user:alice", reason="changed after review").ok
    with pytest.raises(acp.ControlPlaneStaleSelection, match="stale"):
        acp.bulk_action(selection, verb="contain", reason="incident")


def test_bulk_selection_cannot_cross_the_active_tenant(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant("acme")
    try:
        monkeypatch.setattr(
            "maverick.world_model.open_world", lambda *a, **k: _world("user:alice"),
        )
        view = acp.snapshot()
        selected = acp.select_bulk(tenant="acme", source=view)
        assert selected.tenant == "acme"
        with pytest.raises(ValueError, match="active tenant boundary"):
            acp.select_bulk(tenant="other-tenant", source=view)
    finally:
        reset_tenant(token)


def test_timeboxed_containment_releases_only_after_due_time():
    from maverick.revocation import is_revoked, shared

    scheduled = acp.contain_timeboxed(
        "user:local",
        reason="bounded incident",
        release_after_seconds=60,
        idempotency_key="case-123",
        actor="soc",
    )

    assert scheduled.result.ok is True
    assert scheduled.status == "scheduled"
    assert shared().revoked()["user:local"].generation == scheduled.containment_generation
    assert acp.sweep_timeboxed_releases(now=scheduled.release_at - 0.1) == []
    assert is_revoked("user:local")

    released = acp.sweep_timeboxed_releases(now=scheduled.release_at + 0.1, actor="timer")

    assert len(released) == 1 and released[0].ok is True
    assert released[0].verb == "timebox-release"
    assert not is_revoked("user:local")
    assert acp.timeboxed_containments()[0]["status"] == "released"


def test_timebox_never_releases_a_newer_protected_containment():
    from maverick.revocation import is_revoked, shared

    scheduled = acp.contain_timeboxed(
        "user:local",
        reason="first incident",
        release_after_seconds=60,
        idempotency_key="case-123-replaced",
    )
    first_generation = scheduled.containment_generation
    assert acp.contain("user:local", reason="second incident", actor="soc").ok
    assert shared().revoked()["user:local"].generation != first_generation

    outcomes = acp.sweep_timeboxed_releases(now=scheduled.release_at + 1)

    assert len(outcomes) == 1
    assert outcomes[0].ok is False and outcomes[0].code == "superseded"
    assert is_revoked("user:local")
    assert acp.timeboxed_containments()[0]["status"] == "superseded"


def test_manual_release_retires_timebox_and_never_releases_a_newer_state():
    from maverick.revocation import is_revoked

    scheduled = acp.contain_timeboxed(
        "user:local",
        reason="manual recovery",
        release_after_seconds=60,
        idempotency_key="case-124",
    )
    assert acp.release("user:local", actor="soc").ok
    assert not is_revoked("user:local")
    assert acp.sweep_timeboxed_releases(now=scheduled.release_at + 1) == []
    records = acp.timeboxed_containments()
    assert records[0]["status"] == "manually_released"


def test_timebox_recovers_a_schedule_after_a_post_containment_store_fault(monkeypatch):
    from maverick.revocation import is_revoked

    real_finish = acp._finish_timebox

    def _lost_schedule(*_args, **_kwargs):
        raise acp.ControlPlaneDependencyError("timeboxed containment records")

    monkeypatch.setattr(acp, "_finish_timebox", _lost_schedule)
    first = acp.contain_timeboxed(
        "user:local",
        reason="recover schedule",
        release_after_seconds=60,
        idempotency_key="case-124-recovery",
    )
    assert first.result.ok is False
    assert first.result.code == "schedule_unavailable"
    assert is_revoked("user:local")

    monkeypatch.setattr(acp, "_finish_timebox", real_finish)
    key_sha256 = acp._timebox_idempotency_sha256("", "case-124-recovery")
    acp._update_timebox(
        key_sha256,
        lambda record: record.update(lease_until=0.0, updated_at=acp.time.time()),
    )
    recovered = acp.contain_timeboxed(
        "user:local",
        reason="recover schedule",
        release_after_seconds=60,
        idempotency_key="case-124-recovery",
    )

    assert recovered.result.ok is True
    assert recovered.result.code == "recovered"
    assert recovered.status == "scheduled"


def test_timebox_error_is_sanitized_and_does_not_schedule_an_incomplete_containment(monkeypatch):
    sentinel = "C:/secret/containment-authority"

    def _boom(*_args, **_kwargs):
        raise OSError(sentinel)

    monkeypatch.setattr("maverick.agent_edr.contain", _boom)
    result = acp.contain_timeboxed(
        "user:local",
        reason="dependency test",
        release_after_seconds=60,
        idempotency_key="case-125",
    )

    assert result.result.ok is False
    assert result.status == "failed"
    assert result.result.code == "dependency_unavailable"
    assert sentinel not in json.dumps(result.to_dict())
    assert acp.sweep_timeboxed_releases(now=result.release_at + 1) == []


def test_bulk_action_uses_existing_cef_audit_and_otel_exports(monkeypatch):
    from contextlib import contextmanager

    from maverick.audit.export import to_cef

    spans = []

    @contextmanager
    def _span(name, *, attributes=None):
        spans.append((name, dict(attributes or {})))
        yield None

    monkeypatch.setattr("maverick.observability.trace_span", _span)
    monkeypatch.setattr(
        "maverick.world_model.open_world", lambda *a, **k: _world("user:alice"),
    )
    seen = _capture(monkeypatch)
    selection = acp.select_bulk(tenant="", source=acp.snapshot())

    result = acp.bulk_action(
        selection,
        verb="suspend",
        reason="automation outage",
        actor="ops",
    )

    assert result.ok is True
    assert ("agent_control_plane.bulk_action", {
        "control_plane.operation": "bulk_action",
        "control_plane.verb": "suspend",
        "control_plane.target_count": 1,
        "control_plane.platform_selected": False,
        "control_plane.tenant_bound": False,
        "control_plane.timeboxed": False,
    }) in spans
    summary = next(
        payload for kind, payload in seen
        if kind == "control_plane_action" and payload["verb"] == "bulk-suspend"
    )
    cef = to_cef({"kind": "control_plane_action", **summary})
    assert "verb=bulk-suspend" in cef
    assert "target_count=1" in cef
    assert "selection_sha256=" in cef
