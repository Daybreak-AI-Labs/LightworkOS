"""World-backend ownership at long-lived runtime boundaries."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from maverick import server as server_mod
from maverick import tools as tools_mod
from maverick import world_model as world_model_mod
from maverick.grpc_api import server as grpc_server_mod
from maverick.grpc_api.service import EventDTO


class _Closable:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _Channel:
    name = "test"

    def __init__(self) -> None:
        self.stop_calls = 0

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        self.stop_calls += 1


def test_server_run_releases_only_owned_dependencies() -> None:
    owned_world = _Closable()
    owned_sandbox = _Closable()
    channel = _Channel()
    server = server_mod.Server(
        owned_world,
        object(),
        sandbox=owned_sandbox,
        owns_world=True,
        owns_sandbox=True,
    )
    server.add_channel(channel)

    asyncio.run(server.run())
    # The CLI's KeyboardInterrupt handler may call stop again after run's
    # cancellation finalizer. Teardown stays idempotent.
    asyncio.run(server.stop())

    assert owned_world.close_calls == 1
    assert owned_sandbox.close_calls == 1
    assert channel.stop_calls == 1

    caller_world = _Closable()
    caller_sandbox = _Closable()
    caller_server = server_mod.Server(
        caller_world,
        object(),
        sandbox=caller_sandbox,
    )
    caller_server.add_channel(_Channel())

    asyncio.run(caller_server.run())

    assert caller_world.close_calls == 0
    assert caller_sandbox.close_calls == 0


def test_build_from_config_closes_world_and_sandbox_on_startup_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    world = _Closable()
    sandbox = _Closable()

    monkeypatch.setattr(
        server_mod,
        "load_config",
        lambda: {"sandbox": {"workdir": str(tmp_path)}, "channels": {}},
    )
    monkeypatch.setattr(server_mod, "open_world", lambda: world)
    monkeypatch.setattr(server_mod, "LLM", lambda **_kwargs: object())
    monkeypatch.setattr(server_mod, "build_sandbox", lambda **_kw: sandbox)
    monkeypatch.setattr(server_mod, "_WIRES", {})
    monkeypatch.setattr(
        "maverick.operator_preflight._routed_configuration_missing",
        lambda _config: {},
    )
    monkeypatch.setattr(
        "maverick.config.get_sandbox",
        lambda: {"workdir": str(tmp_path)},
    )

    with pytest.raises(RuntimeError, match="No channels enabled"):
        server_mod.build_from_config()

    assert world.close_calls == 1
    assert sandbox.close_calls == 1


def test_base_tool_names_closes_temporary_world(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Closable()
    registry = SimpleNamespace(
        all=lambda: [SimpleNamespace(name="shell"), SimpleNamespace(name="recall")],
    )
    monkeypatch.setattr(world_model_mod, "open_world", lambda _path=None: world)
    monkeypatch.setattr(tools_mod, "base_registry", lambda *_a, **_kw: registry)

    assert tools_mod.base_tool_names() == {"recall", "shell"}
    assert world.close_calls == 1


def test_grpc_disconnect_explicitly_closes_episode_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Codes:
        UNAUTHENTICATED = "UNAUTHENTICATED"

    class _Pb2Grpc:
        class MaverickServicer:
            pass

    class _Pb2:
        Event = SimpleNamespace

    class _Stream:
        def __init__(self) -> None:
            self.closed = False
            self.sent = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.sent:
                raise StopIteration
            self.sent = True
            return EventDTO(1, 2, "agent", "kind", "content", 3.0)

        def close(self) -> None:
            self.closed = True

    stream = _Stream()
    service = SimpleNamespace(stream_episode=lambda *_a, **_kw: stream)
    monkeypatch.setattr(grpc_server_mod, "_grpc_code", lambda: _Codes)
    servicer = grpc_server_mod._servicer(
        service,
        _Pb2,
        _Pb2Grpc,
        bearer_token="secret",
    )
    context = SimpleNamespace(
        invocation_metadata=lambda: (("authorization", "Bearer secret"),),
        is_active=lambda: False,
    )
    request = SimpleNamespace(goal_id=2, since_id=0, max_seconds=1.0)

    assert list(servicer.StreamEpisode(request, context)) == []
    assert stream.closed is True
