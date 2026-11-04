"""Reject stale generated federation schemas before transport side effects."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick import federation, grpc_api


def _pb2(**changes):
    fields = {
        name: SimpleNamespace(number=number, type=kind, label=1)
        for name, number, kind in (
            ("accepted", 1, 8), ("goal_id", 2, 3), ("reason", 3, 9),
            ("outcome_state", 4, 9), ("audit_state", 5, 9), ("execution_state", 6, 9),
        )
    }
    fields.update(changes)
    return SimpleNamespace(DelegateResult=SimpleNamespace(DESCRIPTOR=SimpleNamespace(fields_by_name=fields)))


def _install(monkeypatch, pb2):
    grpc = SimpleNamespace()
    monkeypatch.setattr(grpc_api, "federation_pb2", pb2, raising=False)
    monkeypatch.setattr(grpc_api, "federation_pb2_grpc", grpc, raising=False)
    return grpc


@pytest.mark.parametrize("change", [
    {"outcome_state": None},
    {"audit_state": SimpleNamespace(number=8, type=9, label=1)},
    {"execution_state": SimpleNamespace(number=6, type=8, label=1)},
    {"outcome_state": SimpleNamespace(number=4, type=9, label=3)},
])
def test_stale_or_incompatible_fields_refuse_without_regeneration(monkeypatch, change):
    _install(monkeypatch, _pb2(**change))
    monkeypatch.setattr(federation, "_generate_stubs", lambda: pytest.fail("do not reload an old descriptor pool"))
    with pytest.raises(federation.FederationError, match="maverick gen-stubs.*restart"):
        federation._load_stubs()


def test_current_loaded_descriptors_are_reused(monkeypatch):
    pb2 = _pb2()
    grpc = _install(monkeypatch, pb2)
    monkeypatch.setattr(federation, "_generate_stubs", lambda: pytest.fail("already current"))
    assert federation._load_stubs() == (pb2, grpc)


def test_stale_message_is_rejected_before_missing_companion_import(monkeypatch):
    import builtins
    original_import = builtins.__import__
    _install(monkeypatch, _pb2(outcome_state=None))

    def no_grpc_companion(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "grpc_api" and "federation_pb2_grpc" in fromlist:
            pytest.fail("stale descriptor was not checked before its companion")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", no_grpc_companion)
    monkeypatch.setattr(federation, "_generate_stubs", lambda: pytest.fail("do not replace loaded stale stubs"))
    with pytest.raises(federation.FederationError, match="maverick gen-stubs.*restart"):
        federation._load_stubs()


@pytest.mark.parametrize("current", [False, True])
def test_freshly_generated_descriptors_are_also_validated(monkeypatch, current):
    import builtins

    from maverick import grpc_stubs
    pb2 = _pb2() if current else _pb2(execution_state=None)
    generated = []
    original_import = builtins.__import__

    def import_after_generation(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "grpc_api" and "federation_pb2" in fromlist and not generated:
            raise ImportError("generated modules absent")
        return original_import(name, globals, locals, fromlist, level)

    def generate():
        generated.append(True)
        _install(monkeypatch, pb2)

    monkeypatch.setattr(builtins, "__import__", import_after_generation)
    monkeypatch.setattr(grpc_stubs, "guard_runtime_generation", lambda name: None)
    monkeypatch.setattr(federation, "_generate_stubs", generate)
    if current:
        assert federation._load_stubs()[0] is pb2
    else:
        with pytest.raises(federation.FederationError, match="maverick gen-stubs.*restart"):
            federation._load_stubs()
    assert generated == [True]


def test_stale_schema_blocks_client_before_dial(monkeypatch):
    _install(monkeypatch, _pb2(outcome_state=None))
    monkeypatch.setattr(federation, "_require_grpc", lambda: SimpleNamespace(
        insecure_channel=lambda *args: pytest.fail("stale schema dialed"),
        secure_channel=lambda *args: pytest.fail("stale schema dialed"),
    ))
    transport = federation._GrpcTransport(federation.Peer("receiver", "localhost:1", "token"))
    with pytest.raises(federation.FederationError, match="incompatible"):
        transport._bind()


def test_stale_schema_blocks_server_before_listener_or_dispatch(monkeypatch):
    from maverick import client
    _install(monkeypatch, _pb2(outcome_state=None))
    monkeypatch.setattr(federation, "federation_enabled", lambda: True)
    monkeypatch.setattr(client, "require_client_binding", lambda: None)
    monkeypatch.setattr(federation, "_require_grpc", lambda: SimpleNamespace(
        server=lambda *args, **kwargs: pytest.fail("stale schema created listener"),
    ))
    monkeypatch.setattr(federation, "_servicer", lambda *args: pytest.fail("stale schema created dispatcher"))
    with pytest.raises(federation.FederationError, match="incompatible"):
        federation.serve(service=SimpleNamespace(node="receiver"))
