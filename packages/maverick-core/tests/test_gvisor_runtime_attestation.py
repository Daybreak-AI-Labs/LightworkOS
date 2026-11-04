"""Fail-closed contract for Docker-backed gVisor runtime selection."""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest
from maverick import config, health, sandbox
from maverick.sandbox import gvisor
from maverick.tools import diagnose


def _registry_result(monkeypatch, payload: object) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        assert args == [
            "docker",
            "info",
            "--format",
            gvisor.DOCKER_RUNTIMES_FORMAT,
        ]
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is True
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(gvisor.subprocess, "run", fake_run)
    return calls


def test_attestation_accepts_exact_runsc_registration(monkeypatch) -> None:
    calls = _registry_result(
        monkeypatch,
        {
            "runsc": {
                "path": "/usr/local/bin/runsc",
                "runtimeArgs": ["--platform=kvm"],
            }
        },
    )

    assert gvisor.validate_docker_gvisor_runtime("runsc") == "runsc"
    assert len(calls) == 1


def test_attestation_accepts_official_containerd_runsc_runtime(monkeypatch) -> None:
    _registry_result(
        monkeypatch,
        {
            "gvisor": {
                "runtimeType": "io.containerd.runsc.v1",
                "options": {"ConfigPath": "/etc/containerd/runsc.toml"},
            }
        },
    )

    assert gvisor.validate_docker_gvisor_runtime("gvisor") == "gvisor"


@pytest.mark.parametrize("runtime", ["runc", "not-runsc", "gvisorless-runc"])
def test_attestation_rejects_ambiguous_or_runc_names_without_querying(
    monkeypatch,
    runtime,
) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError("an untrusted runtime name must fail before Docker")

    monkeypatch.setattr(gvisor.subprocess, "run", unexpected)

    with pytest.raises(
        gvisor.GVisorRuntimeValidationError,
        match="not an approved gVisor runtime",
    ):
        gvisor.validate_docker_gvisor_runtime(runtime)


@pytest.mark.parametrize(
    ("registry", "message"),
    [
        ([], "runtime registry is not an object"),
        ({"runsc": []}, "registered runtime entry is not an object"),
        ({"runsc": {}}, "neither path nor runtimeType is present"),
        ({"runsc": {"path": "runc"}}, "non-runsc executable"),
        (
            {"runsc": {"path": "runsc", "runtimeArgs": "--platform=kvm"}},
            "runtimeArgs must be a list",
        ),
        (
            {"runsc": {"runtimeType": "io.containerd.runc.v2"}},
            "non-runsc runtimeType",
        ),
        (
            {
                "runsc": {
                    "runtimeType": "io.containerd.runsc.v1",
                    "runtimeArgs": ["--platform=kvm"],
                }
            },
            "runtimeArgs require a path-based",
        ),
    ],
)
def test_attestation_rejects_malformed_or_non_runsc_metadata(
    monkeypatch,
    registry,
    message,
) -> None:
    _registry_result(monkeypatch, registry)

    with pytest.raises(gvisor.GVisorRuntimeValidationError, match=message):
        gvisor.validate_docker_gvisor_runtime("runsc")


def test_attestation_rejects_malformed_docker_json(monkeypatch) -> None:
    monkeypatch.setattr(
        gvisor.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args,
            0,
            stdout="not-json",
            stderr="",
        ),
    )

    with pytest.raises(
        gvisor.GVisorRuntimeValidationError,
        match="did not return valid JSON",
    ):
        gvisor.validate_docker_gvisor_runtime("runsc")


def test_factory_health_and_diagnose_share_the_attestation_decision(
    monkeypatch,
    tmp_path,
) -> None:
    assert (
        sandbox.validate_docker_gvisor_runtime
        is health.validate_docker_gvisor_runtime
        is diagnose.validate_docker_gvisor_runtime
    )
    _registry_result(monkeypatch, {"runsc": {"path": "runc"}})
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    with pytest.raises(sandbox.SandboxPolicyError, match="non-runsc executable"):
        sandbox.build_sandbox(
            workdir=tmp_path,
            backend="gvisor",
            sandbox_config={"runtime": "runsc"},
        )

    rows: list[str] = []
    monkeypatch.setattr(
        health,
        "_row",
        lambda marker, label, detail="", fix="": rows.append(detail),
    )
    health._check_sandbox(
        {"sandbox": {"backend": "gvisor", "runtime": "runsc"}}
    )
    assert any("non-runsc executable" in row for row in rows)

    monkeypatch.setattr(
        config,
        "get_sandbox",
        lambda: {"backend": "gvisor", "runtime": "runsc"},
    )
    assert "non-runsc executable" in "\n".join(diagnose._check_sandbox())
