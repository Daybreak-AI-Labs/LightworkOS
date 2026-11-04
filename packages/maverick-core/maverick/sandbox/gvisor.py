"""Fail-closed validation for Docker-registered gVisor runtimes.

Docker runtime names are operator-controlled aliases. A name which merely
contains ``runsc`` or ``gvisor`` proves nothing about the executable Docker
will launch, so every caller must validate both a deliberately small name set
and Docker's registered runtime metadata.

This validates the Docker daemon's declared configuration; it does not
cryptographically attest the executable behind a runsc-shaped path. The
Docker daemon administrator remains part of the deployment trust boundary.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

DOCKER_RUNTIMES_FORMAT = "{{json .Runtimes}}"

# These are the standard runsc registration names Lightwork deliberately
# supports. Custom aliases remain possible by registering one of the explicit
# platform names below; substring matches are intentionally forbidden.
TRUSTED_GVISOR_RUNTIME_NAMES = frozenset(
    {
        "gvisor",
        "io.containerd.runsc.v1",
        "runsc",
        "runsc-kvm",
        "runsc-systrap",
    }
)

_RUNSC_EXECUTABLES = frozenset(
    {
        "containerd-shim-runsc-v1",
        "containerd-shim-runsc-v1.exe",
        "runsc",
        "runsc.exe",
    }
)
_RUNSC_RUNTIME_TYPE = "io.containerd.runsc.v1"


class GVisorRuntimeValidationError(RuntimeError):
    """Docker metadata does not identify an approved runsc registration."""


def _trusted_runtime_name(value: object) -> str:
    if value is None or value == "":
        runtime = "runsc"
    elif isinstance(value, str):
        runtime = value.strip()
    else:
        runtime = ""
    if runtime not in TRUSTED_GVISOR_RUNTIME_NAMES:
        allowed = ", ".join(sorted(TRUSTED_GVISOR_RUNTIME_NAMES))
        raise GVisorRuntimeValidationError(
            f"gvisor runtime {runtime or value!r} is not an approved gVisor "
            f"runtime name; expected one of: {allowed}"
        )
    return runtime


def _malformed(runtime: str, detail: str) -> GVisorRuntimeValidationError:
    return GVisorRuntimeValidationError(
        f"gvisor runtime {runtime!r} has malformed Docker runtime metadata: "
        f"{detail}"
    )


def _validate_registered_runtime(
    runtime: str,
    registered: Any,
) -> None:
    if not isinstance(registered, dict):
        raise _malformed(runtime, "the runtime registry is not an object")
    if runtime not in registered:
        raise GVisorRuntimeValidationError(
            f"gvisor runtime {runtime!r} is not registered with Docker"
        )

    metadata = registered[runtime]
    if not isinstance(metadata, dict):
        raise _malformed(runtime, "the registered runtime entry is not an object")

    runtime_args = metadata.get("runtimeArgs")
    if runtime_args is not None and (
        not isinstance(runtime_args, list)
        or not all(
            isinstance(argument, str)
            and bool(argument)
            and "\x00" not in argument
            for argument in runtime_args
        )
    ):
        raise _malformed(runtime, "runtimeArgs must be a list of non-empty strings")

    has_path = "path" in metadata
    has_runtime_type = "runtimeType" in metadata
    if not has_path and not has_runtime_type:
        raise _malformed(runtime, "neither path nor runtimeType is present")

    if has_path:
        path = metadata["path"]
        if not isinstance(path, str) or not path.strip() or "\x00" in path:
            raise _malformed(runtime, "path must be a non-empty string")
        executable = path.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
        if executable not in _RUNSC_EXECUTABLES:
            raise GVisorRuntimeValidationError(
                f"gvisor runtime {runtime!r} resolves to non-runsc executable "
                f"{path!r}"
            )

    if has_runtime_type:
        runtime_type = metadata["runtimeType"]
        if runtime_type != _RUNSC_RUNTIME_TYPE:
            raise GVisorRuntimeValidationError(
                f"gvisor runtime {runtime!r} uses non-runsc runtimeType "
                f"{runtime_type!r}"
            )

    if not has_path and runtime_args:
        raise _malformed(
            runtime,
            "runtimeArgs require a path-based runsc registration",
        )


def validate_docker_gvisor_runtime(
    value: object,
    *,
    timeout: float = 5,
) -> str:
    """Return the exact approved runtime name or raise.

    The Docker daemon is queried on every validation so factory construction,
    health, and agent diagnosis all make the same decision from the same
    registered ``path``/``runtimeArgs`` or containerd ``runtimeType`` object.
    This rejects accidental or deceptive aliases but deliberately treats the
    Docker daemon and its reported registry as trusted configuration.
    """
    runtime = _trusted_runtime_name(value)
    result = subprocess.run(
        ["docker", "info", "--format", DOCKER_RUNTIMES_FORMAT],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    try:
        registered = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise _malformed(runtime, "docker info did not return valid JSON") from exc
    _validate_registered_runtime(runtime, registered)
    return runtime


__all__ = [
    "DOCKER_RUNTIMES_FORMAT",
    "GVisorRuntimeValidationError",
    "TRUSTED_GVISOR_RUNTIME_NAMES",
    "validate_docker_gvisor_runtime",
]
