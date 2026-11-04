"""Bounded, observable cleanup of container identities owned by a backend."""
from __future__ import annotations

import math
import re
import subprocess
import time
from dataclasses import dataclass

from .local import scrub_env

_NAME = re.compile(r"maverick-[A-Za-z0-9_.-]{1,112}\Z")
CLEANUP_SECONDS = 15.0


@dataclass(frozen=True)
class ContainerCleanup:
    engine: str
    name: str
    removed: bool
    attempts: int
    reason: str

    @property
    def note(self) -> str:
        if self.removed:
            return ""
        return (
            f"; container cleanup failed ({self.reason}); "
            f"{self.engine}:{self.name} may be orphaned"
        )


def _command(args: list[str], deadline: float) -> tuple[bool, str, str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False, "", "cleanup deadline exceeded"
    try:
        result = subprocess.run(
            args, capture_output=True, text=True,
            timeout=min(5.0, remaining), env=scrub_env(),
        )
    except subprocess.TimeoutExpired:
        return False, "", f"{args[1]} timed out"
    except OSError:
        return False, "", f"{args[1]} unavailable"
    # Raw daemon errors can contain paths/credentials; retain only status.
    if result.returncode != 0:
        return False, "", f"{args[1]} exited {result.returncode}"
    return True, result.stdout or "", ""


def cleanup_container(
    name: str, engine: str = "docker", *, timeout: float = CLEANUP_SECONDS,
) -> ContainerCleanup:
    """Attempt removal twice within one deadline; verify an already-absent ID.

    Callers supply only a name they generated for their own container. A failed
    kill does not prevent force removal. A failed removal does not prove absence:
    the engine must successfully enumerate matching names before we accept it.
    """
    if engine not in {"docker", "podman"} or not _NAME.fullmatch(name):
        raise ValueError("cleanup requires a supported engine and owned container name")
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("cleanup timeout must be finite and nonnegative")
    deadline = time.monotonic() + timeout
    reason = "cleanup deadline exceeded"
    attempts = 0
    for _ in range(2):
        if time.monotonic() >= deadline:
            break
        attempts += 1
        _command([engine, "kill", name], deadline)
        removed, _, reason = _command([engine, "rm", "-f", name], deadline)
        if removed:
            return ContainerCleanup(engine, name, True, attempts, "removed")
        listed, names, listing_error = _command(
            [engine, "ps", "-a", "--filter", f"name={name}",
             "--format", "{{.Names}}"], deadline,
        )
        if listed and name not in {line.strip().lstrip("/") for line in names.splitlines()}:
            return ContainerCleanup(engine, name, True, attempts, "already absent")
        if listing_error:
            reason = f"{reason}; {listing_error}"
    return ContainerCleanup(engine, name, False, attempts, reason)
