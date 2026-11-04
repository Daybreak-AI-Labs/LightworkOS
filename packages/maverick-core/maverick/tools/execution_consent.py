"""One approval policy for model-directed process and write execution tools."""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..approval_cards import digest
from ..safety import require_operation_consent
from ..sandbox.local import LocalBackend


def execution_target(sandbox: object | None) -> dict[str, str]:
    backend = type(sandbox)
    if sandbox is None:
        isolation = "none (host subprocess)"
    elif isinstance(sandbox, LocalBackend):
        isolation = "local host execution"
    else:
        isolation = "configured sandbox"
    return {
        "backend": f"{backend.__module__}.{backend.__qualname__}",
        "workdir": str(Path(getattr(sandbox, "workdir", Path.cwd())).resolve()),
        "isolation": isolation,
    }


def file_version(path: Path) -> dict[str, str]:
    """Bind reviewed source bytes, including a missing-to-present transition."""
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
        value = hasher.hexdigest()
    except FileNotFoundError:
        value = "missing"
    return {"path": str(path.resolve()), "sha256": value}


def request_execution_consent(
    action: str,
    *,
    target_provider: Callable[[], object],
    parameters: object,
    detail: str,
    effect: str,
    review_items: list[str],
    timeout: float | None = None,
    parameters_provider: Callable[[], object] | None = None,
    input_versions_provider: Callable[[], Mapping[str, Any]] | None = None,
    integrity_note: str = "Exact inputs are committed by SHA-256.",
):
    """Request one fresh, exact, one-use permit; standing grants never apply."""
    target = target_provider()
    return require_operation_consent(
        action,
        risk="high",
        scope=f"workspace:{target['workdir']}",
        detail=detail,
        provenance=action,
        target=target,
        parameters=parameters,
        parameter_summary=review_items + [integrity_note],
        known_effects=[effect],
        unresolved_assumptions=[
            "The operation may modify files or contact services allowed by this environment."
        ],
        before="The reviewed operation has not run.",
        after="The reviewed operation has run once and its effects may persist.",
        irreversible=True,
        target_provider=target_provider,
        parameters_provider=parameters_provider,
        input_versions_provider=input_versions_provider,
        credential_versions_provider=lambda: {
            "kind": "execution-runtime",
            "generation_sha256": digest(target_provider()),
        },
        budget_provider=lambda: {"timeout_seconds": timeout},
        allow_auto_approve=False,
        consult_ledger=False,
    )


__all__ = ["execution_target", "file_version", "request_execution_consent"]
