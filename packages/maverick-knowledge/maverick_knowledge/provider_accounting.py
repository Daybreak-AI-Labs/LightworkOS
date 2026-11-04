"""Optional bridge from standalone knowledge transports to core cost receipts.

``maverick-knowledge`` remains usable without ``maverick-core``. When core is
present, every hosted transport call inherits the current tenant/work-item and
is admitted through the durable provider-cost authority before dispatch.
"""

from __future__ import annotations

import importlib
import re
import uuid
from contextlib import contextmanager


def _cost_cap():
    try:
        provider_cost_cap = importlib.import_module("maverick.provider_cost_cap")
    except ModuleNotFoundError as exc:
        if exc.name in {"maverick", "maverick.provider_cost_cap"}:
            return None
        raise
    required = (
        "current_provider_operation",
        "metered_provider_call",
        "provider_operation_scope",
    )
    if not all(callable(getattr(provider_cost_cap, name, None)) for name in required):
        # Preserve standalone compatibility when an unrelated or older
        # ``maverick`` distribution is importable but lacks this bridge.
        return None
    return provider_cost_cap


def _label(value: object, *, fallback: str) -> str:
    raw = str(value or "").strip()
    if not raw or any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raw = fallback
    if len(raw) <= 256:
        return raw
    # Preserve a recognizable prefix without accepting unbounded provider data.
    import hashlib

    suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{raw[:238]}:{suffix}"


def _prefix(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-.:_")
    return (normalized or "knowledge")[:150]


@contextmanager
def operation_scope(*, category: str, service: object, operation: str):
    """Bind one knowledge operation when core accounting is installed."""

    cap = _cost_cap()
    if cap is None:
        yield None
        return
    with cap.provider_operation_scope(
        operation_id=f"{_prefix(operation)}-{uuid.uuid4().hex}",
        category=category,
        service=_label(service, fallback="knowledge"),
    ) as context:
        yield context


def metered_call(
    provider: str,
    callback,
    *,
    service: object,
    default_category: str = "other",
    attempt_no: int | None = None,
):
    """Run one synchronous hosted call with a durable unknown-cost receipt."""

    cap = _cost_cap()
    if cap is None:
        return callback()
    if cap.current_provider_operation() is None:
        with operation_scope(
            category=default_category,
            service=service,
            operation=f"knowledge-{provider}",
        ):
            return cap.metered_provider_call(
                provider,
                callback,
                service=_label(service, fallback=f"knowledge-{provider}"),
                attempt_no=attempt_no,
            )
    return cap.metered_provider_call(
        provider,
        callback,
        service=_label(service, fallback=f"knowledge-{provider}"),
        attempt_no=attempt_no,
    )


@contextmanager
def metered_operation(
    provider: str,
    *,
    category: str,
    service: object,
    operation: str,
):
    """Yield a call meter sharing one operation id and ordered attempts."""

    attempt_no = 0

    def dispatch(callback):
        nonlocal attempt_no
        attempt_no += 1
        return metered_call(
            provider,
            callback,
            service=service,
            default_category=category,
            attempt_no=attempt_no,
        )

    with operation_scope(category=category, service=service, operation=operation):
        yield dispatch


__all__ = ["metered_call", "metered_operation", "operation_scope"]
