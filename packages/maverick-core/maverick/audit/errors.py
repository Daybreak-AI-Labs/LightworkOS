"""Audit refusals: the exceptions a caller must not swallow.

An audit write is best-effort by default -- a broken log must never crash a
running agent, and the writer swallows ordinary errors after logging them.

:class:`AuditRefused` is the deliberate exception to that rule. It is raised
only when the audit subsystem *declined* to write because writing would have
broken a guarantee the deployment asserts: a compliance floor that mandates a
signed, tamper-evident chain, or a custody policy that forbids signing with a
co-located key. In both cases the subsystem chose between "write something
weaker than promised" and "refuse", and picked refuse.

A caller that catches this and continues converts that choice into a third
outcome neither branch offered -- **record nothing, and take the action
anyway** -- which is the precise failure the guarantee exists to prevent. The
unrecorded action is the breach; the noisy exception is not.

Both concrete refusals live here as one base so a caller can write::

    try:
        record(...)
    except AuditRefused:
        raise
    except Exception:
        log.warning("audit write failed", exc_info=True)

and cover every refusal the subsystem can raise. A handler written against only
one concrete refusal would silently miss the other, and
:class:`~maverick.audit.signing.OffHostSigningRequiredError` is the one that
fires under the strictest posture the product supports.

``RuntimeError`` remains the base so handlers predating these names keep working.
"""

from __future__ import annotations


class AuditRefused(RuntimeError):
    """The audit subsystem declined to write. Do not proceed with the action.

    Never raised for an incidental failure (disk full, serialization error) --
    those are logged and swallowed. Raised only where continuing would
    falsify a guarantee the deployment has asserted.
    """


__all__ = ["AuditRefused"]
