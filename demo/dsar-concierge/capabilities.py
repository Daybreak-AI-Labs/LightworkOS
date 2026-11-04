"""What this build of the DSAR Concierge can do — the capability seam.

STANDALONE (env ``DSAR_STANDALONE=1`` or the platform simply not importable)
forces the platform-only capabilities
off. The agent itself — intake, the message detector, identity
verification, the statutory clock and aging, package assembly, the
non-destructive erasure handoff, and the counted value ledger — always
works. Lightwork adds the governed registers (the request mirrors into the
privacy workspace), the signed audit chain, and real subject-data exports
wired to the platform's erasure machinery.
"""
from __future__ import annotations

import os


def _platform_present() -> bool:
    try:
        import maverick  # noqa: F401
        return True
    except Exception:
        return False


STANDALONE = (os.environ.get("DSAR_STANDALONE") == "1"
              or not _platform_present())

CAPS = {
    # The agent — always on.
    "intake_forms": True,
    "message_detector": True,
    "identity_verify": True,
    "sla_clock": True,
    "package_assembly": True,
    "erasure_handoff": True,
    "value_ledger": True,
    # Lightwork adds — off standalone, by design.
    "privacy_workspace_sync": not STANDALONE,
    "signed_audit": not STANDALONE,
    "platform_exports": not STANDALONE,
}

_LABELS = {
    "intake_forms": "Subject request intake (web form + webhook)",
    "message_detector": "Deterministic message triage (kind + subject)",
    "identity_verify": "Identity verification loop (emailed token)",
    "sla_clock": "Statutory clock + SLA aging bands",
    "package_assembly": "Access/portability package assembly",
    "erasure_handoff": "Non-destructive erasure handoff",
    "value_ledger": "Counted value ledger",
    "privacy_workspace_sync": "Mirror into the Lightwork privacy workspace",
    "signed_audit": "Ed25519-signed audit chain",
    "platform_exports": "Real subject-data exports (platform machinery)",
}

def caps_summary() -> dict:
    active = [_LABELS[k] for k, on in CAPS.items() if on]
    gated = [_LABELS[k] for k, on in CAPS.items() if not on]
    return {
        "standalone": STANDALONE,
        "mode": "Standalone agent" if STANDALONE else "Lightwork platform",
        "active": active,
        "gated": gated,
    }
