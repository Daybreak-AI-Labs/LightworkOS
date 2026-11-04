"""The decode pre-pass runs under the SDK backend too.

Previously the pre-pass was gated on the builtin backend, so any deployment that
actually installed the agent-shield SDK got ZERO encoding-evasion coverage -- an
``rm -rf /`` hidden in base64 reached the tool sink. The variant scan now goes
through the LOCAL builtin floor regardless of backend, so SDK deployments are
covered without multiplying the SDK's remote calls.
"""
from __future__ import annotations

import base64

from maverick_shield.guard import Shield


class _AllowAllSDK:
    """A fake agent-shield that allows everything (the literal surface form)."""

    def scanInput(self, text):  # noqa: N802 -- mirrors the real SDK's method name
        return type("R", (), {"blocked": False})()

    scanOutput = scanInput


def _sdk_shield() -> Shield:
    s = Shield(profile="balanced", backend="builtin", warn_if_missing=False)
    # Force the SDK backend with a fake that allows the literal surface form, so
    # only the decode floor can catch the hidden payload.
    s.backend = Shield.BACKEND_SDK
    s._sdk = _AllowAllSDK()
    return s


def test_encoded_payload_blocked_under_sdk_backend():
    s = _sdk_shield()
    # Sanity: the SDK allows the literal (gibberish) surface form.
    blob = base64.b64encode(b"rm -rf /").decode()
    assert s.scan_input(blob).allowed is False, "decode floor must catch base64 payload"


def test_clean_text_allowed_under_sdk_backend():
    s = _sdk_shield()
    assert s.scan_input("what's the weather in Paris today?").allowed is True
