"""The plugin load gate must honor the CA's *signed* CRL, not just the config
revocation list -- and fail closed on a present-but-tampered CRL."""
from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from maverick import plugins  # noqa: E402
from maverick.plugin_ca import PluginCA  # noqa: E402


@pytest.fixture
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    return tmp_path


def _ca_at_home() -> PluginCA:
    # Default location -- the same one _plugin_signing_policy constructs.
    ca = PluginCA()
    ca.init_root()
    return ca


def _config(root_pub: str, monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"plugins": {"ca_root_pubkey": root_pub,
                                     "require_signing": True}})


def test_ca_revoked_serial_reaches_the_gate(_home, monkeypatch):
    ca = _ca_at_home()
    ca.revoke("SERIAL-COMPROMISED")          # writes the signed CRL
    _config(ca.root_pub(), monkeypatch)
    root, require, revoked = plugins._plugin_signing_policy()
    assert require is True
    assert revoked is not None
    assert "SERIAL-COMPROMISED" in revoked   # CA CRL honored, not just config


def test_fresh_ca_with_no_crl_is_config_only_not_fail_closed(_home, monkeypatch):
    ca = _ca_at_home()                        # never revoked -> no CRL file
    _config(ca.root_pub(), monkeypatch)
    root, require, revoked = plugins._plugin_signing_policy()
    assert revoked == set()                   # not None -> signed plugins can load


def test_tampered_crl_fails_closed(_home, monkeypatch):
    ca = _ca_at_home()
    ca.revoke("SERIAL-X")
    ca._crl_path.write_text("{ not valid json", encoding="utf-8")  # corrupt it
    _config(ca.root_pub(), monkeypatch)
    root, require, revoked = plugins._plugin_signing_policy()
    # A present-but-unverifiable CRL -> revoked=None so verify_artifact refuses
    # EVERY signed plugin (can't prove a cert isn't revoked).
    assert revoked is None
    assert require is True


def test_crl_signed_by_wrong_root_fails_closed(_home, monkeypatch):
    ca = _ca_at_home()
    ca.revoke("SERIAL-Y")
    # Point the gate at a DIFFERENT root pubkey than signed the CRL.
    other = PluginCA(_home / "other-ca")
    other_root = other.init_root()
    _config(other_root, monkeypatch)
    root, require, revoked = plugins._plugin_signing_policy()
    assert revoked is None                    # CRL sig won't verify -> deny all
