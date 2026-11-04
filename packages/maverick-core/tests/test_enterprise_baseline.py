"""The hardening guide's *Recommended enterprise baseline* must actually turn
on every control it claims.

This pins ``docs/security-hardening.md`` to kernel behaviour: we extract the
baseline TOML straight from the guide, write it as the config, and assert each
kernel reader reports its control enabled. If the documented baseline ever
drifts from what the kernel reads (a renamed key, a moved section), this fails
instead of silently shipping a guide that promises a posture it can't deliver.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# packages/maverick-core/tests/<this> -> repo root is parents[3].
_DOC = Path(__file__).resolve().parents[3] / "docs" / "security-hardening.md"


def _baseline_toml() -> str:
    """The first ```toml block under the baseline heading, or skip."""
    if not _DOC.exists():
        pytest.skip(f"hardening guide not found at {_DOC}")
    parts = _DOC.read_text(encoding="utf-8").split(
        "## Recommended enterprise baseline", 1
    )
    if len(parts) != 2:
        pytest.skip("baseline section not found in hardening guide")
    m = re.search(r"```toml\n(.*?)```", parts[1], re.DOTALL)
    if not m:
        pytest.skip("baseline toml block not found")
    return m.group(1)


def test_documented_enterprise_baseline_enables_every_control(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # Exercise the config file, not ambient env overrides.
    for env in (
        "MAVERICK_ENTERPRISE", "MAVERICK_ENFORCE_CAPABILITIES",
        "MAVERICK_TENANT_BY_USER", "MAVERICK_QUOTA_ENFORCE",
        "MAVERICK_AUDIT_SIGN", "MAVERICK_ENCRYPT_AT_REST",
        "MAVERICK_OIDC_ENABLED",
    ):
        monkeypatch.delenv(env, raising=False)

    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.toml").write_text(_baseline_toml(), encoding="utf-8")

    # Each reader resolves the control independently from the same config file.
    from maverick.audit.writer import _resolve_signing
    from maverick.capability import capability_enforced
    from maverick.crypto_at_rest import at_rest_enabled
    from maverick.enterprise import enterprise_enabled
    from maverick.oidc import oidc_enabled
    from maverick.paths import tenant_by_user_enabled
    from maverick.quotas import quotas_enforced

    assert enterprise_enabled() is True          # [enterprise] mode
    assert capability_enforced() is True         # [capabilities] enforce
    assert tenant_by_user_enabled() is True      # [tenancy] by_user
    assert quotas_enforced() is True             # [quotas] enforce
    assert at_rest_enabled() is True             # [encryption] at_rest
    assert _resolve_signing(None) is True        # [audit] sign
    assert oidc_enabled() is True                # [auth.oidc] enabled
