"""Signed-skill policy must fail closed when verification support is absent."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import skills
from maverick.audit import signing

_NAME = "fake-signed-demo"
_BODY = "# What it does\n\nDo a fake signed thing."


def _make_skill(*, sig: str | None = None, pubkey: str | None = None) -> str:
    front = [
        "---",
        f"name: {_NAME}",
        "triggers:",
        "  - do the fake signed thing",
        "tools_needed:",
        "  - shell",
    ]
    if sig is not None:
        front.append(f"sig: {sig}")
    if pubkey is not None:
        front.append(f"pubkey: {pubkey}")
    front.append("---")
    return "\n".join(front) + "\n\n" + _BODY + "\n"


def _write_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


def test_fake_signed_skill_rejected_when_crypto_unavailable(tmp_path, monkeypatch):
    _write_config(
        tmp_path,
        monkeypatch,
        '[skills]\ntrusted_pubkeys = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]\nrequire_signed = true\n',
    )
    monkeypatch.setattr(signing, "_have_crypto", lambda: False)
    content = _make_skill(
        sig="deadbeef",
        pubkey="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"

    with pytest.raises(ValueError, match="cryptography is required"):
        skills.install_skill(str(src), skills_dir=skills_dir)
    assert not list(skills_dir.glob("*.md"))


def test_unsigned_skill_without_policy_still_installs_when_crypto_unavailable(
    tmp_path, monkeypatch
):
    _write_config(tmp_path, monkeypatch, "")
    monkeypatch.setattr(signing, "_have_crypto", lambda: False)
    content = _make_skill()

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"

    s = skills.install_skill(str(src), skills_dir=skills_dir)
    assert s.name == _NAME
    assert (skills_dir / f"{_NAME}.md").exists()
