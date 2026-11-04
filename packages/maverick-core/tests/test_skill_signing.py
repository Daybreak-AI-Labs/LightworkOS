"""Signed-skill install policy (Ed25519 sig in SKILL.md frontmatter).

A valid signature from a trusted publisher installs; a forged/wrong sig is
rejected; unsigned skills still install when not in require-signed mode and
are rejected when it is set. The keypair is generated per-test (throwaway).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import skills

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519"
)
from cryptography.hazmat.primitives import serialization  # noqa: E402


def _keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub_hex


_NAME = "signed-demo"
_BODY = "# What it does\n\nDo a signed thing."


def _make_skill(
    *,
    sig: str | None = None,
    pubkey: str | None = None,
    purposes: tuple[str, ...] = (),
) -> str:
    front = [
        "---",
        f"name: {_NAME}",
        "triggers:",
        "  - do the signed thing",
        "tools_needed:",
        "  - shell",
    ]
    if purposes:
        front.append("purposes:")
        front.extend(f"  - {purpose}" for purpose in purposes)
    if sig is not None:
        front.append(f"sig: {sig}")
    if pubkey is not None:
        front.append(f"pubkey: {pubkey}")
    front.append("---")
    return "\n".join(front) + "\n\n" + _BODY + "\n"


def _sign(priv: ed25519.Ed25519PrivateKey, *, purposes: tuple[str, ...] = ()) -> str:
    # Sign over exactly what verification recomputes: parse the unsigned skill,
    # then sign its canonical bytes. This stays in lockstep with
    # _canonical_signed_bytes no matter which fields it binds.
    parsed = skills.Skill.parse(_make_skill(purposes=purposes), Path("in.md"))
    return priv.sign(skills._canonical_signed_bytes(parsed)).hex()


def _write_config(tmp_path: Path, monkeypatch, body: str) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


def test_valid_signature_from_trusted_pubkey_installs(tmp_path, monkeypatch):
    priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{pub_hex}"]\n')
    content = _make_skill(sig=_sign(priv), pubkey=pub_hex)

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    s = skills.install_skill(str(src), skills_dir=skills_dir)

    assert s.name == _NAME
    assert (skills_dir / f"{_NAME}.md").exists()


def test_purpose_tampering_is_rejected(tmp_path, monkeypatch):
    priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{pub_hex}"]\n')
    sig = _sign(priv, purposes=("audit",))
    content = _make_skill(sig=sig, pubkey=pub_hex, purposes=("finance",))

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    with pytest.raises(ValueError, match="signature does not verify"):
        skills.install_skill(str(src), skills_dir=skills_dir)
    assert not list(skills_dir.glob("*.md"))


def test_purpose_removal_is_rejected(tmp_path, monkeypatch):
    priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{pub_hex}"]\n')
    sig = _sign(priv, purposes=("audit",))
    content = _make_skill(sig=sig, pubkey=pub_hex)

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    with pytest.raises(ValueError, match="signature does not verify"):
        skills.install_skill(str(src), skills_dir=skills_dir)
    assert not list(skills_dir.glob("*.md"))


def test_forged_signature_is_rejected(tmp_path, monkeypatch):
    priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{pub_hex}"]\n')
    # Tamper one hex nibble of an otherwise-valid signature.
    good = _sign(priv)
    forged = ("f" if good[0] != "f" else "0") + good[1:]
    content = _make_skill(sig=forged, pubkey=pub_hex)

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    with pytest.raises(ValueError, match="signature does not verify"):
        skills.install_skill(str(src), skills_dir=skills_dir)
    assert not list(skills_dir.glob("*.md"))


def test_untrusted_publisher_is_rejected(tmp_path, monkeypatch):
    # Signature is valid, but signed by a key not in trusted_pubkeys.
    signer_priv, _signer_pub = _keypair()
    _other_priv, other_pub = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{other_pub}"]\n')
    content = _make_skill(
        sig=_sign(signer_priv),
        pubkey=signer_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex(),
    )

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    with pytest.raises(ValueError, match="untrusted publisher"):
        skills.install_skill(str(src), skills_dir=skills_dir)


def test_unsigned_installs_when_not_require_signed(tmp_path, monkeypatch):
    # No [skills] config at all -> default behavior, unsigned ok.
    _write_config(tmp_path, monkeypatch, "")
    content = _make_skill()  # no sig/pubkey

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    s = skills.install_skill(str(src), skills_dir=skills_dir)
    assert s.name == _NAME
    assert (skills_dir / f"{_NAME}.md").exists()


def test_unsigned_rejected_when_require_signed(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, "[skills]\nrequire_signed = true\n")
    content = _make_skill()  # no sig/pubkey

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    with pytest.raises(ValueError, match="require_signed"):
        skills.install_skill(str(src), skills_dir=skills_dir)
    assert not list(skills_dir.glob("*.md"))


def test_present_but_empty_sig_rejected_as_malformed(tmp_path, monkeypatch):
    # A `sig:`/`pubkey:` key present with an empty value must NOT silently
    # downgrade to "unsigned" and install under the default require_signed=False;
    # a skill claiming to be signed must verify or be rejected as malformed.
    _write_config(tmp_path, monkeypatch, "")  # default: unsigned allowed
    content = _make_skill(sig="", pubkey="")  # keys present, values blank

    src = tmp_path / "in.md"
    src.write_text(content, encoding="utf-8")
    skills_dir = tmp_path / "skills"
    with pytest.raises(ValueError, match="malformed"):
        skills.install_skill(str(src), skills_dir=skills_dir)
    assert not list(skills_dir.glob("*.md"))
