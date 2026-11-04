"""install_from_catalog: resolve by name, verify hash, then install."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from maverick import catalog, skills

_BODY = """---
name: summarize-url
triggers: ["summarize this url"]
tools_needed: ["http_fetch"]
---
# Summarize a URL

Fetch with http_fetch, write 3 sentences.
"""
_SHA = hashlib.sha256(_BODY.encode()).hexdigest()


def _entry(**over):
    d = {
        "name": "summarize-url", "version": "1.0.0",
        "summary": "x", "source": "gh:org/repo:SKILL.md",
        "sha256": _SHA, "author": "org", "verified": True,
    }
    d.update(over)
    return catalog.CatalogEntry.from_dict("skills", d)


def test_install_from_catalog_happy_path(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(catalog, "resolve", lambda name, kind, indexes=None: _entry())
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: _BODY.encode())
    monkeypatch.setattr(skills, "_verify_skill_signature", lambda parsed, **kw: kw["require_signature"])
    s = skills.install_from_catalog("summarize-url", skills_dir=tmp_path)
    assert s.name == "summarize-url"
    assert (tmp_path / "summarize-url.md").exists()


# Regression: the integrity pin must be verified over the RAW fetched bytes,
# not a UTF-8-replace-decoded str. A published SKILL.md whose bytes are not
# UTF-8-clean is pinned by its curator over the real file bytes; hashing the
# lossily-decoded str (U+FFFD substitution) would reject the authentic file.
_NON_UTF8_BODY_BYTES = _BODY.encode() + b"\xff trailing non-utf8\n"
_NON_UTF8_SHA = hashlib.sha256(_NON_UTF8_BODY_BYTES).hexdigest()


def test_verify_sha256_hashes_raw_bytes_not_lossy_str():
    # The bytes pin matches when verifying over bytes...
    assert catalog.verify_sha256(_NON_UTF8_BODY_BYTES, _NON_UTF8_SHA) is True
    # ...but NOT when the bytes are first lossily decoded to str (the bug).
    lossy = _NON_UTF8_BODY_BYTES.decode("utf-8", errors="replace")
    assert catalog.verify_sha256(lossy, _NON_UTF8_SHA) is False


def test_install_from_catalog_accepts_non_utf8_clean_pinned_bytes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        catalog, "resolve",
        lambda name, kind, indexes=None: _entry(sha256=_NON_UTF8_SHA))
    monkeypatch.setattr(
        skills, "_fetch_skill_source_bytes", lambda source: _NON_UTF8_BODY_BYTES)
    monkeypatch.setattr(skills, "_verify_skill_signature", lambda parsed, **kw: kw["require_signature"])
    # The pin is checked against the raw wire bytes; checking the
    # UTF-8-replaced str would raise "content hash mismatch".
    s = skills.install_from_catalog("summarize-url", skills_dir=tmp_path)
    assert s.name == "summarize-url"
    assert (tmp_path / "summarize-url.md").exists()


def test_unsigned_catalog_skill_is_refused_without_trusted_publisher(monkeypatch, tmp_path):
    monkeypatch.setattr(catalog, "resolve", lambda name, kind, indexes=None: _entry())
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: _BODY.encode())
    with pytest.raises(ValueError):
        skills.install_from_catalog("summarize-url", skills_dir=tmp_path)
    assert not list(tmp_path.glob("*.md"))


def test_install_from_catalog_unknown_name(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(catalog, "resolve", lambda name, kind, indexes=None: None)
    with pytest.raises(ValueError, match="no catalog skill"):
        skills.install_from_catalog("nope", skills_dir=tmp_path)


def test_install_from_catalog_rejects_hash_mismatch(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(catalog, "resolve", lambda name, kind, indexes=None: _entry())
    # Source returns tampered content that won't match the pinned sha.
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: b"TAMPERED")
    with pytest.raises(ValueError, match="hash mismatch"):
        skills.install_from_catalog("summarize-url", skills_dir=tmp_path)
    # Nothing written.
    assert not list(tmp_path.glob("*.md"))


def test_install_from_catalog_rejects_unpinned_entry(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(catalog, "resolve",
                        lambda name, kind, indexes=None: _entry(sha256=""))
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: _BODY.encode())
    with pytest.raises(ValueError, match="hash mismatch"):
        skills.install_from_catalog("summarize-url", skills_dir=tmp_path)


def test_fetch_skill_source_rejects_local_path():
    with pytest.raises(ValueError, match="gh: or https:"):
        skills._fetch_skill_source("/etc/passwd")


def test_fetch_skill_source_rejects_http():
    with pytest.raises(ValueError):
        skills._fetch_skill_source("http://insecure/SKILL.md")


def test_example_index_sha_matches_committed_skill():
    """The committed example index must pin the real hash of its skill —
    catches drift if someone edits the example SKILL.md without updating
    the index."""
    import json
    root = Path(__file__).resolve().parents[3]
    idx_path = root / "docs" / "specs" / "catalog-example" / "skills" / "index.json"
    skill_path = root / "docs" / "specs" / "catalog-example" / "skills" / "summarize-url" / "SKILL.md"
    if not idx_path.exists() or not skill_path.exists():
        pytest.skip("example catalog not present")
    index = json.loads(idx_path.read_text())
    body = skill_path.read_text()
    pinned = index["entries"][0]["sha256"]
    actual = hashlib.sha256(body.encode()).hexdigest()
    assert pinned == actual, "example index sha256 drifted from the example SKILL.md"


# --- Supply-chain authenticity: catalog install resolves to a skill
# whose Ed25519 signature verifies against a trusted publisher; sha256 alone is
# integrity-in-transit only (same unauthenticated host serves bytes + hash). ---

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519"
)
from cryptography.hazmat.primitives import serialization  # noqa: E402


def _keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub_hex


def _signed_body(priv, pub_hex: str) -> str:
    """Build a SKILL.md signed over the canonical bytes (matches verifier)."""
    unsigned = (
        "---\n"
        "name: summarize-url\n"
        "triggers:\n"
        "  - summarize this url\n"
        "tools_needed:\n"
        "  - http_fetch\n"
        "---\n"
        "# Summarize a URL\n\nFetch with http_fetch, write 3 sentences.\n"
    )
    parsed = skills.Skill.parse(unsigned, Path("in.md"))
    sig = priv.sign(skills._canonical_signed_bytes(parsed)).hex()
    return (
        "---\n"
        "name: summarize-url\n"
        "triggers:\n"
        "  - summarize this url\n"
        "tools_needed:\n"
        "  - http_fetch\n"
        f"sig: {sig}\n"
        f"pubkey: {pub_hex}\n"
        "---\n"
        "# Summarize a URL\n\nFetch with http_fetch, write 3 sentences.\n"
    )


def _write_config(tmp_path, monkeypatch, body: str) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


def _install_content(monkeypatch, tmp_path, content: str) -> skills.Skill:
    sha = hashlib.sha256(content.encode()).hexdigest()
    monkeypatch.setattr(catalog, "resolve",
                        lambda name, kind, indexes=None: _entry(sha256=sha))
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: content.encode())
    return skills.install_from_catalog("summarize-url", skills_dir=tmp_path / "skills")


def test_catalog_trusted_pubkeys_accepts_signed_and_reports_verified(tmp_path, monkeypatch):
    priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{pub_hex}"]\n')
    s = _install_content(monkeypatch, tmp_path, _signed_body(priv, pub_hex))
    assert s.name == "summarize-url"
    assert s.verified is True


def test_catalog_trusted_pubkeys_rejects_unsigned(tmp_path, monkeypatch):
    _priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{pub_hex}"]\n')
    # _BODY is unsigned. With a trust anchor configured, an unsigned catalog
    # skill must be rejected (require_signed implied for the configured anchor).
    with pytest.raises(ValueError, match="sig"):
        _install_content(monkeypatch, tmp_path, _BODY)
    assert not list((tmp_path / "skills").glob("*.md"))


def test_catalog_trusted_pubkeys_rejects_wrong_key(tmp_path, monkeypatch):
    signer_priv, _signer_pub = _keypair()
    _other_priv, other_pub = _keypair()
    # Signed by signer_priv but only other_pub is trusted.
    _write_config(tmp_path, monkeypatch, f'[skills]\ntrusted_pubkeys = ["{other_pub}"]\n')
    signer_pub = signer_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    with pytest.raises(ValueError, match="untrusted publisher"):
        _install_content(monkeypatch, tmp_path, _signed_body(signer_priv, signer_pub))
    assert not list((tmp_path / "skills").glob("*.md"))


def test_catalog_without_trust_rejects_unsigned_content(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, "")
    with pytest.raises(ValueError, match="sig|trusted_pubkeys"):
        _install_content(monkeypatch, tmp_path, _BODY)


def test_caller_can_force_signature_when_manual_tofu_is_enabled(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, "")
    monkeypatch.setattr(catalog, "resolve", lambda *args, **kwargs: _entry())
    monkeypatch.setattr(
        skills,
        "_fetch_skill_source_bytes",
        lambda source: _BODY.encode(),
    )
    with pytest.raises(ValueError, match="sig|trusted_pubkeys"):
        skills.install_from_catalog(
            "summarize-url",
            skills_dir=tmp_path / "skills",
            require_signature=True,
        )
    assert not list((tmp_path / "skills").glob("*.md"))


def test_catalog_no_trust_signed_self_asserted_is_not_verified(tmp_path, monkeypatch):
    # A self-signed skill without a trust anchor is not authenticated.
    priv, pub_hex = _keypair()
    _write_config(tmp_path, monkeypatch, "")
    with pytest.raises(ValueError, match="trust anchor"):
        _install_content(monkeypatch, tmp_path, _signed_body(priv, pub_hex))


def test_catalog_require_signed_catalog_forces_signing_with_empty_trust(tmp_path, monkeypatch):
    # require_signed_catalog set, trusted_pubkeys empty -> unsigned rejected.
    _write_config(tmp_path, monkeypatch, "[skills]\nrequire_signed_catalog = true\n")
    with pytest.raises(ValueError, match="sig|trusted_pubkeys"):
        _install_content(monkeypatch, tmp_path, _BODY)
    assert not list((tmp_path / "skills").glob("*.md"))


def test_catalog_require_signed_catalog_via_env(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, "")
    monkeypatch.setenv("MAVERICK_REQUIRE_SIGNED_CATALOG", "1")
    with pytest.raises(ValueError, match="sig|trusted_pubkeys"):
        _install_content(monkeypatch, tmp_path, _BODY)


def test_catalog_present_but_empty_sig_rejected_as_malformed(tmp_path, monkeypatch):
    # A skill that visually claims to be signed (sig:/pubkey: present) but with
    # empty values must be rejected as malformed, NOT installed unsigned.
    _write_config(tmp_path, monkeypatch, "")
    malformed = (
        "---\n"
        "name: summarize-url\n"
        "triggers:\n"
        "  - summarize this url\n"
        "tools_needed:\n"
        "  - http_fetch\n"
        "sig:\n"
        "pubkey:\n"
        "---\n"
        "# Summarize a URL\n\nFetch with http_fetch, write 3 sentences.\n"
    )
    with pytest.raises(ValueError, match="malformed"):
        _install_content(monkeypatch, tmp_path, malformed)
    assert not list((tmp_path / "skills").glob("*.md"))
