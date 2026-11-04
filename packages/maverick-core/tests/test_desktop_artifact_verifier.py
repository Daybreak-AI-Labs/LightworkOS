"""Engineering artifact identity checks; Minisign process is mocked."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "verify_desktop_artifact.py"
spec = importlib.util.spec_from_file_location("desktop_artifact_verifier", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def bundle(tmp_path):
    artifact = tmp_path / "engineering.tar.gz"
    artifact.write_bytes(b"selected engineering artifact")
    row = {"schema": "lightwork.signed-engineering-artifact.v1", "repository": "Daybreak-AI-Labs/LightworkOS", "commit": "a" * 40, "version": "1.2.3", "target": "aarch64-apple-darwin", "support_channel": "engineering", "artifact_filename": artifact.name, "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "size_bytes": artifact.stat().st_size}
    manifest = tmp_path / "release.json"
    manifest.write_text(json.dumps(row))
    signature = tmp_path / "release.minisig"
    signature.write_text("fake signature")
    return dict(manifest=manifest, signature=signature, artifact=artifact, public_key="A" * 56, expected_commit="a" * 40, expected_version="1.2.3", target="aarch64-apple-darwin")


def test_verified_engineering_bytes_never_claim_customer_or_platform_acceptance(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier.subprocess, "run", lambda *args, **kwargs: None)
    result = verifier.verify(**bundle(tmp_path))
    assert result["signature_verified"] is True
    assert result["customer_qualified"] is False
    assert result["platform_signing_verified"] is False


def test_replaced_artifact_and_wrong_release_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier.subprocess, "run", lambda *args, **kwargs: None)
    arguments = bundle(tmp_path)
    with pytest.raises(ValueError, match="exact reviewed"):
        verifier.verify(**dict(arguments, expected_commit="b" * 40))
    arguments["artifact"].write_bytes(b"changed package")
    with pytest.raises(ValueError, match="selected artifact bytes"):
        verifier.verify(**arguments)
