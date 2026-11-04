"""Black-box tests for the downloadable governance evidence verifier."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    REPO_ROOT / "benchmarks" / "results" / "governance-frontier-v1"
)
VERIFIER = EVIDENCE / "verify_manifest.py"
MANIFEST = EVIDENCE / "measured-manifest.json"
TRUSTED_KEY = EVIDENCE / "trusted-publisher.pub"


def _verify(
    verifier: Path,
    manifest: Path,
    trusted_key: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(verifier),
            str(manifest),
            str(trusted_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_public_verifier_succeeds_without_the_lightwork_package(tmp_path):
    verifier = shutil.copy2(VERIFIER, tmp_path / VERIFIER.name)
    manifest = shutil.copy2(MANIFEST, tmp_path / MANIFEST.name)
    trusted_key = shutil.copy2(TRUSTED_KEY, tmp_path / TRUSTED_KEY.name)
    poison = tmp_path / "maverick"
    poison.mkdir()
    (poison / "__init__.py").write_text(
        "raise AssertionError('Lightwork source was imported')\n",
        encoding="utf-8",
    )

    result = _verify(verifier, manifest, trusted_key)

    assert result.returncode == 0, result.stderr
    assert "VERIFIED: Ed25519 signature" in result.stdout
    assert "Source-binding digests were not recomputed" in result.stdout


def test_public_verifier_rejects_signed_payload_tampering(tmp_path):
    document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    document["config_digest"] = "0" * 64
    manifest = tmp_path / "tampered.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    result = _verify(VERIFIER, manifest, TRUSTED_KEY)

    assert result.returncode == 1
    assert "signature does not verify" in result.stderr


def test_public_verifier_rejects_the_wrong_trusted_key(tmp_path):
    wrong_key = tmp_path / "wrong.pub"
    wrong_key.write_text("00" * 32 + "\n", encoding="ascii")

    result = _verify(VERIFIER, MANIFEST, wrong_key)

    assert result.returncode == 1
    assert "does not match the separately trusted key" in result.stderr


def test_public_verifier_rejects_duplicate_object_keys(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"signature": {}, "signature": {}}\n',
        encoding="utf-8",
    )

    result = _verify(VERIFIER, duplicate, TRUSTED_KEY)

    assert result.returncode == 1
    assert "duplicate JSON object key" in result.stderr


def test_public_verifier_rejects_nonfinite_json_numbers(tmp_path):
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text(
        '{"value": NaN, "signature": {}}\n',
        encoding="utf-8",
    )

    result = _verify(VERIFIER, nonfinite, TRUSTED_KEY)

    assert result.returncode == 1
    assert "non-finite JSON number is not permitted" in result.stderr
