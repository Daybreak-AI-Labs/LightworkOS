#!/usr/bin/env python3
"""Verify a separately signed exact engineering artifact; never install or publish it.

The public key and expected release identity must come from the release owner,
independently of the downloaded files. No keys are created or changed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

MAX_ARTIFACT_BYTES = 4 * 1024**3
TARGETS = {"aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}


def regular(path: Path, limit: int) -> os.stat_result:
    path = path.absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Artifact verification does not follow symbolic links.")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
        raise ValueError("Select a single bounded regular artifact, signature or manifest file.")
    return info


def sha256(path: Path) -> str:
    before = regular(path, MAX_ARTIFACT_BYTES)
    value = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise ValueError("The selected artifact changed before verification.")
        total = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("Artifact exceeded its size bound while reading.")
            value.update(block)
    after = regular(path, MAX_ARTIFACT_BYTES)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("The selected artifact changed during verification.")
    return value.hexdigest()


def verify(*, manifest: Path, signature: Path, artifact: Path, public_key: str,
           expected_commit: str, expected_version: str, target: str) -> dict:
    if target not in TARGETS or not re.fullmatch(r"[a-f0-9]{40}", expected_commit) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", expected_version):
        raise ValueError("Select an exact supported engineering target, full commit and release version.")
    if not re.fullmatch(r"[A-Za-z0-9+/]{56}", public_key):
        raise ValueError("Supply the owner's independently trusted Minisign public key, not a key from this download.")
    regular(manifest, 65536)
    regular(signature, 16384)
    # Verify immutable private copies so a swapped manifest cannot be parsed
    # after its different predecessor was authenticated.
    with manifest.open("rb") as stream:
        payload = stream.read(65537)
    with signature.open("rb") as stream:
        signature_bytes = stream.read(16385)
    if len(payload) > 65536 or len(signature_bytes) > 16384:
        raise ValueError("Release metadata changed beyond its bound.")
    with tempfile.TemporaryDirectory(prefix="lightwork-artifact-review-") as temporary:
        checked_manifest = Path(temporary) / "release.json"
        checked_signature = Path(temporary) / "release.minisig"
        checked_manifest.write_bytes(payload)
        checked_signature.write_bytes(signature_bytes)
        subprocess.run(["minisign", "-V", "-m", str(checked_manifest), "-x", str(checked_signature), "-P", public_key], check=True, timeout=30, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    row = json.loads(payload)
    if not isinstance(row, dict) or row.get("schema") != "lightwork.signed-engineering-artifact.v1":
        raise ValueError("The authenticated manifest has an unsupported schema.")
    expected = {"repository": "Daybreak-AI-Labs/LightworkOS", "commit": expected_commit, "version": expected_version, "target": target, "support_channel": "engineering", "artifact_filename": artifact.name}
    if any(row.get(key) != value for key, value in expected.items()):
        raise ValueError("The authenticated artifact is not the exact reviewed repository/release/target/channel/file.")
    digest = sha256(artifact)
    size = artifact.stat().st_size
    if not re.fullmatch(r"[a-f0-9]{64}", str(row.get("artifact_sha256", ""))) or row["artifact_sha256"] != digest or type(row.get("size_bytes")) is not int or row["size_bytes"] != size:
        raise ValueError("The selected artifact bytes do not match the signed release manifest.")
    return {"schema": "lightwork.engineering-artifact-verification.v1", **expected, "artifact_sha256": digest, "size_bytes": size, "manifest_sha256": hashlib.sha256(payload).hexdigest(), "signature_verified": True, "platform_signing_verified": False, "customer_qualified": False, "notice": "Exact signed engineering bytes verified. This does not establish Apple notarization, native platform acceptance, a self-contained customer runtime, or customer distribution approval."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "signature", "artifact"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("public-key", "expected-commit", "expected-version", "target"):
        parser.add_argument("--" + name, required=True)
    arguments = vars(parser.parse_args())
    try:
        print(json.dumps(verify(**arguments), indent=2, allow_nan=False))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, "Artifact verification failed: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
