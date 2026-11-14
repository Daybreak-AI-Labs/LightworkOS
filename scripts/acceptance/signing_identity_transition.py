"""Exercise the real Tauri signer with disposable distinct identities.

Synthetic bytes only: no MSI execution, certificate-store changes or release
publication. Private keys are deleted before any public evidence is written.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from maverick import release_identity_transition as bridge
from maverick.file_lock import ensure_private_directory
from maverick.windows_installer_verification import verify_minisign


def exercise(cli: Path):
    node = shutil.which("node")
    if node is None or not cli.is_file():
        raise ValueError("A local Node runtime and installed Tauri CLI are required")
    producer = json.loads(cli.with_name("package.json").read_text(encoding="utf-8"))["version"]
    def command(*args):
        result = subprocess.run([node, str(cli), *args], capture_output=True, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError("The disposable Tauri signature command failed; no private output is published")
    with tempfile.TemporaryDirectory(prefix="lightwork-bridge-signers-") as temporary:
        root = ensure_private_directory(Path(temporary))
        keys = {}
        for name in ("old", "new", "unrelated"):
            path = root / (name + ".key")
            command("signer", "generate", "--ci", "--password", "synthetic-fixture-only", "--write-keys", str(path))
            keys[name] = (path, path.with_suffix(".key.pub").read_text(encoding="utf-8").strip())
        def sign(path, name):
            command("signer", "sign", "--private-key-path", str(keys[name][0]), "--password", "synthetic-fixture-only", str(path))
            return Path(str(path) + ".sig").read_text(encoding="utf-8").strip()
        payload = b"Synthetic identity bridge fixture; not an installable MSI.\n"
        artifact = root / "fixture-bridge.msi"
        artifact.write_bytes(payload)
        artifact_signature = sign(artifact, "old")
        now = int(time.time())
        policy = {"schema": 1, "id": "d" * 32, "issued_at": now - 30, "expires_at": now + 600,
                  "from": {"version": "1.0.0", "runtime_sha256": hashlib.sha256(b"old-runtime").hexdigest(), "native_sha256": hashlib.sha256(b"old-native").hexdigest(),
                           "publisher_thumbprint": "A" * 40, "public_key": keys["old"][1]},
                  "to": {"version": "1.0.1", "runtime_sha256": hashlib.sha256(b"new-runtime").hexdigest(), "native_sha256": hashlib.sha256(b"new-native").hexdigest(),
                         "publisher_thumbprint": "B" * 40, "public_key": keys["new"][1]},
                  "new_installer_sha256": hashlib.sha256(payload).hexdigest(), "rollback": "exact-retained-pair-only"}
        document = root / "policy.json"
        document.write_text(bridge.canonical(policy), encoding="utf-8", newline="")
        envelope = {"policy": policy, "from_signature": sign(document, "old"), "to_signature": sign(document, "new")}
        if not (bridge.verify(envelope, installed=policy["from"]) == envelope):
            raise RuntimeError("Identity bridge verification failed")
        if not (verify_minisign(artifact, keys["old"][1], artifact_signature) == policy["new_installer_sha256"]):
            raise RuntimeError("Artifact signature verification failed")
        unrelated = {**envelope, "to_signature": sign(document, "unrelated")}
        try:
            bridge.verify(unrelated, installed=policy["from"])
        except bridge.IdentityTransitionError:
            pass
        else:
            raise AssertionError("Unrelated proposed key was accepted")
        retained = {"producer": "@tauri-apps/cli " + producer, "scope": "Synthetic cryptographic interoperability; no Authenticode or MSI acceptance",
                    "envelope": envelope, "payload_base64": base64.b64encode(payload).decode(), "artifact_signature": artifact_signature,
                    "unrelated_signature": unrelated["to_signature"], "private_keys_retained": False}
    return retained


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tauri-cli", required=True, type=Path)
    parser.add_argument("--fixture-output", type=Path)
    args = parser.parse_args()
    evidence = exercise(args.tauri_cli.resolve())
    if args.fixture_output:
        args.fixture_output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"producer": evidence["producer"], "dual_signature_verified": True,
                      "cross_signed_artifact_verified": True, "unrelated_key_rejected": True,
                      "private_keys_deleted": True, "authenticode_tested": False, "msi_executed": False}))


if __name__ == "__main__":
    main()
