"""Write the update feed only after independent signature verification.

This build-host utility does not sign, verify certificates, publish, or execute
an installer. The protected workflow verifies both signatures before calling it.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def feed(inventory: dict, signature: str, url_template: str) -> dict:
    version = inventory.get("version", "")
    if (inventory.get("schema") != "lightwork.windows-customer-build.v1"
            or inventory.get("acceptance_fixture") is not False
            or inventory.get("complete_release_cohort") is not True
            or not re.fullmatch(r"\d+\.\d+\.\d+", version)):
        raise ValueError("Only a complete release candidate may produce update metadata")
    if url_template.count("{version}") != 1:
        raise ValueError("Installer address must contain one immutable {version} placeholder")
    url = url_template.replace("{version}", version)
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Installer address must have a valid HTTPS port") from exc
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.fragment or len(url) > 4096
            or any(ord(char) <= 32 for char in url) or "{" in url or "}" in url
            or port == 0 or "\\" in url):
        raise ValueError("Installer address must be HTTPS without credentials or fragments")
    try:
        decoded = base64.b64decode(signature, validate=True).decode("ascii").splitlines()
        if (len(decoded) != 4 or not decoded[0].startswith("untrusted comment:")
                or not decoded[2].startswith("trusted comment:")
                or len(base64.b64decode(decoded[1], validate=True)) != 74
                or len(base64.b64decode(decoded[3], validate=True)) != 64):
            raise ValueError
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Expected the verified Tauri installer signature") from exc
    runtime_sha256 = (inventory.get("runtime") or {}).get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", runtime_sha256):
        raise ValueError("The release requires its exact runtime SHA-256 identity")
    return {"version": version, "runtime_sha256": runtime_sha256, "notes": "Lightwork " + version,
            "pub_date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "platforms": {"windows-x86_64": {"signature": signature, "url": url}}}


def write_feed(directory: Path, url_template: str, *, identity_transition: Path | None = None,
               transition_source_key: Path | None = None, transition_target_native: Path | None = None) -> None:
    """Check immutable identity before changing the visible latest pointer."""
    inventory = json.loads((directory / "runtime-inventory.json").read_text(encoding="utf-8"))
    signature = (directory / "Lightwork.msi.sig").read_text(encoding="utf-8").strip()
    content = feed(inventory, signature, url_template)
    digest = hashlib.sha256((directory / "Lightwork.msi").read_bytes()).hexdigest()
    content["installer_sha256"] = digest
    if identity_transition is not None:
        from maverick import release_identity_transition as bridge
        from maverick.windows_installer_verification import verify_minisign

        if transition_source_key is None or transition_target_native is None:
            raise ValueError("A bridge feed requires the retained source public key and exact built target native executable")
        if identity_transition.stat().st_size > bridge.MAX_ENVELOPE_BYTES or transition_source_key.stat().st_size > 4096:
            raise ValueError("The bridge policy or source key exceeds its size limit")
        envelope = bridge.parse(identity_transition.read_text(encoding="utf-8"))
        installed = {**envelope["policy"]["from"], "public_key": transition_source_key.read_text(encoding="utf-8").strip()}
        envelope = bridge.verify(envelope, installed=installed)
        target = envelope["policy"]["to"]
        if (target["version"] != content["version"] or target["runtime_sha256"] != content["runtime_sha256"]
                or envelope["policy"]["new_installer_sha256"] != digest
                or target["native_sha256"] != hashlib.sha256(transition_target_native.read_bytes()).hexdigest()
                or target["public_key"] != (directory / "updater.pub").read_text(encoding="utf-8").strip()):
            raise ValueError("The bridge policy does not match the exact staged target release")
        # A bridge offer on the old channel must remain downloadable by the
        # installed old key. The target build itself compiles the reviewed new
        # key; its ordinary new channel carries a separately signed manifest.
        verify_minisign(directory / "Lightwork.msi", installed["public_key"], signature)
        content["identity_transition"] = envelope
    elif transition_source_key is not None or transition_target_native is not None:
        raise ValueError("Select the signed identity transition before its verification inputs")
    versions = directory / "versions"
    versions.mkdir(exist_ok=True)
    # Publish this immutable address alongside latest.json. Repair and retained
    # pre-upgrade installers must remain available after the channel advances.
    versioned = versions / (content["version"] + ".json")
    if versioned.exists():
        existing = json.loads(versioned.read_text(encoding="utf-8"))
        if {key: value for key, value in existing.items() if key != "pub_date"} != {key: value for key, value in content.items() if key != "pub_date"}:
            raise ValueError("Refusing to replace an immutable release manifest")
        content["pub_date"] = existing["pub_date"]
    serialized = json.dumps(content, indent=2) + "\n"
    if not versioned.exists():
        # Exclusive creation protects immutable releases from concurrent writers.
        with versioned.open("x", encoding="utf-8", newline="\n") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
    import tempfile
    for name, value in (("SHA256SUMS", f"{digest}  Lightwork.msi\n"), ("latest.json", serialized)):
        descriptor, temporary = tempfile.mkstemp(prefix=".release-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, directory / name)
        finally:
            Path(temporary).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--installer-url-template", required=True)
    parser.add_argument("--identity-transition", type=Path)
    parser.add_argument("--transition-source-key", type=Path)
    parser.add_argument("--transition-target-native", type=Path)
    args = parser.parse_args()
    write_feed(args.directory, args.installer_url_template, identity_transition=args.identity_transition,
               transition_source_key=args.transition_source_key, transition_target_native=args.transition_target_native)


if __name__ == "__main__":
    main()
