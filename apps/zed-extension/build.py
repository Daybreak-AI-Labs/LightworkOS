"""Build and bundle an unsigned, locked-source Zed preview; never install or publish."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET = "wasm32-wasip2"
INPUTS = (
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "extension.toml",
    "src/lib.rs", "tasks/maverick.json", "README.md", "BUILDING.md", "build.py",
    "LICENSE", "NOTICE",
)


def output(command: list[str]) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def main() -> None:
    cargo = os.environ.get("LIGHTWORK_CARGO") or shutil.which("cargo")
    rustc = os.environ.get("RUSTC") or shutil.which("rustc")
    if not cargo or not rustc:
        raise SystemExit("Install Rust 1.97.1 with wasm32-wasip2; see BUILDING.md.")
    version = output([rustc, "--version"])
    if not version.startswith("rustc 1.97.1 "):
        raise SystemExit("This preview is pinned to Rust 1.97.1; active compiler: " + version)
    subprocess.run(
        [cargo, "build", "--locked", "--release", "--target", TARGET],
        cwd=ROOT, check=True,
    )
    metadata = json.loads(output([cargo, "metadata", "--locked", "--no-deps", "--format-version=1"]))
    artifact = Path(metadata["target_directory"]) / TARGET / "release/maverick_zed_extension.wasm"
    binary = artifact.read_bytes()
    if binary[:8] != b"\x00asm\x0d\x00\x01\x00":
        raise SystemExit("Build did not produce the expected WASI component; no bundle written.")
    files = {name: (ROOT / name).read_bytes() for name in INPUTS}
    files["extension.wasm"] = binary
    manifest = {
        "kind": "unsigned-preview", "installed_host_qualified": False,
        "rustc": version, "cargo": output([cargo, "--version"]), "target": TARGET,
        "inputs_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    files["BUILD-MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    directory = ROOT / "build"
    directory.mkdir(exist_ok=True)
    bundle = directory / "lightwork-zed-preview.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo("lightwork-zed/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    checksum = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (directory / (bundle.name + ".sha256")).write_text(checksum + "  " + bundle.name + "\n", encoding="utf-8")
    print(str(bundle))
    print("SHA256 " + checksum)
    print("Unsigned preview only. No Zed install, Lightwork CLI invocation or publication performed.")


if __name__ == "__main__":
    main()
