"""Bounded diagnostics from disposable acceptance fixtures, never state archives."""
from __future__ import annotations

import argparse
import json
import re
import stat
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_FILES = 32
MAX_IMAGE_BYTES = 4 * 1024 * 1024
MAX_IMAGES = 5
NATIVE_MAINTENANCE_LOGS = (
    "native-webview-*/state/backups/installation-recovery/*/i-*.log",
    "native-webview-*/state/backups/installation-recovery/*/x-*.log",
)
# Thread names and file.py:line:function frames only (native_webview_journey.reduced_stacks).
NATIVE_DASHBOARD_STACKS = "native-webview-*/dashboard-stacks.txt"
PATTERNS = (
    "lightwork-msi-*.log",
    "rollback-signed-*/stages.json",
    "rollback-signed-*/create.log",
    "rollback-signed-*/trust.log",
    "rollback-signed-*/sign-base.log",
    "rollback-signed-*/sign-next.log",
    "rollback-signed-*/native-webview.log",
    "rollback-signed-*/completed-rollback.log",
    "rollback-signed-*/cleanup.log",
    "identity-transition-*/stages.json",
    "identity-transition-*/*.log",
    "native-webview-*/acceptance.json",
    "native-webview-*/driver.log",
    "native-webview-*/msi-*.log",
    *NATIVE_MAINTENANCE_LOGS,
    "native-webview-*/downloads/Lightwork-startup-support.json",
    NATIVE_DASHBOARD_STACKS,
    "lightwork-customer-state-*/dashboard-*.log",
    "lightwork-customer-state-*/recovery-*.log",
    "lw-rollback-*/recovery-*.log",
    "lw-rollback-*/state/backups/installation-recovery/*/i-*.log",
    "lw-rollback-*/state/backups/installation-recovery/*/x-*.log",
)


def scrub(text: str) -> str:
    text = re.sub(r"-----BEGIN [^-]+-----[\s\S]*?(?:-----END [^-]+-----|\Z)", "[REDACTED KEY]", text)
    text = re.sub(r"(?i)(authorization\s*[:=]\s*|bearer\s+)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:\w*(?:password|token|secret|credential|private_key)\w*)\s*[:=]\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"(https?://[^\s?]+)\?[^\s]+", r"\1?[REDACTED]", text)
    text = re.sub(r"\b[A-Za-z0-9_+/=-]{32,}(?:\.[A-Za-z0-9_+/=-]+)*\b", "[REDACTED OPAQUE VALUE]", text)
    return text


def ordinary_file(path: Path, root: Path) -> bool:
    """Never traverse a symlink/junction out of the allowlisted fixture tree."""
    try:
        path.relative_to(root)
        for item in (path, *path.parents):
            details = item.lstat()
            if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
                return False
            if item == root:
                return path.is_file()
    except (OSError, ValueError):
        pass
    return False


def collect(runner: Path, artifacts: Path, output: Path) -> dict:
    runner, artifacts, output = (path.absolute() for path in (runner, artifacts, output))
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    candidates = [(path, runner) for pattern in PATTERNS for path in runner.glob(pattern)]
    candidates += [(artifacts / name, artifacts) for name in (
        "acceptance.json", "completed-rollback-acceptance.json", "runtime-inventory.json",
        "publisher-transition-acceptance.json",
    )]
    # Reports remain first. Preserve the native operation's own MSI evidence
    # before earlier fixture install/uninstall logs consume the file limit.
    for path, root in sorted(set(candidates), key=lambda item: (
            item[1] != artifacts, item[0].suffix != ".json",
            not any(item[0].match(pattern) for pattern in (*NATIVE_MAINTENANCE_LOGS, NATIVE_DASHBOARD_STACKS)),
            str(item[0]))):
        if len(entries) >= MAX_FILES:
            break
        if not ordinary_file(path, root):
            continue
        try:
            size = path.stat().st_size
            with path.open("rb") as source:
                if size > MAX_BYTES:
                    source.seek(-MAX_BYTES, 2)
                raw = source.read(MAX_BYTES)
            encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
            # Windows Installer commonly writes UTF-16; detect tails too.
            if encoding == "utf-8" and raw[:200].count(b"\0") > 20:
                encoding = "utf-16-le"
            name = f"{len(entries):02d}-{path.name}.txt"
            (output / name).write_text(scrub(raw.decode(encoding, errors="replace")), encoding="utf-8")
            entries.append({"file": name, "source": path.relative_to(root).as_posix(), "truncated": size > MAX_BYTES})
        except OSError:
            entries.append({"source": path.relative_to(root).as_posix(), "unavailable": True})
    images = []
    for name in ("first-owner.png", "normal-support.png", "signed-native-upgrade.png", "signed-native-rollback.png", "startup-support.png"):
        for path in sorted(runner.glob("native-webview-*/" + name)):
            if len(images) >= MAX_IMAGES or not ordinary_file(path, runner):
                continue
            try:
                with path.open("rb") as source:
                    raw = source.read(MAX_IMAGE_BYTES + 1)
            except OSError:
                continue
            if len(raw) > MAX_IMAGE_BYTES:
                continue
            if raw.startswith(b"\x89PNG\r\n\x1a\n"):
                target = f"native-{len(images):02d}-{name}"
                (output / target).write_bytes(raw)
                images.append({"file": target, "source": path.relative_to(runner).as_posix()})
    report = {"schema": "lightwork.acceptance-diagnostics.v1", "synthetic_fixtures_only": True,
              "scope": "Allowlisted acceptance reports, scrubbed log tails and five synthetic native screenshots; no keys, state files, installers or archives.",
              "maximum_files": MAX_FILES, "maximum_bytes_per_file": MAX_BYTES, "files": entries,
              "images": images, "maximum_images": MAX_IMAGES, "maximum_image_bytes": MAX_IMAGE_BYTES}
    (output / "manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("runner", "artifacts", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    report = collect(args.runner, args.artifacts, args.output)
    print(f"Retained {len(report['files'])} bounded acceptance diagnostic files.")


if __name__ == "__main__":
    main()
