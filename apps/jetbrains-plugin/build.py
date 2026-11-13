"""Build an unsigned installable preview with the pinned Gradle wrapper."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WRAPPER_SHA256 = "81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f"


def main() -> None:
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        raise SystemExit("Set JAVA_HOME to a JDK21 installation; see BUILDING.md.")
    java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
    version = subprocess.check_output([str(java), "-version"], stderr=subprocess.STDOUT, text=True)
    if 'version "21.' not in version and 'version "21"' not in version:
        raise SystemExit("This preview requires JDK21; active Java: " + version)
    wrapper = ROOT / "gradle/wrapper/gradle-wrapper.jar"
    if hashlib.sha256(wrapper.read_bytes()).hexdigest() != WRAPPER_SHA256:
        raise SystemExit("Gradle wrapper checksum mismatch; restore the reviewed wrapper before building.")
    subprocess.run(
        [str(java), "-classpath", str(wrapper),
         "org.gradle.wrapper.GradleWrapperMain", "--no-daemon", "--console=plain",
         "check", "buildPlugin"], cwd=ROOT, check=True,
    )
    plugin_version = re.search(r'^version = "([^"\r\n]+)"$',
                               (ROOT / "build.gradle.kts").read_text(encoding="utf-8"), re.MULTILINE)
    if plugin_version is None or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", plugin_version[1]):
        raise SystemExit("Expected a literal plugin version in build.gradle.kts.")
    artifact = ROOT / "build/distributions" / f"lightwork-jetbrains-{plugin_version[1]}.zip"
    if not artifact.is_file():
        raise SystemExit("Expected plugin archive missing; no release manifest written.")
    inputs = [ROOT / name for name in (
        "build.gradle.kts", "settings.gradle.kts", "gradle.properties", "gradle.lockfile", "build.py",
        "gradle/wrapper/gradle-wrapper.properties", "gradle/wrapper/gradle-wrapper.jar",
    )]
    inputs.extend(sorted(path for path in (ROOT / "src").rglob("*") if path.is_file()))
    checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = {
        "kind": "unsigned-preview", "installed_host_qualified": False,
        "java": version.strip(), "sdk": "IntelliJ Community 2024.3.6 (243)",
        "artifact": artifact.name, "sha256": checksum,
        "inputs_sha256": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs},
    }
    artifact.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    artifact.with_suffix(".zip.sha256").write_text(checksum + "  " + artifact.name + "\n", encoding="utf-8")
    print(str(artifact))
    print("SHA256 " + checksum)
    print("Unsigned preview only; no IDE install, signing or publication performed.")


if __name__ == "__main__":
    main()
