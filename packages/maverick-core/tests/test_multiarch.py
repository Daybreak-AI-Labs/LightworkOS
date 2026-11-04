"""Contract tests for the multi-arch build kit (deploy/multiarch).

hadolint is not available in the test environment, so this is the
documented fallback: basic invariant checks that the Dockerfile parses
structurally (ARG-before-FROM, known instructions only) and that the
supported-platform and reduced-cohort contracts hold (amd64 + ARM64 only,
manifest-driven installs, buildx + QEMU guidance present).
"""
from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MA = _REPO_ROOT / "deploy" / "multiarch"
_DOCKERFILE = _MA / "Dockerfile.multiarch"

_KNOWN_INSTRUCTIONS = {
    "FROM", "ARG", "ENV", "RUN", "COPY", "WORKDIR", "ENTRYPOINT", "CMD", "USER",
}


def _instructions() -> list[str]:
    lines: list[str] = []
    continued = False
    for raw in _DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if continued:
            continued = line.endswith("\\")
            continue
        lines.append(line)
        continued = line.endswith("\\")
    return lines


def test_dockerfile_parses_with_known_instructions_only():
    instructions = _instructions()
    assert instructions, "empty Dockerfile"
    for line in instructions:
        word = line.split()[0]
        assert word in _KNOWN_INSTRUCTIONS, f"unknown instruction: {line!r}"


def test_base_image_is_arg_gated_with_slim_default():
    instructions = _instructions()
    # ARG BASE_IMAGE must precede FROM so reviewed compatible images can be
    # selected without changing the Dockerfile.
    arg_idx = next(i for i, line in enumerate(instructions)
                   if line.startswith("ARG BASE_IMAGE"))
    from_idx = next(i for i, line in enumerate(instructions)
                    if line.startswith("FROM"))
    assert arg_idx < from_idx
    assert "ARG BASE_IMAGE=python:3.12-slim" in instructions[arg_idx]
    assert instructions[from_idx].startswith("FROM ${BASE_IMAGE}")


def test_riscv64_is_explicitly_unsupported():
    text = _DOCKERFILE.read_text(encoding="utf-8")
    script = (_MA / "build.sh").read_text()
    readme = (_MA / "README.md").read_text()
    assert "riscv64 is intentionally unsupported" in text
    assert "linux/amd64|linux/arm64" in script
    assert "linux/riscv64" not in script
    assert "RISC-V is intentionally unsupported" in readme


def test_image_uses_the_manifest_driven_reduced_cohort():
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "scripts/install_release_cohort.py" in text
    assert "--only maverick-agent maverick-shield" in text
    assert "ARG INSTALL_DASHBOARD=0" in text
    assert "--only maverick-agent maverick-shield maverick-dashboard" in text
    assert "release-cohort.toml" in text
    assert "requirements/ci.txt" in text
    assert 'ENTRYPOINT ["maverick"]' in text


def test_runtime_is_unprivileged_and_ignores_user_site_packages():
    text = _DOCKERFILE.read_text(encoding="utf-8")
    instructions = _instructions()
    assert "PYTHONNOUSERSITE=1" in text
    assert "ENV HOME=/home/maverick" in instructions
    assert [line for line in instructions if line.startswith("USER ")][-1] == "USER maverick"
    assert "chown -R maverick:maverick /workspace /home/maverick" in text
    assert "chown -R maverick:maverick /opt/maverick" not in text


def test_build_script_targets_multiple_platforms_via_buildx():
    text = (_MA / "build.sh").read_text()
    assert "docker buildx build" in text
    assert "linux/amd64,linux/arm64" in text
    assert "tonistiigi/binfmt --install all" in text  # QEMU prerequisite
    assert "Dockerfile.multiarch" in text


def test_readme_is_honest_about_native_dependencies_and_scope():
    text = (_MA / "README.md").read_text()
    assert "not pure Python" in text
    assert "pywhispercpp" in text
    assert "ARM64 wheels" in text
    assert "eight-package release cohort" in text
    assert "setup-qemu-action" in text
