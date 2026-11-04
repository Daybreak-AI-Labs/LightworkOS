"""Release artifacts are Sigstore-signed (keyless) and verifiable.

Locks the supply-chain wiring: the release workflow signs every binary + the
SBOM with cosign keyless (needs `id-token: write`), and a verify script ships
for downstream users. These tests intentionally parse only the small subset of
YAML needed here so they can scope assertions to the real `jobs.release` block
without adding PyYAML to the kernel test environment.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_RELEASE_LINES = (_REPO / ".github" / "workflows" / "release.yml").read_text().splitlines()
_VERIFY = _REPO / "deploy" / "verify-release.sh"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(line: str) -> str:
    """Remove comments from simple YAML lines used by the release workflow."""
    return line.split("#", 1)[0].rstrip()


def _block_after(key: str, lines: list[str], *, parent_indent: int = -1) -> list[str]:
    """Return the indented YAML block immediately below ``key:``.

    The helper is deliberately small, but importantly scopes checks to real YAML
    keys instead of raw substrings that could appear in comments, other jobs, or
    inert text.
    """
    for index, line in enumerate(lines):
        stripped = _strip_comment(line).strip()
        if stripped != f"{key}:":
            continue
        line_indent = _indent(line)
        if line_indent <= parent_indent:
            continue

        block: list[str] = []
        for child in lines[index + 1 :]:
            if child.strip() and _indent(child) <= line_indent:
                break
            block.append(child)
        return block
    raise AssertionError(f"{key!r} block missing")


def _release_job() -> list[str]:
    jobs = _block_after("jobs", _RELEASE_LINES)
    return _block_after("release", jobs)


def _release_permissions() -> dict[str, str]:
    permissions = _block_after("permissions", _release_job())
    parsed: dict[str, str] = {}
    for line in permissions:
        cleaned = _strip_comment(line).strip()
        if not cleaned or ":" not in cleaned:
            continue
        key, value = cleaned.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _release_step_blocks() -> list[list[str]]:
    steps = _block_after("steps", _release_job())
    blocks: list[list[str]] = []
    current: list[str] = []
    step_indent: int | None = None
    for line in steps:
        cleaned = _strip_comment(line).lstrip()
        if cleaned.startswith("- "):
            if current:
                blocks.append(current)
            current = [line]
            step_indent = _indent(line)
        elif current and (not line.strip() or step_indent is None or _indent(line) > step_indent):
            current.append(line)
    if current:
        blocks.append(current)
    return blocks


def _step_named(name: str) -> list[str]:
    needle = f"name: {name}"
    for step in _release_step_blocks():
        if any(_strip_comment(line).strip().lstrip("- ") == needle for line in step):
            return step
    raise AssertionError(f"release step {name!r} missing")


def _shell_commands(step: list[str]) -> str:
    commands: list[str] = []
    in_run = False
    run_indent = 0
    for line in step:
        cleaned = _strip_comment(line).strip()
        if not in_run and cleaned == "run: |":
            in_run = True
            run_indent = _indent(line)
            continue
        if in_run:
            if line.strip() and _indent(line) <= run_indent:
                break
            command = line.strip()
            if command and not command.startswith("#"):
                commands.append(command)
    return "\n".join(commands)


def test_release_job_has_id_token_permission():
    # Keyless cosign signing fails without OIDC token issuance. The permission
    # must be granted on the release job itself, not merely elsewhere.
    assert _release_permissions().get("id-token") == "write"


def test_release_signs_artifacts():
    signing_commands = _shell_commands(_step_named("Sign release artifacts (keyless, Sigstore)"))
    assert "cosign sign-blob" in signing_commands
    assert "--output-signature" in signing_commands
    assert "--output-certificate" in signing_commands


def test_cosign_installer_pinned_to_sha():
    for step in _release_step_blocks():
        for line in step:
            cleaned = _strip_comment(line).strip()
            if not cleaned.startswith("uses: sigstore/cosign-installer@"):
                continue
            ref = cleaned.rsplit("@", 1)[1]
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (
                "cosign-installer must be pinned to a commit SHA"
            )
            return
    raise AssertionError("cosign-installer action missing from release job")


def test_verify_script_present_and_executable():
    assert _VERIFY.is_file()
    assert os.access(_VERIFY, os.X_OK)
    body = _VERIFY.read_text()
    assert "cosign verify-blob" in body
    assert "--certificate-identity-regexp" in body
    assert "--certificate-oidc-issuer" in body


def test_verify_script_requires_exact_release_tag():
    body = _VERIFY.read_text()
    assert "usage: verify-release.sh <artifact> <release-tag> [sig] [cert]" in body
    assert 'TAG="$2"' in body
    assert "@refs/tags/${ESCAPED_TAG}$" in body
    assert "refs/tags/v.*" not in body
    assert 'IDENTITY_REGEXP="${IDENTITY_REGEXP:-' not in body


REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------- cosign workflow ----------

def test_cosign_signing_in_publish_workflow():
    p = REPO_ROOT / ".github" / "workflows" / "publish.yml"
    body = p.read_text()
    assert "sigstore/cosign-installer" in body
    assert "cosign sign-blob" in body
    assert "id-token: write" in body
    # The sign job is gated on the successful upstream Release tag run.
    assert 'workflows: ["Release"]' in body
    assert "github.event.workflow_run.conclusion == 'success'" in body
    assert "startsWith(github.event.workflow_run.head_branch, 'v')" in body
