"""Regression tests for first-party package installation trust boundaries.

The Lightwork distribution names are intentionally treated as untrusted on
public indexes until the organization has reserved and protected them. CI and
installer entry points must therefore use pinned local source or an explicit
private index, never an implicit public lookup.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from textwrap import dedent

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[3]
GENERATED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
    }
)


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_desktop_bundle_provenance_scripts_are_valid_javascript():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for desktop provenance script validation")
    scripts = re.findall(
        r"(?ms)^[ \t]*node <<'NODE'\n(.*?)^[ \t]*NODE$",
        _read(".github/workflows/desktop.yml"),
    )
    assert scripts, "desktop workflow must validate its actual provenance scripts"
    for script in scripts:
        result = subprocess.run(
            [node, "--check"], input=dedent(script), capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _desktop_verifier_fixture(tmp_path: Path) -> tuple[Path, str]:
    if shutil.which("git") is None:
        pytest.skip("git is required for desktop provenance tests")
    repository = tmp_path / "repo"
    helper = repository / "apps/installer-desktop/scripts/verify-source.mjs"
    helper.parent.mkdir(parents=True)
    helper.write_text(
        _read("apps/installer-desktop/scripts/verify-source.mjs"),
        encoding="utf-8",
        newline="\n",
    )
    files = {
        "apps/installer-desktop/.gitignore": "ignored-probe.txt\n",
        "apps/installer-desktop/index.html": "<main>verified</main>\n",
        "apps/installer-desktop/src-tauri/icons/icon.png": "icon fixture\n",
        "apps/desktop-runtime/Cargo.toml": '[package]\nname = "runtime-fixture"\n',
        "apps/desktop-runtime/src/lib.rs": "pub fn fixture() {}\n",
        "deploy/desktop/install.sh": "#!/bin/sh\nprintf verified\n",
        "deploy/desktop/install.ps1": "Write-Output 'verified'\n",
    }
    for relative_path, content in files.items():
        candidate = repository / relative_path
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(content, encoding="utf-8", newline="\n")
    _git(repository, "init", "--quiet")
    _git(repository, "config", "core.autocrlf", "false")
    _git(repository, "config", "core.eol", "lf")
    _git(repository, "config", "user.name", "Desktop provenance test")
    _git(repository, "config", "user.email", "desktop@example.invalid")
    _git(
        repository,
        "remote",
        "add",
        "origin",
        "https://github.com/Daybreak-AI-Labs/LightworkOS.git",
    )
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return repository, _git(repository, "rev-parse", "HEAD")


def _run_desktop_verifier(
    repository: Path,
    revision: str,
    *,
    extra_environment: dict[str, str] | None = None,
    require_head: bool = True,
    canonicalize_checkout: bool = False,
) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for desktop provenance tests")
    environment = os.environ.copy()
    environment.update(extra_environment or {})
    arguments = [
        node,
        str(repository / "apps/installer-desktop/scripts/verify-source.mjs"),
        "--repo",
        str(repository),
        "--ref",
        revision,
    ]
    if require_head:
        arguments.append("--require-head")
    if canonicalize_checkout:
        arguments.append("--canonicalize-checkout")
    return subprocess.run(
        arguments,
        cwd=repository,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )


def _repository_files(
    *,
    filename: str | None = None,
    suffix: str | None = None,
) -> Iterator[Path]:
    """Yield tracked-source candidates without traversing generated trees."""
    if (filename is None) == (suffix is None):
        raise ValueError("provide exactly one of filename or suffix")

    for directory, subdirectories, filenames in os.walk(REPO_ROOT):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in GENERATED_DIRECTORY_NAMES
        )
        for candidate in sorted(filenames):
            if candidate == filename or (suffix is not None and candidate.endswith(suffix)):
                yield Path(directory) / candidate


def test_composite_action_installs_first_party_packages_from_its_checkout():
    text = _read("deploy/github-action/action.yml")

    assert "GITHUB_ACTION_PATH" in text
    assert "scripts/install_release_cohort.py" in text
    assert "--source-root" in text
    assert "--core-extra release-runtime" in text
    assert "release-cohort.toml" in text

    assert not re.search(
        r"python\s+-m\s+pip\s+install\s+['\"]?maverick-agent",
        text,
    )


def test_reusable_pr_workflow_requires_immutable_runtime_source():
    text = _read(".github/workflows/agent-on-pr.yml")

    assert "lightwork_ref:" in text
    assert "Full 40-character commit SHA" in text
    assert "repository: Daybreak-AI-Labs/LightworkOS" in text
    assert "persist-credentials: false" in text
    assert '"$source_root/packages/maverick-core[all]"' in text
    assert "pip install 'maverick-agent[all]'" not in text


def test_gitlab_template_has_no_implicit_public_index_fallback():
    text = _read("deploy/gitlab-ci/maverick.gitlab-ci.yml")

    assert "MAVERICK_SOURCE_DIR" in text
    assert "MAVERICK_SOURCE_REF" in text
    assert "MAVERICK_PACKAGE_INDEX_URL" in text
    assert "python -m pip --isolated install" in text
    assert "Public PyPI is blocked" in text
    assert "status --porcelain --untracked-files=all" in text
    assert 'pip install "maverick-agent"' not in text


def test_desktop_installers_require_a_pinned_source_ref():
    shell = _read("deploy/desktop/install.sh")
    powershell = _read("deploy/desktop/install.ps1")

    for text in (shell, powershell):
        assert "MAVERICK_REF is required" in text
        assert "public-index fallback is disabled" in text
        assert "MAVERICK_ALLOW_UNPINNED" not in text
        assert "maverick-agent[installer]" not in text
        assert "status --porcelain --untracked-files=all" in text

    assert "rev-parse HEAD" in shell
    assert "rev-parse HEAD" in powershell


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(("reported", "installs", "stops"), [
    ("3.10", True, True),
    ("3.12", False, False),
])
def test_desktop_installer_checks_the_python_floor_after_installing(tmp_path, reported, installs, stops):
    """A distro python3 below the floor (3.10 on Ubuntu 22.04) must stop the
    installer with a plain message right after the package-manager install,
    not later at pip's requires-python check."""
    script = _read("deploy/desktop/install.sh")
    start = script.index("python3_meets_floor() {")
    function = script[start:script.index("\n}\n", script.index("ensure_python() {")) + 3]
    major, minor = reported.split(".")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stubs = {
        "python3": f'#!/bin/sh\ncase "$2" in *02d*) echo {major}{int(minor):02d} ;; *) echo {reported} ;; esac\n',
        "apt-get": f'#!/bin/sh\necho "apt-get $*" >> "{tmp_path}/calls"\n',
        "sudo": '#!/bin/sh\nexec "$@"\n',
        "uname": "#!/bin/sh\necho Linux\n",
    }
    for name, body in stubs.items():
        (bin_dir / name).write_text(body, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    harness = (
        "set -euo pipefail\n"
        "log() { :; }\n"
        "die() { printf 'DIE: %s\\n' \"$*\"; exit 1; }\n"
        "have() { command -v \"$1\" >/dev/null 2>&1; }\n"
        f"{function}"
        "ensure_python\n"
        "echo RETURNED\n"
    )
    result = subprocess.run(
        [shutil.which("bash"), "-c", harness],
        env={"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin", "HOME": str(tmp_path)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert (tmp_path / "calls").exists() is installs
    if stops:
        assert result.returncode == 1, result.stdout + result.stderr
        assert "DIE: Lightwork needs Python 3.11 or newer" in result.stdout
        assert "python3 is 3.10" in result.stdout
        assert "RETURNED" not in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "RETURNED" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(("reported", "stops"), [("3.10", True), ("3.12", False)])
def test_vps_installer_checks_the_python_floor_after_installing(tmp_path, reported, stops):
    """The VPS path installs the distro python3, which is 3.10 on Ubuntu
    22.04; it must stop with a plain message before the cohort install."""
    script = _read("deploy/vps/install.sh")
    start = script.index("install_system_deps() {")
    function = script[start:script.index("\n}\n", start) + 3]
    function = function.replace("/usr/bin/python3", shlex.quote((tmp_path / "bin" / "python3").as_posix()))
    major, minor = reported.split(".")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stubs = {
        "python3": f'#!/bin/sh\ncase "$*" in *02d*) echo {major}{int(minor):02d} ;; *) echo {reported} ;; esac\n',
        "apt-get": "#!/bin/sh\nexit 0\n",
        "pipx": "#!/bin/sh\nexit 0\n",
    }
    for name, body in stubs.items():
        (bin_dir / name).write_text(body, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    harness = f"set -euo pipefail\nlog() {{ :; }}\n{function}install_system_deps\necho RETURNED\n"
    result = subprocess.run(
        [shutil.which("bash"), "-c", harness],
        env={"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin", "HOME": str(tmp_path)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    if stops:
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Lightwork needs Python 3.11 or newer" in result.stderr
        assert "python3 is 3.10" in result.stderr
        assert "RETURNED" not in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "RETURNED" in result.stdout
    assert "Installs Python 3.12" not in script


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(("reported", "stops"), [("3.10", True), ("3.12", False)])
def test_dev_bootstrap_checks_the_python_floor_before_creating_the_venv(tmp_path, reported, stops):
    """post-create.sh falls back to the host python3 when no python3.12 or
    python3.11 exists; a 3.10 host (Ubuntu 22.04, the benchmark VM guide's old
    image) must stop with a plain message, not inside pip."""
    script = _read(".devcontainer/post-create.sh")
    start = script.index("python_bin=python3\n")
    selection = script[start:script.index('"$python_bin" -m venv .venv', start)]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python3 = bin_dir / "python3"
    python3.write_text(
        "#!/bin/sh\n"
        f'case "$2" in *version_info\\ \\<*) [ "{reported}" != "3.10" ] ;; *) echo {reported} ;; esac\n',
        encoding="utf-8",
    )
    python3.chmod(0o755)
    # PATH holds only the stub, so a host python3.12/3.11 cannot be preferred;
    # the selection code uses only shell builtins besides the interpreter.
    result = subprocess.run(
        [shutil.which("bash"), "-c", f"set -euo pipefail\n{selection}echo SELECTED \"$python_bin\"\n"],
        env={"PATH": str(bin_dir), "HOME": str(tmp_path)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    if stops:
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Lightwork needs Python 3.11 or 3.12, but python3 is 3.10" in result.stderr
        assert "SELECTED" not in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "SELECTED python3" in result.stdout


def test_vps_installer_requires_a_clean_immutable_checkout():
    text = _read("deploy/vps/install.sh")

    assert "MAVERICK_REF is required" in text
    assert "^[0-9a-f]{40}$" in text
    assert "rev-parse HEAD" in text
    assert "status --porcelain --untracked-files=all" in text
    assert "maverick.stage." in text
    assert "MAVERICK_VERSION" not in text
    assert "Lightwork/main/deploy/vps/install.sh" not in text


def test_vps_installer_installs_the_container_images_core_extras():
    """The VPS path installed only release-runtime while the container
    image installed postgres/oidc/s3 too, so MAVERICK_WORLD_BACKEND=postgres
    or OIDC login on a VPS failed with an ImportError at first use."""
    text = _read("deploy/vps/install.sh")
    dockerfile = _read("deploy/docker/Dockerfile")

    image_extras = re.search(r"--core-extra\s+([\w,-]+)", dockerfile).group(1)
    default = re.search(
        r'MAVERICK_CORE_EXTRAS="\$\{MAVERICK_CORE_EXTRAS:-([\w,-]+)\}"', text
    )
    assert default is not None, "install.sh must default MAVERICK_CORE_EXTRAS"
    assert set(default.group(1).split(",")) == set(image_extras.split(","))
    assert '--core-extra "$MAVERICK_CORE_EXTRAS"' in text
    # The extras must exist so install_release_cohort's validation accepts them.
    core = tomllib.loads(
        _read("packages/maverick-core/pyproject.toml")
    )["project"]["optional-dependencies"]
    assert set(default.group(1).split(",")) <= set(core)


def test_native_installer_build_ref_is_a_full_commit():
    build_rs = _read("apps/installer-desktop/src-tauri/build.rs")
    native_shell = _read("apps/installer-desktop/src-tauri/src/lib.rs")
    workflow = _read(".github/workflows/desktop.yml")
    readme = _read("apps/installer-desktop/README.md")
    verifier = _read("apps/installer-desktop/scripts/verify-source.mjs")
    icon_ignore = _read("apps/installer-desktop/.gitignore")

    assert "validate_install_ref" in build_rs
    assert "trimmed.len() == 40" in build_rs
    assert "lowercase, full 40-character commit SHA" in build_rs
    assert "verify_commit" in build_rs
    assert "verify_install_ref_ancestor" in build_rs
    assert "verify_canonical_repository" in build_rs
    assert "verify_raw_source_snapshot" in build_rs
    assert "emit_git_rerun_triggers" in build_rs
    assert '"--no-replace-objects"' in build_rs
    assert '"GIT_NO_REPLACE_OBJECTS"' in build_rs
    assert 'starts_with("GIT_")' in build_rs
    assert "MAVERICK_REQUIRE_CLEAN_INSTALLER_SOURCE" in build_rs
    assert "PROTECTED_BUILD_PATHS" not in build_rs
    assert "Sha256::digest" in build_rs
    assert 'env!("OUT_DIR")' in native_shell
    assert "MAVERICK_INSTALL_SH_SHA256" in native_shell
    assert "../../../../deploy/desktop/install" not in native_shell
    assert "MAVERICK_INSTALL_REF: ${{ github.sha }}" in workflow
    assert 'MAVERICK_REQUIRE_CLEAN_INSTALLER_SOURCE: "1"' in workflow
    assert '"deploy/desktop/install.ps1"' in workflow
    assert '"deploy/desktop/install.sh"' in workflow
    assert "--canonicalize-checkout" in workflow
    assert "github.repository == 'Daybreak-AI-Labs/LightworkOS'" in workflow
    assert "pnpm tauri icon" not in workflow
    assert '--target "$BUNDLE_TARGET"' in workflow
    assert '--config "$TAURI_BUILD_CONFIG"' in workflow
    assert "--ci" in workflow
    assert "rmSync(bundleRoot" in workflow
    assert "tar -czf" in workflow
    assert "Record bundle provenance and checksums" in workflow
    assert "bootstrap_blobs" in workflow
    assert "locked_inputs" in workflow
    assert "bundle_entries" in workflow
    assert "uploaded_payloads" in workflow
    assert "MAVERICK_WORKFLOW_REF" in workflow
    assert "MAVERICK_WORKFLOW_SHA" in workflow
    assert "GITHUB_RUN_ATTEMPT" in workflow
    assert "effectiveConfig" in workflow
    assert "lightwork-desktop-${target}" in workflow
    assert "maverick-desktop-${target}" not in workflow
    assert "src-tauri/target/release/bundle/**/*.app" not in workflow
    assert "apps/installer-desktop/provenance/${{ matrix.target }}.tar.gz" in workflow
    assert "verifyDesktopSource" in verifier
    assert "GIT_NO_REPLACE_OBJECTS" in verifier
    assert '"--no-replace-objects"' in verifier
    assert "canonicalizeCheckout" in verifier
    for icon in (
        "32x32.png",
        "128x128.png",
        "128x128@2x.png",
        "icon.icns",
        "icon.ico",
        "icon.png",
    ):
        assert f"!src-tauri/icons/{icon}" in icon_ignore
        assert (REPO_ROOT / f"apps/installer-desktop/src-tauri/icons/{icon}").is_file()
    assert "lowercase-full-40-character-commit-sha" in readme
    assert "<commit-or-tag>" not in readme


def test_desktop_source_verifier_scrubs_git_environment(tmp_path):
    repository, revision = _desktop_verifier_fixture(tmp_path)

    result = _run_desktop_verifier(
        repository,
        revision,
        extra_environment={
            "GIT_DIR": str(tmp_path / "attacker-git-dir"),
            "GIT_OBJECT_DIRECTORY": str(tmp_path / "attacker-objects"),
            "GIT_REPLACE_REF_BASE": "refs/attacker",
        },
    )

    assert result.returncode == 0, result.stderr
    assert f"at {revision}" in result.stdout


def test_desktop_source_verifier_canonicalizes_checkout_bytes(tmp_path):
    repository, revision = _desktop_verifier_fixture(tmp_path)
    bootstrap = repository / "deploy/desktop/install.ps1"
    committed = bootstrap.read_bytes()
    bootstrap.write_bytes(b"untrusted checkout transform\r\n")

    result = _run_desktop_verifier(
        repository,
        revision,
        canonicalize_checkout=True,
    )

    assert result.returncode == 0, result.stderr
    assert bootstrap.read_bytes() == committed
    assert _git(repository, "config", "--local", "core.autocrlf") == "false"
    assert _git(repository, "config", "--local", "core.eol") == "lf"


def test_desktop_source_verifier_canonicalizes_a_crlf_checkout(tmp_path):
    # A Windows runner checks out with core.autocrlf=true, so every text file
    # is written with CRLF and the index records those bytes as clean. A plain
    # `git reset --hard` after turning autocrlf off rewrites none of them.
    repository, revision = _desktop_verifier_fixture(tmp_path)
    _git(repository, "config", "core.autocrlf", "true")
    _git(repository, "rm", "-r", "-q", "--cached", ".")
    _git(repository, "reset", "-q", "--hard", revision)
    # Age the files and refresh the index so git trusts its stat data, as it
    # does on a runner where seconds pass between checkout and verification
    # (a file written in the same second as the index is re-read instead).
    stale = time.time() - 3600
    for tracked in _git(repository, "ls-files").splitlines():
        os.utime(repository / tracked, (stale, stale))
    _git(repository, "update-index", "-q", "--refresh")
    launcher = repository / "deploy/desktop/install.sh"
    assert launcher.read_bytes() == b"#!/bin/sh\r\nprintf verified\r\n"
    assert _git(repository, "status", "--porcelain") == ""

    result = _run_desktop_verifier(
        repository,
        revision,
        canonicalize_checkout=True,
    )

    assert result.returncode == 0, result.stderr
    assert launcher.read_bytes() == b"#!/bin/sh\nprintf verified\n"


def test_desktop_source_verifier_rejects_raw_and_ignored_changes(tmp_path):
    repository, revision = _desktop_verifier_fixture(tmp_path)

    generated = repository / "apps/installer-desktop/src-tauri/target/release/generated.bin"
    generated.parent.mkdir(parents=True)
    generated.write_bytes(b"generated output is outside the source snapshot")
    assert _run_desktop_verifier(repository, revision).returncode == 0

    ignored = repository / "apps/installer-desktop/ignored-probe.txt"
    ignored.write_bytes(b"ignored but still an unreviewed build input")
    ignored_result = _run_desktop_verifier(repository, revision)
    assert ignored_result.returncode == 1
    assert "untracked: apps/installer-desktop/ignored-probe.txt" in (ignored_result.stderr)
    ignored.unlink()

    tracked = repository / "deploy/desktop/install.sh"
    tracked.write_bytes(b"#!/bin/sh\nprintf substituted\n")
    modified_result = _run_desktop_verifier(repository, revision)
    assert modified_result.returncode == 1
    assert "raw bytes differ" in modified_result.stderr


def test_desktop_source_verifier_covers_shared_launcher(tmp_path):
    repository, revision = _desktop_verifier_fixture(tmp_path)
    generated = repository / "apps/desktop-runtime/target/debug/generated.bin"
    generated.parent.mkdir(parents=True)
    generated.write_bytes(b"generated output")
    assert _run_desktop_verifier(repository, revision).returncode == 0

    source = repository / "apps/desktop-runtime/src/lib.rs"
    source.write_text("pub fn substituted() {}\n", encoding="utf-8")
    result = _run_desktop_verifier(repository, revision)
    assert result.returncode == 1
    assert "raw bytes differ" in result.stderr
    assert "apps/desktop-runtime/src/lib.rs" in result.stderr


def test_desktop_source_verifier_is_not_subverted_by_git_replace(tmp_path):
    repository, original = _desktop_verifier_fixture(tmp_path)
    bootstrap = repository / "deploy/desktop/install.sh"
    bootstrap.write_bytes(b"#!/bin/sh\nprintf replacement\n")
    _git(repository, "add", "deploy/desktop/install.sh")
    _git(repository, "commit", "--quiet", "-m", "replacement tree")
    replacement = _git(repository, "rev-parse", "HEAD")
    _git(repository, "checkout", "--detach", "--quiet", original)
    _git(repository, "replace", original, replacement)
    _git(repository, "reset", "--hard", "--quiet", original)

    assert _git(repository, "rev-parse", "HEAD") == original
    assert (
        _git(repository, "show", f"{original}:deploy/desktop/install.sh")
        == "#!/bin/sh\nprintf replacement"
    )
    result = _run_desktop_verifier(repository, original)

    assert result.returncode == 1
    assert "raw bytes differ" in result.stderr


def test_desktop_source_verifier_rejects_noncanonical_origin(tmp_path):
    repository, revision = _desktop_verifier_fixture(tmp_path)
    _git(
        repository,
        "remote",
        "set-url",
        "origin",
        "https://github.com/example/fork.git",
    )

    result = _run_desktop_verifier(repository, revision)

    assert result.returncode == 1
    assert "origin must be the canonical" in result.stderr


def test_desktop_source_verifier_rejects_unrelated_explicit_ref(tmp_path):
    repository, original = _desktop_verifier_fixture(tmp_path)
    _git(repository, "checkout", "--orphan", "unrelated")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "unrelated root")

    result = _run_desktop_verifier(
        repository,
        original,
        require_head=False,
    )

    assert result.returncode == 1
    assert "is not an ancestor of HEAD" in result.stderr


def test_training_bootstrap_installs_only_from_verified_checkout():
    text = _read("scripts/train_runpod.sh")

    assert "MAVERICK_SOURCE_DIR" in text
    assert "MAVERICK_SOURCE_REF" in text
    assert "status --porcelain --untracked-files=all" in text
    assert '"$MAVERICK_SOURCE_DIR/packages/maverick-core[training]"' in text
    assert "pip install --quiet 'maverick-agent[training]'" not in text


def test_public_pypi_consumer_is_disabled_until_namespace_is_reserved():
    text = _read(".github/workflows/homebrew-bump.yml")

    assert "MAVERICK_PUBLIC_PYPI_ENABLED == 'true'" in text
    assert text.count("github.event.release.prerelease == false") == 3
    assert "disabled by default" in text
    top_level = text.split("jobs:", 1)[0]
    resolver = text.split("\n  resolve:", 1)[1].split("\n  test-formula:", 1)[0]
    formula_test = text.split("\n  test-formula:", 1)[1].split("\n  open-pr:", 1)[0]
    publisher = text.split("\n  open-pr:", 1)[1]
    assert "contents: read" in top_level
    assert "contents: write" not in resolver
    assert "pull-requests: write" not in resolver
    assert "pip-tools==7.6.2" in resolver
    assert "runs-on: macos-15" in resolver
    assert '"--no-header"' in resolver
    assert '"--no-emit-index-url"' in resolver
    assert '"--index-url"' in resolver
    assert '"https://pypi.org/simple"' in resolver
    assert "resolved-homebrew-formula" in resolver
    assert "setuptools==84.2.1" in resolver
    assert "fetch-depth: 0" in resolver
    assert "Verify the signed exact-release Python authority" in resolver
    assert resolver.index("Verify the signed exact-release Python authority") < resolver.index(
        "Pin the formula to the published sdist"
    )
    assert 'gh release view "$tag"' in resolver
    assert "release-manifest.json.cosign.bundle" in resolver
    assert "SHA256SUMS.cosign.bundle" in resolver
    assert resolver.count("cosign verify-blob") == 3
    assert r"publish\.yml@refs/heads/main" in resolver
    assert 'manifest["source_revision"] != revision' in resolver
    assert "checksum_records != digests" in resolver
    assert "downloaded GitHub sdist digest mismatch" in resolver
    assert "EXPECTED_SDIST_FILENAME" in resolver
    assert "EXPECTED_SDIST_SHA256" in resolver
    assert "require_matching_pypi_sdist" in resolver
    assert "expected_sha256=expected_sdist_sha" in resolver
    assert "LIGHTWORK_BUILD_REQUIREMENTS_BEGIN" in resolver
    assert "LIGHTWORK_RUNTIME_REQUIREMENTS_BEGIN" in resolver
    assert "version=version" in resolver
    assert "runs-on: macos-15" in formula_test
    assert "brew install --formula --build-from-source" in formula_test
    assert "brew test maverick" in formula_test
    assert "HOMEBREW_NO_INSTALL_FROM_API" in formula_test
    assert "needs: [resolve, test-formula]" in publisher
    assert "permissions:\n      contents: read" in publisher
    assert "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510" in publisher
    assert "LIGHTWORK_AUTOMATION_APP_CLIENT_ID" in publisher
    assert "LIGHTWORK_AUTOMATION_APP_PRIVATE_KEY" in publisher
    assert "permission-contents: write" in publisher
    assert "permission-pull-requests: write" in publisher
    assert "actions/download-artifact@" in publisher
    assert "token: ${{ steps.automation-token.outputs.token }}" in publisher
    assert "token: ${{ github.token }}" not in publisher
    assert publisher.count("ref: main") == 1
    assert publisher.count("base: main") == 1
    assert resolver.count("ref: main") == 1


def test_homebrew_formula_bootstraps_python_312_without_venv_pip():
    formula = _read("deploy/homebrew/maverick.rb")

    assert 'python = Formula["python@3.12"].opt_bin/"python3.12"' in formula
    assert "virtualenv_create(libexec, python)" in formula
    assert 'system python, "-m", "pip", "--python=#{libexec}/bin/python"' in formula
    assert formula.count('"--require-hashes"') == 2
    assert formula.count('"--only-binary=:all:"') == 2
    assert formula.count('"--no-deps"') == 3
    assert '"--no-deps", "--no-build-isolation", buildpath' in formula
    assert '"--python=#{libexec}/bin/python", "check"' in formula
    assert 'libexec/"bin/pip"' not in formula
    assert "LIGHTWORK_BUILD_REQUIREMENTS_BEGIN" in formula
    assert "LIGHTWORK_BUILD_REQUIREMENTS_END" in formula
    assert "LIGHTWORK_RUNTIME_REQUIREMENTS_BEGIN" in formula
    assert "LIGHTWORK_RUNTIME_REQUIREMENTS_END" in formula
    assert ".fetch(1)" not in formula
    assert 'odie "generated build requirements are missing"' in formula
    assert "That tap is not deployed" in formula
    assert "brew install Daybreak-AI-Labs/tap/maverick" in formula
    assert "brew install cdayAI/tap/maverick" not in formula


def test_cross_ecosystem_osv_gate_is_pinned_complete_and_source_verified():
    ci = _read(".github/workflows/ci.yml")
    step = ci.split(
        "- name: OSV Scanner across every reviewed dependency surface",
        1,
    )[1].split(
        "- name: Upload cross-ecosystem vulnerability report",
        1,
    )[0]
    assert "releases/download/v2.3.8/osv-scanner_linux_amd64" in step
    assert "bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc" in step  # pragma: allowlist secret
    assert "--config osv-scanner.toml" in step
    assert "|| true" not in step
    for dependency_surface in (
        "requirements/ci.txt",
        "rust/Cargo.lock",
        "vendor/tests/Cargo.lock",
        "examples/clients/rust/Cargo.lock",
        "apps/desktop/src-tauri/Cargo.lock",
        "apps/installer-desktop/src-tauri/Cargo.lock",
        "examples/clients/typescript/package-lock.json",
        "apps/installer-desktop/pnpm-lock.yaml",
        "examples/clients/csharp/packages.lock.json",
        "examples/clients/go/go.mod",
        "go/model-proxy/go.mod",
        "examples/clients/java/pom.xml",
        "demo/dsar-concierge/requirements-standalone.txt",
        "demo/environment-threat-hunter/requirements.txt",
        "demo/grc-concierge/requirements.txt",
        "demo/model-risk-ai-assurance-officer/requirements.txt",
        "demo/platform-threat-hunter/requirements.txt",
    ):
        assert dependency_surface in step

    policy = tomllib.loads(_read("osv-scanner.toml"))
    assert policy.get("IgnoredVulns", []) == []
    assert "python scripts/check_vendor_patches.py" in ci
    assert "|| scan_status=$?" in step
    assert 'python -m scripts.check_osv_results "$report"' in step
    assert '--scanner-exit "$scan_status"' in step
    assert '--output "$GITHUB_WORKSPACE/osv-remediation.json"' in step
    artifact_step = ci.split("- name: Upload cross-ecosystem vulnerability report", 1)[1].split("- name:", 1)[0]
    assert "osv-results.json" in artifact_step
    assert "osv-remediation.json" in artifact_step


#: Dependency lockfile names, including ones OSV-Scanner cannot read: those
#: must still be listed as deliberately unscanned, with the reason.
DEPENDENCY_LOCKFILE_NAMES = frozenset(
    {
        ".terraform.lock.hcl", "Cargo.lock", "Gemfile.lock", "Package.resolved",
        "Pipfile.lock", "Podfile.lock", "bun.lock", "buildscript-gradle.lockfile",
        "composer.lock", "conan.lock", "go.mod", "go.sum", "gradle.lockfile",
        "mix.lock", "npm-shrinkwrap.json", "package-lock.json", "packages.lock.json",
        "pdm.lock", "pnpm-lock.yaml", "poetry.lock", "pom.xml", "pubspec.lock",
        "renv.lock", "uv.lock", "verification-metadata.xml", "yarn.lock",
    }
)


def _is_dependency_lockfile(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    if path.name in DEPENDENCY_LOCKFILE_NAMES:
        return True
    # Pinned pip sets: requirements*.txt anywhere and requirements/<name>.txt.
    return path.suffix == ".txt" and (
        path.name.startswith("requirements") or "requirements" in path.parts[:-1]
    )


def test_osv_gate_scans_every_tracked_lockfile_or_says_why_not():
    if shutil.which("git") is None:
        pytest.skip("git is required to list tracked lockfiles")
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=False,
    )
    if listing.returncode != 0:
        pytest.skip("not a git checkout, so there are no tracked lockfiles to list")
    tracked = {name for name in listing.stdout.decode("utf-8").split("\0") if name}
    lockfiles = {name for name in tracked if _is_dependency_lockfile(name)}
    assert "requirements/ci.txt" in lockfiles

    step = _read(".github/workflows/ci.yml").split(
        "- name: OSV Scanner across every reviewed dependency surface", 1,
    )[1].split("- name: Upload cross-ecosystem vulnerability report", 1)[0]
    # A lock copied to a filename OSV recognizes is scanned through the copy.
    copies = {
        variable: source
        for source, variable in re.findall(r'^\s*cp (\S+) "\$(\w+)"$', step, re.MULTILINE)
    }
    scanned: set[str] = set()
    for argument in re.findall(r"--lockfile (\S+)", step):
        variable = re.fullmatch(r'"\$(\w+)"', argument)
        scanned.add(copies[variable.group(1)] if variable else argument)
    unscanned = dict(re.findall(r"^\s*# osv-unscanned: (\S+) -- (\S.*)$", step, re.MULTILINE))

    assert sorted(scanned - tracked) == [], "OSV is pointed at untracked or missing files"
    assert sorted(scanned & unscanned.keys()) == [], "a lockfile is both scanned and excluded"
    assert sorted(unscanned.keys() - lockfiles) == [], "stale osv-unscanned exclusions"
    missing = sorted(lockfiles - scanned - unscanned.keys())
    assert missing == [], (
        "tracked lockfiles neither scanned by OSV nor listed as osv-unscanned with a reason:\n"
        + "\n".join(missing)
    )


def test_go_java_and_standalone_demo_security_floors_are_explicit():
    go_client = _read("examples/clients/go/go.mod")
    model_proxy = _read("go/model-proxy/go.mod")
    java_client = _read("examples/clients/java/pom.xml")
    assert "\ngo 1.26.10\n" in go_client
    assert "golang.org/x/sys v0.47.0" in go_client
    assert "\ngo 1.26.10\n" in model_proxy
    assert "<jackson.version>3.1.7</jackson.version>" in java_client
    assert "<artifactId>jackson-bom</artifactId>" in java_client

    demo_requirements = (
        "demo/dsar-concierge/requirements-standalone.txt",
        "demo/environment-threat-hunter/requirements.txt",
        "demo/grc-concierge/requirements.txt",
        "demo/model-risk-ai-assurance-officer/requirements.txt",
        "demo/platform-threat-hunter/requirements.txt",
    )
    for path in demo_requirements:
        requirements = _read(path)
        assert "h11>=0.16.0" in requirements
        assert "idna>=3.18" in requirements
    assert "python-multipart>=0.0.32" in _read("demo/dsar-concierge/requirements-standalone.txt")


def test_ci_integration_docs_do_not_call_workdir_a_security_boundary():
    action = _read("deploy/github-action/action.yml")
    action_docs = _read("deploy/github-action/README.md")
    gitlab = _read("deploy/gitlab-ci/maverick.gitlab-ci.yml")
    gitlab_docs = _read("deploy/gitlab-ci/README.md")

    for text in (action, action_docs, gitlab, gitlab_docs):
        assert "trusted disposable" in text
        assert "CI runner is already an ephemeral VM" not in text
    assert "working directory is not a filesystem or network" in (gitlab_docs)
    assert "confines the starting directory, not the" in action_docs


def test_external_github_actions_are_pinned_to_full_commits():
    files = sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml"))
    files.append(REPO_ROOT / "deploy" / "github-action" / "action.yml")

    mutable: list[str] = []
    for path in files:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if match is None:
                continue
            target = match.group(1)
            if target.startswith(("./", "docker://")):
                continue
            if re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", target) is None:
                mutable.append(f"{path.relative_to(REPO_ROOT)}:{line_no}: {target}")

    assert mutable == [], "mutable external actions:\n" + "\n".join(mutable)


def test_markdown_workflow_examples_do_not_recommend_mutable_action_refs():
    mutable: list[str] = []
    for path in _repository_files(suffix=".md"):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if match is None:
                continue
            target = match.group(1)
            ref = target.rpartition("@")[2]
            if not ref or "full-40-character-commit-sha" in ref:
                continue
            if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
                mutable.append(f"{path.relative_to(REPO_ROOT)}:{line_no}: {target}")

    assert mutable == [], "mutable Markdown action refs:\n" + "\n".join(mutable)


def test_public_publish_workflow_uses_an_explicit_package_allowlist():
    text = _read(".github/workflows/publish.yml")
    cohort = tomllib.loads(_read("release-cohort.toml"))

    assert "release-cohort.toml" in text
    assert {item["path"] for item in cohort["packages"]} == {
        "packages/maverick-core",
        "packages/maverick-shield",
        "packages/maverick-channels",
        "packages/maverick-dashboard",
        "packages/maverick-mcp",
        "packages/maverick-evolve",
        "packages/maverick-knowledge",
        "apps/installer-cli",
    }
    assert "for d in packages/* apps/*" not in text
    # OIDC is granted only on the publish/sign jobs, never the dependency-
    # installing build job through a workflow-wide permission.
    top_permissions = text.split("jobs:", 1)[0]
    assert "id-token: write" not in top_permissions


def test_active_runtime_guidance_never_resolves_first_party_from_public_index():
    active_files = (
        "packages/maverick-core/maverick/cli/__init__.py",
        "packages/maverick-core/maverick/health.py",
        "packages/maverick-core/maverick/deployment.py",
        "packages/maverick-core/maverick/queue_dispatcher.py",
    )
    unsafe = re.compile(
        r"pip(?:3|x)?\s+(?:install|inject)[^\n]*(?:maverick-agent|"
        r"maverick-dashboard|maverick-mcp-server|maverick-channels|"
        r"maverick-shield|maverick-installer)",
        re.IGNORECASE,
    )
    for path in active_files:
        assert unsafe.search(_read(path)) is None, path


def test_install_guides_use_the_source_install_path():
    """No PyPI package, binary or container image is published, so the
    documented install is a clone of the public repository followed by
    scripts/install_release_cohort.py, written out in docs/source-install.md.
    The README carries that quickstart, every install guide links the source
    install guide, and none tells users to install a Lightwork package from
    public PyPI."""
    clone = "git clone https://github.com/Daybreak-AI-Labs/LightworkOS"
    cohort_installer = "scripts/install_release_cohort.py"
    source_install = (REPO_ROOT / "docs" / "source-install.md").read_text(encoding="utf-8")
    assert clone in source_install
    assert cohort_installer in source_install
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert clone in readme
    assert cohort_installer in readme
    assert "(docs/source-install.md)" in readme
    guides = [
        REPO_ROOT / name
        for name in (
            "README.md",
            "docs/getting-started.md",
            "docs/deployment.md",
            "docs/index.md",
            "docs/handbook.md",
        )
    ]
    guides.extend(sorted((REPO_ROOT / "docs" / "i18n").glob("*/getting-started.md")))
    public_pypi_install = re.compile(r"\bpipx? install\s+['\"]?maverick-")
    for path in guides:
        text = path.read_text(encoding="utf-8")
        assert "pipx install 'maverick-agent[installer]'" not in text, path
        assert not public_pypi_install.search(text), path
        assert "source-install.md" in text, path


def _metadata(relative_path: str) -> dict:
    return tomllib.loads(_read(relative_path))


def _assert_floor(requirements: list[str], package: str, floor: str) -> None:
    matches = [
        Requirement(item)
        for item in requirements
        if Requirement(item).name.casefold() == package.casefold()
    ]
    assert matches, f"{package} is not constrained"
    lower_bounds = [
        Version(spec.version)
        for requirement in matches
        for spec in requirement.specifier
        if spec.operator == ">="
    ]
    exact_versions = [
        Version(spec.version)
        for requirement in matches
        for spec in requirement.specifier
        if spec.operator in {"==", "==="} and "*" not in spec.version
    ]
    has_safe_floor = bool(lower_bounds) and max(lower_bounds) >= Version(floor)
    has_safe_exact_pin = bool(exact_versions) and min(exact_versions) >= Version(floor)
    assert has_safe_floor or has_safe_exact_pin, (
        f"{package} must be constrained to >= {floor}: {matches}"
    )


def test_security_dependency_floors_cover_current_fixed_releases():
    core = _metadata("packages/maverick-core/pyproject.toml")
    core_deps = core["project"]["dependencies"]
    core_extras = core["project"]["optional-dependencies"]
    _assert_floor(core_deps, "click", "8.3.3")
    _assert_floor(core_deps, "cryptography", "48.0.1")
    _assert_floor(core_extras["langchain"], "langchain-core", "1.3.3")
    _assert_floor(core_extras["langchain"], "langsmith", "0.8.18")
    _assert_floor(core_extras["computer-use"], "pillow", "13.0.0")
    _assert_floor(core_extras["release-runtime"], "pypdf", "6.21.4")
    _assert_floor(core_extras["pdf"], "pypdf", "6.21.4")
    _assert_floor(core_extras["evidence-analysis"], "pypdf", "6.21.4")
    _assert_floor(core_extras["evidence-analysis"], "pillow", "13.0.0")
    assert all(
        canonicalize_name(Requirement(item).name) != "pytesseract"
        for item in core_extras["evidence-analysis"]
    )
    _assert_floor(core_extras["dev"], "python-multipart", "0.0.31")
    _assert_floor(core_extras["dev"], "starlette", "1.3.1")

    dashboard = _metadata("packages/maverick-dashboard/pyproject.toml")
    _assert_floor(dashboard["project"]["dependencies"], "python-multipart", "0.0.31")
    _assert_floor(dashboard["project"]["dependencies"], "starlette", "1.3.1")

    channels = _metadata("packages/maverick-channels/pyproject.toml")
    channel_extras = channels["project"]["optional-dependencies"]
    for extra in ("discord", "matrix", "all"):
        _assert_floor(channel_extras[extra], "aiohttp", "3.14.1")
    for extra in ("whatsapp", "sms", "all"):
        _assert_floor(channel_extras[extra], "python-multipart", "0.0.31")
        _assert_floor(channel_extras[extra], "starlette", "1.3.1")

    knowledge = _metadata("packages/maverick-knowledge/pyproject.toml")
    knowledge_extras = knowledge["project"]["optional-dependencies"]
    _assert_floor(knowledge_extras["parsers"], "pypdf", "6.21.4")
    _assert_floor(knowledge_extras["vision"], "pillow", "13.0.0")


def test_all_python_builds_require_patched_setuptools_floor():
    for path in _repository_files(filename="pyproject.toml"):
        metadata = tomllib.loads(path.read_text(encoding="utf-8"))
        build = metadata.get("build-system")
        if build is None:
            continue
        requirements = build.get("requires", [])
        if any(Requirement(item).name.casefold() == "setuptools" for item in requirements):
            _assert_floor(requirements, "setuptools", "83.0.0")


def test_windows_python_autodiscovery_does_not_scan_drive_root():
    script = _read("deploy/desktop/install.ps1")
    resolver = script.split("function Resolve-Python {", 1)[1].split("\nWrite-Host", 1)[0]
    parents = resolver.split("$parents = @(", 1)[1].split("\n  )", 1)[0]
    assert "'C:\\'" not in parents
    assert "$env:LOCALAPPDATA" in parents and "$env:ProgramFiles" in parents
    assert "$env:MAVERICK_PYTHON" in resolver


# ---------- deploy bootstrap MAVERICK_REPO validation ----------

_DEPLOY = Path(__file__).resolve().parents[3] / "deploy" / "desktop"


def test_install_sh_validates_repo_slug():
    body = (_DEPLOY / "install.sh").read_text()
    # The bash validator + the regex it enforces.
    assert "validate_repo" in body
    assert "[A-Za-z0-9._-]+/[A-Za-z0-9._-]+" in body


def test_install_ps1_validates_repo_slug():
    body = (_DEPLOY / "install.ps1").read_text()
    assert "Ensure-RepoSlug" in body
    assert "[A-Za-z0-9._-]+/[A-Za-z0-9._-]+" in body
