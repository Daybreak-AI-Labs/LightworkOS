"""Contract tests for the Windows MSI authoring (apps/installer-msi).

Static validation only — building/installing the MSI needs WiX v4 on a
Windows host. These tests pin the invariants that must survive edits: the
.wxs is well-formed XML, the UpgradeCode is present and stable (product
family identity for MajorUpgrade), the install is per-user, and nothing
hardcodes a developer's local paths.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

_HERE = Path(__file__).resolve().parent
_WXS = _HERE / "Package.wxs"
_BOOTSTRAP = _HERE / "maverick_bootstrap.py"
_README = _HERE / "README.md"
_WORKFLOW = _HERE.parents[1] / ".github" / "workflows" / "build-msi.yml"
_NS = "{http://wixtoolset.org/schemas/v4/wxs}"

# The product family identity. NEVER change this value: MajorUpgrade matches
# installed versions by UpgradeCode, so a new GUID breaks upgrades into
# side-by-side installs. (Mirrored in Package.wxs.)
_UPGRADE_CODE = "9E2B7C41-6A8D-4F3B-8E5A-2C90D17B4F6E"


def _package() -> ET.Element:
    root = ET.parse(_WXS).getroot()
    assert root.tag == f"{_NS}Wix"
    pkg = root.find(f"{_NS}Package")
    assert pkg is not None, "Package element missing"
    return pkg


def _bootstrap_module():
    spec = importlib.util.spec_from_file_location("maverick_msi_bootstrap", _BOOTSTRAP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_smoke_wheel(path: Path, version: str) -> None:
    dist_info = f"maverick_agent-{version}.dist-info"
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w", ZIP_DEFLATED) as wheel:
        wheel.writestr("maverick_msi_smoke.py", f"VERSION = {version!r}\n")
        wheel.writestr(
            f"{dist_info}/METADATA",
            "Metadata-Version: 2.1\n"
            "Name: maverick-agent\n"
            f"Version: {version}\n",
        )
        wheel.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\n"
            "Generator: Lightwork MSI smoke\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n",
        )
        wheel.writestr(f"{dist_info}/RECORD", "")


def test_wxs_is_wellformed_wix4_xml():
    _package()  # ET.parse raises on malformed XML; tag asserts pin the v4 namespace


def test_upgrade_code_present_and_stable():
    assert _package().get("UpgradeCode") == _UPGRADE_CODE


def test_major_upgrade_rule_declared():
    pkg = _package()
    up = pkg.find(f"{_NS}MajorUpgrade")
    assert up is not None, "MajorUpgrade element missing"
    assert up.get("DowngradeErrorMessage")


def test_per_user_install_default():
    assert _package().get("Scope") == "perUser"


def test_engineering_only_scope_and_actual_install_path_are_explicit():
    package = _package()
    assert "Engineering Bootstrap" in str(package.get("Name"))

    readme = _README.read_text(encoding="utf-8")
    assert "engineering-only" in readme
    assert r"%LOCALAPPDATA%\Programs\Maverick\bin" in readme
    assert r"%LOCALAPPDATA%\Programs\Lightwork" not in readme
    assert "not a complete Lightwork platform installer" in readme
    assert "live PyPI" in readme
    assert "not a release artifact" in readme

    workflow = _WORKFLOW.read_text(encoding="utf-8")
    assert "build-msi-engineering-bootstrap" in workflow
    assert "maverick-cli-msi-engineering-bootstrap-unsigned" in workflow
    assert 'artifact_class = "engineering_bootstrap"' in workflow
    assert "complete_release_cohort = $false" in workflow
    assert "requires_live_pypi = $true" in workflow


def test_path_component_edits_user_path_only():
    pkg = _package()
    envs = pkg.findall(f".//{_NS}Environment")
    path_envs = [e for e in envs if e.get("Name") == "PATH"]
    assert len(path_envs) == 1, "expected exactly one PATH Environment component"
    env = path_envs[0]
    assert env.get("System") == "no"        # never the machine PATH on perUser
    assert env.get("Part") == "last"        # append, don't clobber
    assert env.get("Permanent") == "no"     # removed on uninstall
    assert env.get("Value") == "[BINFOLDER]"


def test_no_hardcoded_user_paths():
    # Sources must be relative or come from -d preprocessor vars, never a
    # developer's machine layout.
    for name in (
        "Package.wxs",
        "maverick.cmd",
        "maverick_bootstrap.py",
        "build.ps1",
    ):
        text = (_HERE / name).read_text()
        assert not re.search(r"[A-Za-z]:\\Users\\|/home/|/Users/", text), name


def test_launcher_uses_console_script_entry_point():
    # There is no maverick/__main__.py, so `py -m maverick` cannot work; the
    # launcher must go through maverick.cli:main and locate the bundled wheel
    # relative to itself.
    cmd = (_HERE / "maverick.cmd").read_text()
    assert "from maverick.cli import main" in cmd
    assert "%~dp0" in cmd
    assert "maverick_bootstrap.py" in cmd
    assert "PRODUCT_VERSION" in cmd
    assert "import maverick" not in cmd
    assert re.search(r"py -3? -m maverick\b", cmd) is None
    helper = _package().find(f".//{_NS}File[@Id='MaverickBootstrap']")
    assert helper is not None
    assert helper.get("Name") == "maverick_bootstrap.py"
    assert helper.get("Source") == "maverick_bootstrap.py"


def test_build_script_invokes_wix_v4():
    ps1 = (_HERE / "build.ps1").read_text()
    assert "wix build" in ps1
    assert "WheelPath" in ps1 and "ProductVersion" in ps1 and "WheelName" in ps1
    assert "[System.IO.Path]::GetFileName($wheelPath)" in ps1
    assert "PEP 427" in ps1


def test_msi_preserves_complete_pep427_wheel_basename():
    package = _package()
    wheel = package.find(f".//{_NS}File[@Id='MaverickWheel']")
    assert wheel is not None
    assert wheel.get("Source") == "$(var.WheelPath)"
    assert wheel.get("Name") == "$(var.WheelName)"
    assert wheel.get("Name") != "maverick_agent.whl"
    version = package.find(
        f".//{_NS}RegistryValue[@Name='wheel']"
    )
    assert version is not None
    assert version.get("Value") == "$(var.ProductVersion)"


@pytest.mark.parametrize(
    ("installed", "outcome", "install_count"),
    [
        (None, "installed", 1),
        ("9.8.7", "current", 0),
        ("9.8.6", "upgraded", 1),
    ],
)
def test_bootstrap_covers_first_install_same_version_and_upgrade(
    tmp_path,
    installed,
    outcome,
    install_count,
):
    bootstrap = _bootstrap_module()
    wheel_dir = tmp_path / "wheels"
    wheel = wheel_dir / "maverick_agent-9.8.7-py3-none-any.whl"
    _write_smoke_wheel(wheel, "9.8.7")
    state = {"version": installed}
    installs = []

    def install(staged, python):
        installs.append((staged, python))
        state["version"] = "9.8.7"

    result = bootstrap.bootstrap(
        "9.8.7",
        wheel_dir,
        python="test-python",
        version_reader=lambda: state["version"],
        installer=install,
        verifier=lambda expected, _python: state["version"] == expected,
    )

    assert result == outcome
    assert len(installs) == install_count
    if installs:
        assert installs[0] == (wheel, "test-python")


def test_pip_accepts_preserved_staged_name_and_rejects_old_rename(tmp_path):
    """Exercise pip's wheel-filename gate, not merely WiX/XML parsing."""
    wheel_dir = tmp_path / "staged" / "wheels"
    staged = wheel_dir / "maverick_agent-9.8.7-py3-none-any.whl"
    _write_smoke_wheel(staged, "9.8.7")
    bootstrap = _bootstrap_module()
    assert bootstrap.bundled_wheel(wheel_dir, "9.8.7") == staged

    accepted = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-deps",
            "--no-index",
            "--target",
            str(tmp_path / "accepted"),
            str(staged),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert (tmp_path / "accepted" / "maverick_msi_smoke.py").is_file()

    invalid = tmp_path / "maverick_agent.whl"
    invalid.write_bytes(staged.read_bytes())
    rejected = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-deps",
            "--no-index",
            "--target",
            str(tmp_path / "rejected"),
            str(invalid),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert rejected.returncode != 0
    rejection = (rejected.stdout + rejected.stderr).lower()
    assert (
        "invalid wheel filename" in rejection
        or "not a valid wheel filename" in rejection
    )
