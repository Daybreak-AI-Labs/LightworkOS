from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import venv
from pathlib import Path

import pytest
import yaml

MODULE = Path(__file__).with_name("stage_customer.py")
spec = importlib.util.spec_from_file_location("stage_customer", MODULE)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


@pytest.fixture(scope="module")
def native_channel_gui_fixture(tmp_path_factory):
    """A real GUI-subsystem process, without creating a window or installing MSI."""
    compiler = Path(os.environ.get("SystemRoot", "C:/Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if os.name != "nt" or not compiler.is_file() or not shutil.which("pwsh"):
        pytest.skip("Windows C# compiler and PowerShell 7 required for the native pipe regression")
    root = tmp_path_factory.mktemp("native-channel-gui")
    source = root / "Channel.cs"
    source.write_text('''using System;
using System.Threading;
class Channel {
    static int Main(string[] args) {
        if (args.Length != 1 || args[0] != "--maintenance-channel") return 9;
        string mode = Environment.GetEnvironmentVariable("CHANNEL_QUERY_FIXTURE_MODE");
        if (mode == "timeout") { Thread.Sleep(10000); return 0; }
        Thread.Sleep(200);
        if (mode == "failure") { Console.Error.Write("Synthetic channel failure"); return 7; }
        Console.Error.Write(new string('x', 131072));
        Console.WriteLine("{\\"version\\":\\"1.2.3\\",\\"packaged_runtime\\":true}");
        return 0;
    }
}
''', encoding="utf-8")
    compiled = subprocess.run([str(compiler), "/nologo", "/target:winexe",
                               "/out:" + str(root / "maverick-desktop.exe"), str(source)],
                              capture_output=True, text=True, timeout=30, check=False)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    probe = root / "read-channel.ps1"
    probe.write_text('''param([string]$Source,[string]$InstallDirectory,[int]$TimeoutMilliseconds)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Acceptance script did not parse.' }
$function=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-InstalledChannel'},$true))
if ($function.Count -ne 1) { throw 'Expected exactly one native query function.' }
Invoke-Expression $function[0].Extent.Text
$installPath=$InstallDirectory
Read-InstalledChannel -TimeoutMilliseconds $TimeoutMilliseconds | ConvertTo-Json -Compress
''', encoding="utf-8")
    return root, probe


@pytest.mark.parametrize("mode", ["success", "failure", "timeout"])
def test_native_channel_waits_for_gui_process_and_drains_both_pipes(native_channel_gui_fixture, mode):
    root, probe = native_channel_gui_fixture
    env = dict(os.environ, CHANNEL_QUERY_FIXTURE_MODE=mode)
    result = subprocess.run([shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-File", str(probe),
                             "-Source", str(MODULE.with_name("test-completed-rollback.ps1")),
                             "-InstallDirectory", str(root), "-TimeoutMilliseconds", "300" if mode == "timeout" else "10000"],
                            capture_output=True, text=True, encoding="utf-8", timeout=20, env=env, check=False)
    if mode == "success":
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"version": "1.2.3", "packaged_runtime": True}
    else:
        assert result.returncode != 0
        assert ("timed out" if mode == "timeout" else "failed (7)") in result.stderr
        if mode == "failure":
            assert "Synthetic channel failure" in result.stderr


def public_key():
    raw = base64.b64encode(b"Ed" + b"\x00" * 40).decode()
    return base64.b64encode(f"untrusted comment: test-only key\n{raw}\n".encode()).decode()


def test_direct_desktop_native_build_has_a_valid_windows_icon():
    manifest_dir = stage.ROOT / "apps/desktop/src-tauri"
    config = json.loads((manifest_dir / "tauri.conf.json").read_text(encoding="utf-8"))
    icons = [manifest_dir / name for name in config["bundle"]["icon"] if name.lower().endswith(".ico")]
    assert icons, "Direct cargo tests need a Windows icon before customer staging runs"
    for icon in icons:
        assert icon.is_file()
        assert icon.read_bytes()[:4] == b"\x00\x00\x01\x00", "Expected an ICO resource"


def test_synthetic_workflow_signing_explicitly_supplies_the_empty_key_password():
    workflow = yaml.safe_load((stage.ROOT / ".github/workflows/windows-customer.yml").read_text(encoding="utf-8"))
    commands = []
    sources = [step.get("run", "") for step in workflow["jobs"]["build-and-accept"]["steps"]]
    sources.append(MODULE.with_name("fixture-publisher.ps1").read_text(encoding="utf-8"))
    for source in sources:
        for line in source.splitlines():
            if re.match(r"\s*node\s+\S+\s+signer\s+sign\s", line):
                commands.append(shlex.split(line))
    assert len(commands) == 2, "Both synthetic MSI signing paths must be covered"
    for arguments in commands:
        # Tauri generates --ci keys with an empty password, but signer sign
        # still prompts when the password argument is absent, even in CI.
        assert "--password" in arguments, "Headless signing must never prompt for the fixture key password"
        index = arguments.index("--password")
        assert arguments[index + 1] == "", "Use the generated test key's exact empty password"
        assert index + 2 < len(arguments), "The signature must still target its MSI argument"


def test_windows_customer_jobs_use_the_reviewed_windows_python_build():
    workflow = yaml.safe_load((stage.ROOT / ".github/workflows/windows-customer.yml").read_text(encoding="utf-8"))
    # actions/python-versions release 3.12.10-14343898437 provides win32-x64.
    # Later 3.12 security-only pins (including 3.12.13) have no Windows build;
    # matching the Python series alone does not make setup-python installable.
    checked = []
    for name, job in workflow["jobs"].items():
        if not job.get("runs-on", "").startswith("windows-"):
            continue
        steps = [step for step in job["steps"] if step.get("uses", "").startswith("actions/setup-python@")]
        assert len(steps) == 1, f"{name} needs the reviewed Windows Python build"
        assert steps[0]["with"]["python-version"] == "3.12.10", f"{name} must pin an available Windows binary"
        assert steps[0]["with"].get("architecture") == "x64", f"{name} must match the packaged runtime architecture"
        checked.append(name)
    assert set(checked) == {"build-and-accept", "sign-customer-candidate"}


def test_windows_packaging_installs_its_yaml_test_dependency():
    workflow = yaml.safe_load((stage.ROOT / ".github/workflows/windows-customer.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build-and-accept"]["steps"]
    test_index = next(index for index, step in enumerate(steps) if "-m pytest" in step.get("run", ""))
    installers = [line for step in steps[:test_index] for line in step.get("run", "").splitlines()
                  if "-m pip install" in line]
    # PIP_CONSTRAINT restricts a package if installed; it never installs it.
    assert any("pyyaml==6.0.3" in shlex.split(line.lower()) for line in installers)


def test_windows_build_reuses_the_exact_verified_interpreter():
    workflow = yaml.safe_load((stage.ROOT / ".github/workflows/windows-customer.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build-and-accept"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert '"CUSTOMER_BUILD_PYTHON=$buildPython" >> $env:GITHUB_ENV' in commands
    assert "--target-python python" not in commands
    for marker in (" -I -m pip install", " scripts/install_release_cohort.py", " scripts/verify_constraint_closure.py",
                   " -m pytest", " -m PyInstaller"):
        matches = [line for line in commands.splitlines() if marker in line]
        assert matches and all(line.lstrip().startswith("& $env:CUSTOMER_BUILD_PYTHON ") for line in matches), marker
    assert commands.count("scripts/install_release_cohort.py --verify-only") >= 2
    builds = [line for line in commands.splitlines() if "./apps/installer-msi/build-customer.ps1 " in line]
    assert len(builds) == 2 and all("-Python $env:CUSTOMER_BUILD_PYTHON" in line for line in builds)


@pytest.mark.skipif(os.name != "nt", reason="Windows bare-child Python resolves outside the venv")
def test_windows_cohort_workflow_keeps_a_target_only_import_in_its_child(tmp_path):
    workflow = yaml.safe_load((stage.ROOT / ".github/workflows/windows-customer.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build-and-accept"]["steps"]
    command = next(line.strip() for step in steps for line in step.get("run", "").splitlines()
                   if "scripts/install_release_cohort.py" in line)
    words = shlex.split(command)
    script_index = words.index("scripts/install_release_cohort.py")
    arguments = words[script_index + 1:]
    # Seed pip from bundled ensurepip without network access. Python 3.10 has
    # no tomllib, so the real cohort helper needs pip's vendored TOML parser.
    # The fixture module remains local to this environment, never the base.
    target = tmp_path / "isolated Python"
    venv.EnvBuilder(with_pip=True).create(target)
    python = target / "Scripts/python.exe"
    # Fail before running the helper if this prerequisite is unavailable;
    # never let its fallback attempt a network bootstrap inside this test.
    subprocess.run([str(python), "-I", "-c", "from pip._vendor import tomli; assert callable(tomli.loads)"],
                   check=True, capture_output=True)
    purelib = subprocess.check_output([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"], text=True).strip()
    module = "lightwork_target_only_marker"
    (Path(purelib) / (module + ".py")).write_text("MARKER = 'only-in-requested-venv'\n", encoding="utf-8")
    probe = f"import json,sys,{module}; print(json.dumps([sys.executable,{module}.MARKER,{module}.__file__]))"
    wrapper = '''import importlib.util, json, subprocess, sys
spec = importlib.util.spec_from_file_location("cohort_install_probe", sys.argv[1])
helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)
def verify(python, version, packages):
    assert len(packages) == 8
    subprocess.run([python, "-c", sys.argv[3]], check=True)
helper.verify_installed = verify
raise SystemExit(helper.main(json.loads(sys.argv[2]) + ["--verify-only"]))
'''
    env = os.environ.copy()
    env["PATH"] = str(python.parent) + os.pathsep + env.get("PATH", "")
    result = subprocess.run([str(python), "-c", wrapper, str(stage.ROOT / "scripts/install_release_cohort.py"),
        json.dumps(arguments), probe], env=env, cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    executable, marker, module_path = json.loads(result.stdout.strip())
    assert Path(executable).resolve() == python.resolve()
    assert marker == "only-in-requested-venv" and Path(module_path).is_relative_to(target)


@pytest.mark.parametrize("url", [
    "http://updates.example.test/latest.json", "file:///tmp/update", "https://user@example.test/u",
    "https://example.test/u#fragment", "https:///missing", "javascript:alert(1)",
    "https://example.test:bad/u", "https://example.test:0/u", "https://example.test/ u",
])
def test_channel_refuses_unsafe_or_credential_bearing_address(url):
    with pytest.raises(ValueError, match="HTTPS"):
        stage.validate_channel(url, public_key())


@pytest.mark.parametrize("key", ["", "placeholder", "!!!!", base64.b64encode(b"not a public key").decode()])
def test_customer_build_requires_real_key_shape(key):
    with pytest.raises(ValueError, match="minisign"):
        stage.validate_channel("https://updates.example.test/latest.json", key)


def test_every_cohort_member_must_be_in_the_actual_frozen_runtime(tmp_path):
    runtime = tmp_path / "maverick.exe"
    runtime.write_bytes(b"MZfixture")
    cohort = {"version": "1.2.3", "packages": [
        {"distribution": "maverick-agent"}, {"distribution": "maverick-dashboard"},
    ]}
    def incomplete(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, "  maverick-agent 1.2.3\n", "")
    with pytest.raises(ValueError, match="maverick-dashboard"):
        stage.verify_runtime(runtime, cohort, run=incomplete)
    calls = []
    def complete(command, **kwargs):
        calls.append(command[1:])
        assert kwargs["env"]["MAVERICK_HOME"] != str(stage.ROOT)
        return subprocess.CompletedProcess(command, 0, "  maverick-agent 1.2.3\n  maverick-dashboard 1.2.3\n", "")
    assert stage.verify_runtime(runtime, cohort, run=complete)["bytes"] == 9
    assert calls == [["version"], ["release-runtime-check"], ["dashboard", "--help"], ["mcp", "--help"]]


def test_customer_config_bundles_offline_runtime_and_never_signs_with_build_secrets(tmp_path, monkeypatch):
    runtime = tmp_path / "maverick.exe"
    runtime.write_bytes(b"MZfixture")
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: {
        "sha256": stage.hashlib.sha256(runtime.read_bytes()).hexdigest(), "bytes": runtime.stat().st_size,
    })
    path = stage.stage(runtime, tmp_path / "staged", "https://updates.example.test/latest.json", public_key())
    config = json.loads(path.read_text(encoding="utf-8"))
    bundle = config["bundle"]
    assert bundle["targets"] == ["msi"]
    assert bundle["windows"]["webviewInstallMode"]["type"] == "offlineInstaller"
    assert bundle["windows"]["allowDowngrades"] is False
    assert bundle["windows"]["wix"]["upgradeCode"] == stage.UPGRADE_CODE
    assert bundle["windows"]["wix"]["fragmentPaths"] == [
        str(stage.RECOVERY_FRAGMENT.resolve())
    ]
    assert bundle["windows"]["wix"]["componentRefs"] == stage.RECOVERY_COMPONENTS
    assert bundle["createUpdaterArtifacts"] is False
    assert len(bundle["externalBin"]) == 1
    assert Path(bundle["externalBin"][0] + "-" + stage.TARGET + ".exe").read_bytes() == runtime.read_bytes()
    assert config["plugins"]["updater"]["pubkey"] == public_key()
    inventory = json.loads(path.with_name("runtime-inventory.json").read_text(encoding="utf-8"))
    assert len(inventory["packages"]) == 8
    assert inventory["acceptance_fixture"] is False
    assert inventory["publisher_signature_verified"] is False
    assert inventory["installed_recovery"] == {
        "runtime": "maverick-recovery.exe",
        "native_shell": "maverick-recovery-desktop.exe",
        "signed_installer": "Lightwork-recovery.msi",
        "start_menu": "Repair Lightwork",
    }


def test_customer_recovery_fragment_uses_exact_msi_files_and_fixed_app_shortcut():
    import xml.etree.ElementTree as ET

    root = ET.parse(stage.RECOVERY_FRAGMENT).getroot()
    ns = {"w": "http://schemas.microsoft.com/wix/2006/wi"}
    components = {
        node.attrib["Id"]: node
        for node in root.findall("w:Fragment/w:DirectoryRef/w:Component", ns)
    }
    assert set(components) == set(stage.RECOVERY_COMPONENTS)
    copies = {
        node.attrib["Id"]: node.attrib
        for node in components["LightworkRecoveryCopies"].findall("w:CopyFile", ns)
    }
    assert copies["LightworkRecoveryRuntime"]["FileId"] == "Bin_maverick.exe"
    assert copies["LightworkRecoveryRuntime"]["DestinationName"] == "maverick-recovery.exe"
    assert copies["LightworkRecoveryDesktop"]["FileId"] == "Path"
    assert copies["LightworkRecoveryDesktop"]["DestinationName"] == "maverick-recovery-desktop.exe"
    # The package itself is retained by an explicit deferred copy, not a
    # MoveFile row: the installer reads a MoveFile source property as a
    # directory and OriginalDatabase is a file path.
    assert "LightworkRecoveryInstaller" not in copies
    actions = {
        node.attrib["Id"]: node.attrib
        for node in root.findall("w:Fragment/w:CustomAction", ns)
    }
    retain = actions["LightworkRetainInstaller"]
    assert retain["Execute"] == "deferred" and retain["Impersonate"] == "no" and retain["Return"] == "check"
    assert '"[OriginalDatabase]" "[INSTALLDIR]Lightwork-recovery.msi"' in retain["ExeCommand"]
    assert actions["LightworkRetainInstallerRollback"]["Execute"] == "rollback"
    scheduled = {
        node.attrib["Action"]: node
        for node in root.findall("w:Fragment/w:InstallExecuteSequence/w:Custom", ns)
    }
    assert set(scheduled) == {"LightworkRetainInstaller", "LightworkRetainInstallerRollback"}
    assert scheduled["LightworkRetainInstallerRollback"].text == "NOT Installed"
    # The in-app repair reinstalls the same version with REINSTALL=ALL from the
    # verified package; the retained copy must follow that package as well.
    assert scheduled["LightworkRetainInstaller"].text == "NOT Installed OR REINSTALL"
    shortcut = components["LightworkRepairShortcut"].find("w:Shortcut", ns)
    assert shortcut.attrib["Name"] == "Repair Lightwork"
    assert shortcut.attrib["Target"] == "[INSTALLDIR]maverick-recovery-desktop.exe"
    assert shortcut.attrib["Arguments"] == "--maintenance-result"


def test_fault_injection_cannot_enter_a_customer_release(tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: {})
    with pytest.raises(ValueError, match="acceptance fixture"):
        stage.stage(tmp_path / "runtime", tmp_path / "staged", "https://updates.example.test/latest.json",
                    public_key(), fault_fragment=tmp_path / "fault.wxs")
    assert not (tmp_path / "staged").exists()


def test_same_stage_directory_cannot_reuse_stale_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: {})
    with pytest.raises(FileExistsError):
        stage.stage(tmp_path / "runtime", tmp_path, "https://updates.example.test/latest.json", public_key())


def test_acceptance_failure_fragment_is_referenced_so_linker_cannot_drop_it(tmp_path, monkeypatch):
    runtime = tmp_path / "maverick.exe"
    runtime.write_bytes(b"MZfixture")
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: {
        "sha256": stage.hashlib.sha256(runtime.read_bytes()).hexdigest(), "bytes": runtime.stat().st_size,
    })
    path = stage.stage(runtime, tmp_path / "staged", "https://updates.example.test/latest.json", public_key(),
                       fixture_version="0.1.8", fault_fragment=MODULE.with_name("acceptance-failure.wxs"))
    config = json.loads(path.read_text(encoding="utf-8"))
    import xml.etree.ElementTree as ET
    fault_path = next(
        item for item in config["bundle"]["windows"]["wix"]["fragmentPaths"]
        if Path(item).name == "acceptance-failure.wxs"
    )
    fragment = ET.parse(fault_path).getroot()
    ns = {"w": "http://schemas.microsoft.com/wix/2006/wi"}
    feature = fragment.find("w:Fragment/w:Feature", ns)
    assert feature.attrib["Id"] in config["bundle"]["windows"]["wix"]["featureRefs"]
    action = fragment.find("w:Fragment/w:InstallExecuteSequence/w:Custom", ns)
    assert action.attrib["After"] == "InstallFiles"
    assert action.text == "LIGHTWORK_ACCEPTANCE_FAIL=1"


def test_customer_smoke_checks_registered_setup_route_in_both_modes():
    # Compare smoke addresses with actual decorated GET handlers, so an invalid
    # setup URL cannot pass just because normal and recovery smoke copies agree.
    script = MODULE.with_name("test-customer.ps1").read_text(encoding="utf-8")
    app = ast.parse((stage.ROOT / "packages/maverick-dashboard/maverick_dashboard/app.py").read_text(encoding="utf-8"))
    handlers = {}
    for node in app.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr == "get" and decorator.args
                        and isinstance(decorator.args[0], ast.Constant)):
                    handlers[decorator.args[0].value] = node.name
    paths = re.findall(r"Invoke-WebRequest 'http://127\.0\.0\.1:8765([^']+)'", script)
    assert paths
    assert all(path in handlers for path in paths)
    setup_paths = [path for path in paths if handlers[path] == "get_started_page"]
    assert len(setup_paths) == 2, "Normal render and isolated recovery must exercise the real setup handler."


@pytest.mark.skipif(not (shutil.which("pwsh") or shutil.which("powershell")), reason="PowerShell runtime unavailable")
def test_actual_powershell_acceptance_guards_reject_unproven_install_results():
    completed = subprocess.run([
        shutil.which("pwsh") or shutil.which("powershell"), "-NoProfile", "-NonInteractive",
        "-File", str(MODULE.with_name("test-acceptance-guards.ps1")),
        "-ScriptDirectory", str(MODULE.parent),
    ], capture_output=True, text=True, timeout=60, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "8 MSI failure cases, 16 native package-path cases, original-error preservation and 5 native channel cases passed" in completed.stdout
