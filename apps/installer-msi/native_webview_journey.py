"""Installed WebView2 first-owner, signed update, rollback and startup-help acceptance.

Runs only on the disposable hosted Windows acceptance VM. The driver sends real
WebView input and native menu commands; it never supplies a replacement IPC API.
The signed installers remain same-runtime fixtures, not real release acceptance.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from itertools import islice
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from collect_acceptance_diagnostics import ordinary_file
from native_webview_driver import WebView, app_windows, menu
from native_webview_fixture import (
    available_port,
    command,
    digest,
    download_driver,
    hosted_only,
    hosts_mapping,
    make_tls,
    update_server,
    webview_runtime,
)

# The desktop shell's fixed loopback dashboard port (apps/desktop-runtime probe_address).
LOOPBACK_PORT = 8765
# Fixed lines the desktop shell (apps/desktop-runtime) and the dashboard server
# write while the owned dashboard starts; only these names leave the page.
STARTUP_MARKERS = (
    ("startup_begun", "Starting Lightwork on this computer."),
    ("spawn_failed", "Lightwork could not start:"),
    ("no_output", "No startup output was recorded."),
    ("server_process", "Started server process"),
    ("waiting_for_startup", "Waiting for application startup."),
    ("startup_failed", "Application startup failed."),
    ("startup_complete", "Application startup complete."),
    ("listening", "Uvicorn running on"),
    ("bind_failed", "error while attempting to bind"),
    ("control_unavailable", "owned desktop control pipe is unavailable"),
    ("control_closed", "owned desktop control channel closed"),
    ("traceback", "Traceback (most recent call last)"),
    ("exited", "Lightwork exited:"),
    ("drain_requested", "Saving active work before closing Lightwork"),
    ("drain_completed", "Lightwork completed graceful shutdown."),
    ("drain_forced", "Graceful shutdown did not complete; stopping the owned process tree."),
)
STARTUP_ERROR_TYPES = (
    "AssertionError", "AttributeError", "ClientBindingError", "ConfigError", "ConnectionError", "DatabaseError",
    "EncryptionUnavailable", "FileExistsError", "FileNotFoundError", "ImportError", "IntegrityError",
    "InvalidTenantError", "IsADirectoryError", "KeyError", "MemoryError", "ModuleNotFoundError", "NameError",
    "NotADirectoryError", "OSError", "OperationalError", "PermissionError", "RecursionError", "RuntimeError",
    "SystemExit", "TimeoutError", "TypeError", "UnicodeDecodeError", "UnicodeEncodeError", "ValidationError",
    "ValueError",
)
STARTUP_PROCESS_STATES = ("running", "exited", "not_started", "unavailable", "unreported", "bridge_unavailable",
                          "not_offered_on_recovery_page")
_STARTUP_FRAME = re.compile(r"(?:[A-Za-z0-9_.-]{1,64}\.py|other):[0-9]{1,7}:[A-Za-z_<>][A-Za-z0-9_<>]{0,63}")
_STARTUP_EXIT = re.compile(r"none|0x[0-9a-f]{1,8}|-?[0-9]{1,10}")
# Pinned profiler, installed only into the disposable journey directory when
# the app's own dashboard runs but never serves, to see where startup waits.
PY_SPY = "py-spy==0.4.0"
_SPY_THREAD = re.compile(r'Thread (?:0x)?[0-9A-Fa-f]{1,16} \(([a-z+ ]{1,32})\): "([^"\r\n]{0,128})"')
_SPY_FRAME = re.compile(r"\s+([A-Za-z_<>][A-Za-z0-9_<>.]{0,63}) \((.+):([0-9]{1,7})\)")


def reduced_stacks(dump: str, *, threads: int = 40, frames: int = 30) -> list[str]:
    """Thread names and ``file.py:line:function`` frames from a py-spy dump.

    The process line, paths, arguments and anything else are dropped."""
    kept, seen, depth = [], 0, 0
    for line in dump.splitlines():
        if line.strip().startswith("Thread "):
            seen += 1
            if seen > threads:
                break
            thread = _SPY_THREAD.fullmatch(line.strip())
            name = thread.group(2) if thread and re.fullmatch(r"[A-Za-z0-9_ .:-]{1,64}", thread.group(2)) else "other"
            kept.append(f"thread {name} ({thread.group(1) if thread else 'unknown'})")
            depth = 0
            continue
        frame = _SPY_FRAME.fullmatch(line)
        if frame and seen and depth < frames:
            base = re.split(r"[\\/]", frame.group(2))[-1]
            base = base if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\.py", base) else "other"
            kept.append(f"  {base}:{frame.group(3)}:{frame.group(1)}")
            depth += 1
    return kept


def dashboard_processes(listing, root: int) -> list[int]:
    """``maverick.exe`` processes started by ``root``, including the frozen bootloader's child."""
    children: dict[int, list[dict]] = {}
    for row in listing if isinstance(listing, list) else [listing]:
        if (isinstance(row, dict) and type(row.get("ProcessId")) is int
                and type(row.get("ParentProcessId")) is int):
            children.setdefault(row["ParentProcessId"], []).append(row)
    found, queue = [], [root]
    while queue and len(found) < 8:
        for row in sorted(children.get(queue.pop(0), []), key=lambda item: item["ProcessId"]):
            if str(row.get("Name", "")).lower() == "maverick.exe" and row["ProcessId"] not in found:
                found.append(row["ProcessId"])
                queue.append(row["ProcessId"])
    return found


def verified_driver_version(directory: Path, runtime_version: str, output: str) -> str:
    selected = (directory / "driver-version.txt").read_text(encoding="utf-8").strip()
    observed = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", output)
    if (not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", selected)
            or observed != [selected]
            or selected.split(".")[:3] != runtime_version.split(".")[:3]):
        raise RuntimeError("The signed WebView driver does not match its downloaded version and runtime build.")
    return selected


def support_inventory(bundle: dict, metadata: dict, cohort: dict) -> dict:
    source = [row["distribution"] for row in cohort["packages"]]
    frozen = [row["distribution"] for row in metadata["packages"]]
    version = cohort["version"]
    if (len(source) != 8 or len(set(source)) != 8 or len(frozen) != 8
            or set(source) != set(frozen) or metadata.get("complete_release_cohort") is not True
            or metadata.get("cohort_version") != version
            or bundle.get("versions") != dict.fromkeys(source, version)):
        raise RuntimeError("The frozen support inventory must contain all eight exact release-cohort versions.")
    return {"package_count": 8, "cohort_version": version, "versions": bundle["versions"]}


class Journey:
    def __init__(self, workspace: Path, runner: Path, base: Path, candidate: Path):
        hosted_only()
        if runner.resolve() != Path(os.environ["RUNNER_TEMP"]).resolve():
            raise RuntimeError("Native acceptance must use the current disposable runner.")
        self.workspace, self.base, self.candidate = workspace, base, candidate
        self.directory = runner / ("native-webview-" + uuid.uuid4().hex)
        self.directory.mkdir()
        self.install = self.directory / "app"
        self.state = self.directory / "state"
        self.state.mkdir()
        self.downloads = self.directory / "downloads"
        self.downloads.mkdir()
        self.binary = self.install / "maverick-desktop.exe"
        self.runtime = self.install / "maverick.exe"
        self.recovery_binary = self.install / "maverick-recovery-desktop.exe"
        self.recovery_runtime = self.install / "maverick-recovery.exe"
        self.recovery_installer = self.install / "Lightwork-recovery.msi"
        self.active_binary = self.binary
        self.metadata = json.loads((workspace / "customer-artifacts/runtime-inventory.json").read_text(encoding="utf-8-sig"))
        self.debugger_port, self.driver_port = available_port(), available_port()
        self.view = WebView(self.driver_port)
        self.driver = None
        self.driver_path = None
        self.app = None
        self.driver_log = None
        self.thumbprint = ""
        self.report = {"schema": "lightwork.native-webview-acceptance.v1", "passed": False,
                       "synthetic_fixture_versions": True, "same_frozen_runtime_fixture": True,
                       "native_webview_automated": True, "ipc_mocked": False,
                       "publicly_recognized_publisher": False, "clean_customer_machine": False,
                       "checks": [], "cleanup_errors": []}
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("MAVERICK_", "LIGHTWORK_", "TAURI_SIGNING_"))
                    and key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
        system = os.environ["SystemRoot"]
        self.env.update(MAVERICK_HOME=str(self.state), MAVERICK_CLIENT_ID="native-acceptance",
                        MAVERICK_TENANT="native-acceptance", TAURI_WEBVIEW_AUTOMATION="true",
                        WEBVIEW2_USER_DATA_FOLDER=str(self.directory / "webview-profile"),
                        WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=f"--remote-debugging-port={self.debugger_port}",
                        PATH=f"{system}\\System32;{system};{system}\\System32\\Wbem")
        (self.state / "config.toml").write_text("[client]\nid='native-acceptance'\n[features]\nworkspace_recovery=true\n", encoding="utf-8")
        self.password = secrets.token_urlsafe(32)

    def record(self, phase: str, *, passed=False):
        print("Installed native acceptance: " + phase, flush=True)
        self.report["phase"] = phase
        if passed:
            self.report["checks"].append(phase)
        (self.directory / "acceptance.json").write_text(json.dumps(self.report, indent=2), encoding="utf-8")

    def cleanup_step(self, name: str, operation):
        try:
            operation()
            return True
        except Exception:
            self.report["cleanup_errors"].append(name)
            return False

    def trust(self, phase: str):
        command([shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                 str(self.workspace / "apps/installer-msi/native-fixture-trust.ps1"), "-Phase", phase,
                 "-FixtureDirectory", str(self.directory), "-Thumbprint", self.thumbprint], timeout=60)

    def msi(self, package: Path, action: str):
        log = self.directory / ("msi-" + uuid.uuid4().hex + ".log")
        result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/msiexec.exe"),
            action, str(package.resolve(strict=True)), "/qn", "/norestart", "/L*v", str(log),
            "INSTALLDIR=" + str(self.install)], capture_output=True, timeout=240, check=False)
        allowed = {0, 3010} | ({1605, 1614} if action == "/x" else set())
        if result.returncode not in allowed:
            raise RuntimeError(f"Native fixture installer failed ({result.returncode}); MSI log retained.")

    def start_driver(self, path: Path, *, append=False):
        port = available_port() if append else self.driver_port
        view = WebView(port)
        log = (self.directory / "driver.log").open("ab" if append else "wb")
        try:
            if append:
                log.write(b"\n--- WebDriver restarted after native relaunch ---\n")
                log.flush()
            driver = subprocess.Popen([str(path), f"--port={port}"], env=self.env,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        except BaseException:
            log.close()
            raise
        self.driver_path, self.driver_port = path, port
        self.view, self.driver, self.driver_log = view, driver, log

    def stop_driver(self):
        driver, log = self.driver, self.driver_log
        self.driver = self.driver_log = None
        primary = None
        try:
            if driver:
                with contextlib.suppress(OSError):
                    driver.kill()
                driver.wait(timeout=15)
        except BaseException as error:
            primary = error
        finally:
            if log:
                log.close()
        if primary:
            raise primary

    def restart_driver_after_relaunch(self):
        if not self.driver_path:
            raise RuntimeError("The signed WebView driver path is unavailable.")
        # The previous native process can disappear before WebDriver accepts a
        # DELETE for its now-dead browser target. Reusing that driver leaves a
        # stale session which cannot attach to the replacement WebView. End the
        # local driver process without sending another browser command, then
        # attach a fresh driver to the same installed app debugging endpoint.
        self.view.session = ""
        self.stop_driver()
        self.start_driver(self.driver_path, append=True)
        self.attach()

    def start(self, binary: Path | None = None, *arguments: str):
        if "port_before_first_launch" not in self.report:
            # The shell spawns no dashboard if one already answers at launch.
            self.report["port_before_first_launch"] = self.loopback_probe()["listener"]
        self.active_binary = binary or self.binary
        self.app = subprocess.Popen([str(self.active_binary), *arguments], env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.attach()

    def attach(self):
        self.view.session = ""
        capabilities = self.view.wait(lambda: self.view.attach(self.debugger_port), timeout=120)
        self.report["webview_version"] = capabilities.get("browserVersion")
        self.view.call("POST", self.view.session + "/ms/cdp/execute", {"cmd": "Browser.setDownloadBehavior",
            "params": {"behavior": "allow", "downloadPath": str(self.downloads)}})

    def menu(self, label: str):
        self.view.wait(lambda: app_windows(self.binary))
        menu(self.binary, label)

    def stop(self):
        primary = False
        active_binary = getattr(self, "active_binary", self.binary)
        try:
            windows = app_windows(active_binary)
            if windows:
                menu(active_binary, "Quit Lightwork")
                deadline = time.monotonic() + 20
                while app_windows(active_binary) and time.monotonic() < deadline:
                    time.sleep(.25)
                if app_windows(active_binary):
                    raise RuntimeError("The owned native app did not stop after Quit Lightwork.")
        except BaseException:
            primary = True
            raise
        finally:
            # Quitting the attached driver can alter its WebView. Dispatch and
            # observe the native app's own Quit action before ending the session.
            try:
                self.view.close()
            except Exception:
                if not primary:
                    raise
                self.report["cleanup_errors"].append("webview-session")

    def recovery(self):
        self.menu("Workspace recovery mode")
        self.view.click("#enter-recovery")
        try:
            observed = self.view.wait(self.recovery_progress, timeout=120)
            if observed["reason"] != "none":
                raise RuntimeError("Recovery mode reported a refusal.")
        except (OSError, RuntimeError, KeyError):
            self.report["recovery_entry"] = self.recovery_diagnostic()
            self.report["recovery_startup"] = self.startup_process()
            self.record(self.report["phase"])
            raise RuntimeError("Native recovery mode did not open; bounded recovery_entry diagnostics were retained.") from None
        self.report["recovery_entry"] = observed
        # Keep the actual installation controls and loaded-state requirements.
        self.view.element("#wrec-installation-confirm")
        self.view.wait(lambda: self.view.property("#wrec-refresh", "disabled") is False)

    def recovery_progress(self):
        observed = self.recovery_diagnostic()
        return observed if observed["controls_present"] or observed["reason"] != "none" else None

    def recovery_diagnostic(self):
        # Inspect fixed visible messages inside the page. Never return raw
        # error text, startup logs, URLs, credentials or customer input values.
        script = """
const native = location.origin === 'http://tauri.localhost' && location.pathname === '/recovery.html';
const local = location.origin === 'http://127.0.0.1:8765';
const paths = ['/workspace/recovery','/auth/local-login','/auth/login','/start'];
const page = native ? 'bundled_recovery' : local && paths.includes(location.pathname) ? location.pathname : 'other';
const node = native ? document.querySelector('#details') : null;
const detail = node ? (node.textContent || '').slice(0, 4096) : '';
const reasons = [
  ['The previous workspace is still responding.', 'previous_workspace_running'],
  ['This workspace is managed outside the desktop app.', 'external_workspace'],
  ['The selected workspace mode did not respond', 'startup_deadline'],
  ['Lightwork could not start:', 'launch_failed'],
  ['Open these controls from Lightwork Desktop.', 'native_bridge_unavailable'],
  ["Review and confirm this action in the app's recovery controls.", 'origin_refused'],
  ['Startup state is unavailable.', 'state_unavailable'],
  ['The owned Lightwork process is still stopping.', 'previous_process_stopping'],
  ['Dashboard shutdown timeout must be', 'shutdown_timeout_invalid'],
  ['Port 8765', 'port_conflict'],
  ['not allowed', 'command_refused']
];
let reason = 'none';
if (native && detail && detail !== 'No errors recorded.') {
  reason = (reasons.find(([text]) => detail.includes(text)) || ['', 'unclassified_refusal'])[1];
}
const controls = local && location.pathname === '/workspace/recovery' &&
  document.querySelector('#wrec-installation-confirm') !== null;
return {page, reason, controls_present: controls, ready: document.readyState === 'complete'};
"""
        fallback = {"page": "unavailable", "reason": "none", "controls_present": False, "ready": False}
        try:
            value = self.view.call("POST", self.view.session + "/execute/sync", {"script": script, "args": []})
            if (not isinstance(value, dict) or set(value) != set(fallback)
                    or value["page"] not in {"bundled_recovery", "/workspace/recovery", "/auth/local-login", "/auth/login", "/start", "other"}
                    or value["reason"] not in {"none", "previous_workspace_running", "external_workspace", "startup_deadline",
                                               "launch_failed", "native_bridge_unavailable", "origin_refused", "state_unavailable",
                                               "previous_process_stopping", "shutdown_timeout_invalid", "port_conflict",
                                               "command_refused", "unclassified_refusal"}
                    or type(value["controls_present"]) is not bool or type(value["ready"]) is not bool):
                return fallback
            return value
        except (OSError, RuntimeError, KeyError):
            return fallback

    def authorization(self, *, rollback=False) -> str:
        self.recovery()
        # The page defaults to the protected desktop handoff, which shows no
        # code. This journey carries the manual code fallback the page offers.
        if self.view.property("#wrec-installation-handoff", "checked") is not False:
            self.view.click("#wrec-installation-handoff")
            if self.view.property("#wrec-installation-handoff", "checked") is not False:
                raise RuntimeError("Workspace recovery did not offer its manual approval code.")
        if rollback:
            # Select the real option with WebDriver key input, not JS mutation.
            # Choosing a point clears the confirmation, so confirm after it.
            self.view.keyboard("#wrec-installation-point", "\ue015")
        self.view.click("#wrec-installation-confirm")
        if rollback:
            self.view.click("#wrec-installation-rollback")
        else:
            try:
                self.view.wait(lambda: self.view.property("#wrec-installation-authorize", "disabled") is False, timeout=30)
            except RuntimeError:
                raise RuntimeError("Workspace recovery offered no upgrade authorization; the native release review is missing or expired.") from None
            self.view.click("#wrec-installation-authorize")
        return self.view.wait(lambda: self.view.property("#wrec-installation-code", "value"))

    def assert_version(self, expected: str):
        self.view.wait(lambda: self.view.text("#installed-version") == expected, timeout=180)
        if digest(self.runtime) != self.metadata["runtime"]["sha256"]:
            raise RuntimeError("The installed runtime differs from the declared fixture bytes.")

    def first_owner(self):
        self.record("first-launch-and-named-owner")
        try:
            self.view.wait(lambda: self.view.call("GET", self.view.session + "/url").startswith("http://127.0.0.1:8765/"), timeout=120)
        except (OSError, RuntimeError, KeyError):
            window = {**self.startup_diagnostic(), **self.loopback_probe(), "startup_process": self.startup_process()}
            # Skip only when the shell reported no live dashboard; an unknown
            # state may be the hung process the stacks exist to explain.
            window["dashboard_stacks"] = ("not_running"
                                          if window["startup_process"]["process_state"] in {"exited", "not_started"}
                                          else self.dashboard_stacks())
            self.report["window_at_deadline"] = window
            self.record("first-launch-and-named-owner")
            raise RuntimeError("The native window never reached the local dashboard; bounded window_at_deadline diagnostics were retained.") from None
        self.view.navigate("http://127.0.0.1:8765/start")
        # Fresh installations now open owner setup directly; older first-run
        # pages still offer the explicit link.
        landing = urlsplit(self.view.call("GET", self.view.session + "/url")).path
        if landing == "/start":
            self.view.click('a[href="/auth/local-owner"]')
        elif landing != "/auth/local-owner":
            raise RuntimeError("Native first-owner setup did not open its expected page.")
        self.view.fill('input[name="email"]', "native-owner@example.test")
        self.view.fill('input[name="password"]', self.password)
        # Owner setup asks for the passphrase twice and will not submit otherwise.
        self.view.fill('input[name="password2"]', self.password)
        self.view.click('input[name="confirm"]')
        # Enter activates the real submit button and verifies keyboard use.
        self.view.keyboard('button[type="submit"]', "\ue007")
        try:
            observed = self.view.wait(self.owner_progress)
        except (OSError, RuntimeError, KeyError):
            self.report["owner_setup"] = self.owner_diagnostic()
            self.record("first-launch-and-named-owner")
            raise RuntimeError("Native first-owner setup did not finish; bounded owner_setup diagnostics were retained.") from None
        self.report["owner_setup"] = observed
        if observed["form_rejected"]:
            self.record("first-launch-and-named-owner")
            raise RuntimeError("Native first-owner form was rejected (" + observed["rejection"] + "); bounded owner_setup diagnostics were retained.")
        if not observed["claim_exists"]:
            raise RuntimeError("Native first-owner setup did not create its protected claim.")
        self.view.screenshot(self.directory / "first-owner.png")
        self.record("first-launch-and-named-owner", passed=True)

    def startup_diagnostic(self):
        # Classify in the browser with fixed vocabulary: startup messages, URLs,
        # paths and cookies must never leave the page or enter CI artifacts.
        script = """
const origin = location.origin;
const bundled = {'/': 'bundled_splash', '/index.html': 'bundled_splash',
  '/recovery.html': 'bundled_recovery', '/maintenance.html': 'bundled_maintenance'};
const page = origin === 'http://tauri.localhost' ? (bundled[location.pathname] || 'bundled_other')
  : origin === 'http://127.0.0.1:8765' ? 'dashboard' : 'other';
const splash = page === 'bundled_splash';
const node = splash ? document.querySelector('#status-text') : null;
const text = node ? (node.textContent || '').trim().slice(0, 256) : '';
const states = [['Starting Lightwork', 'starting'], ['Opening your workspace', 'opening_workspace'],
  ['Still starting', 'still_starting'], ['Trying again', 'retrying'],
  ['Port 8765 is occupied by an unrecognized service', 'port_occupied']];
const trouble = splash ? document.querySelector('#trouble') : null;
return {page, splash_status: node ? (states.find(([prefix]) => text.startsWith(prefix)) || ['', 'unclassified'])[1] : 'none',
  trouble_visible: !!trouble && trouble.getClientRects().length > 0, ready: document.readyState === 'complete'};
"""
        fallback = {"page": "unavailable", "splash_status": "none", "trouble_visible": False, "ready": False}
        try:
            result = self.view.call("POST", self.view.session + "/execute/sync", {"script": script, "args": []})
            if (not isinstance(result, dict) or set(result) != set(fallback)
                    or result["page"] not in {"bundled_splash", "bundled_recovery", "bundled_maintenance", "bundled_other", "dashboard", "other"}
                    or result["splash_status"] not in {"none", "starting", "opening_workspace", "still_starting", "retrying",
                                                       "port_occupied", "unclassified"}
                    or type(result["trouble_visible"]) is not bool or type(result["ready"]) is not bool):
                result = fallback
        except (OSError, RuntimeError, KeyError):
            result = fallback
        return result

    def startup_process(self):
        # The shell's own startup report and startup messages, classified in the
        # page: only fixed names, an allowlisted exception type, the exit code
        # and traceback frames as file.py:line:function leave it, never text,
        # paths or the report's correlation id.
        script = "const markers = " + json.dumps(STARTUP_MARKERS) + ", known = " + json.dumps(STARTUP_ERROR_TYPES) + ";" + """
const core = window.__TAURI__ && window.__TAURI__.core;
const empty = (state) => ({process_state: state, packaged_runtime: 'unknown', exit_code: 'none', markers: [],
  error_type: 'none', frames: [], output_kb: 0});
if (!core || typeof core.invoke !== 'function') return empty('bridge_unavailable');
const ask = (name) => core.invoke(name).then((value) => value, () => null);
// The shell offers its startup report on the splash only and refuses it on
// the bundled recovery page; say so there instead of "unreported".
const onRecovery = typeof location !== 'undefined' && location.pathname === '/recovery.html';
// The report first: reading the messages reaps an exited process.
return (onRecovery ? Promise.resolve(null) : ask('startup_support_report')).then((report) => ask('dashboard_diagnostics').then((log) => {
  const states = ['running', 'exited', 'not_started', 'unavailable'];
  const available = report ? report.packaged_runtime_available : undefined;
  const text = typeof log === 'string' ? log.slice(-262144) : '';
  const exit = /Lightwork exited: exit (?:code|status): (0x[0-9a-fA-F]{1,8}|-?[0-9]{1,10})/.exec(text);
  let error_type = 'none', frames = [], current = null;
  for (const line of text.split(/\\r?\\n/).map((value) => value.trim())) {
    if (line.startsWith('Traceback (most recent call last)')) { current = []; continue; }
    const frame = /^File "([^"]*)", line ([0-9]{1,7}), in ([A-Za-z_<>][A-Za-z0-9_<>]{0,63})$/.exec(line);
    if (frame && current) {
      const name = frame[1].split(/[\\\\/]/).pop();
      current.push((/^[A-Za-z0-9_.-]{1,64}\\.py$/.test(name) ? name : 'other') + ':' + frame[2] + ':' + frame[3]);
      continue;
    }
    const error = /^(?:[A-Za-z_][A-Za-z0-9_]*\\.)*([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Unavailable|Exit))(?::|$)/.exec(line);
    if (error) {
      error_type = known.includes(error[1]) ? error[1] : 'other';
      if (current) { frames = current.slice(-8); current = null; }
    }
  }
  return {process_state: onRecovery ? 'not_offered_on_recovery_page'
      : report && states.includes(report.process_state) ? report.process_state : 'unreported',
    packaged_runtime: available === true ? 'present' : available === false ? 'missing'
      : available === null ? 'not_pinned' : 'unknown',
    exit_code: exit ? exit[1].toLowerCase() : 'none',
    markers: markers.filter(([, needle]) => text.includes(needle)).map(([name]) => name),
    error_type, frames, output_kb: Math.min(256, Math.ceil(text.length / 1024))};
}));
"""
        fallback = {"process_state": "unavailable_to_driver", "packaged_runtime": "unknown", "exit_code": "none",
                    "markers": [], "error_type": "none", "frames": [], "output_kb": 0}
        names = [name for name, _needle in STARTUP_MARKERS]
        try:
            value = self.view.call("POST", self.view.session + "/execute/sync", {"script": script, "args": []})
        except (OSError, RuntimeError, KeyError):
            return fallback
        if (not isinstance(value, dict) or set(value) != set(fallback)
                or value["process_state"] not in STARTUP_PROCESS_STATES
                or value["packaged_runtime"] not in {"present", "missing", "not_pinned", "unknown"}
                or not isinstance(value["exit_code"], str) or not _STARTUP_EXIT.fullmatch(value["exit_code"])
                or not isinstance(value["markers"], list) or len(set(map(str, value["markers"]))) != len(value["markers"])
                or not all(isinstance(item, str) and item in names for item in value["markers"])
                or value["error_type"] not in {"none", "other", *STARTUP_ERROR_TYPES}
                or not isinstance(value["frames"], list) or len(value["frames"]) > 8
                or not all(isinstance(item, str) and _STARTUP_FRAME.fullmatch(item) for item in value["frames"])
                or type(value["output_kb"]) is not int or not 0 <= value["output_kb"] <= 256):
            return fallback
        return value

    def dashboard_stacks(self) -> str:
        # Only this app's dashboard process tree, only after it ran without
        # serving; every failure is a fixed reason, never the original error.
        try:
            listing = json.loads(command([shutil.which("pwsh") or "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive",
                "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name"
                " | ConvertTo-Json -Compress"], timeout=60))
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            return "listing_unavailable"
        pids = dashboard_processes(listing, self.app.pid)
        if not pids:
            return "no_dashboard_process"
        tools = self.directory / "py-spy"
        try:
            command([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                     "--only-binary=:all:", "--target", str(tools), PY_SPY], timeout=240)
            spy = next(iter(sorted(tools.rglob("py-spy.exe"))))
        except (OSError, RuntimeError, ValueError, StopIteration, subprocess.SubprocessError):
            return "tool_unavailable"
        lines, dumped = [], False
        for index, pid in enumerate(pids):
            try:
                lines += [f"process {index}", *reduced_stacks(command([str(spy), "dump", "--pid", str(pid)], timeout=60))]
                dumped = True
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                lines.append(f"process {index}: unavailable")
        if not dumped:
            return "dump_failed"
        try:
            (self.directory / "dashboard-stacks.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            return "write_failed"
        return "captured"

    def loopback_probe(self, port: int = LOOPBACK_PORT, timeout: float = 5.0):
        # The desktop shell's own identity handshake (apps/desktop-runtime
        # readiness_headers): exactly one X-Lightwork-Service: dashboard-v1.
        # Loopback only, never through a proxy. Windows takes about two seconds
        # to report a refused loopback connection, hence the five-second bound.
        started = time.monotonic()
        request = urllib.request.Request(f"http://127.0.0.1:{port}/healthz", headers={"Cache-Control": "no-cache"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=timeout) as response:
                status, identity = response.status, response.headers.get_all("X-Lightwork-Service") or []
        except urllib.error.HTTPError as error:
            status, identity = error.code, error.headers.get_all("X-Lightwork-Service") or []
            error.close()
        except urllib.error.URLError as error:
            status, identity = None, "not_listening" if isinstance(error.reason, ConnectionRefusedError) else "no_answer"
        except (OSError, ValueError):
            status, identity = None, "no_answer"
        if status is None:
            listener = identity
        elif identity != ["dashboard-v1"]:
            listener = "answered_without_identity"
        else:
            listener = {200: "answered_ready", 503: "answered_setup_required"}.get(status, "answered_other_status")
        return {"listener": listener, "latency_ms": min(5000, max(0, int((time.monotonic() - started) * 1000)))}

    def owner_diagnostic(self):
        # Classify in the browser: raw alert text, URLs, inputs and cookies must
        # never leave the page or enter driver/CI artifacts for this diagnostic.
        script = """
const path = ['/start','/auth/local-owner','/auth/local-login'].includes(location.pathname)
  ? location.pathname : 'other';
const alert = path.startsWith('/auth/local-') ? document.querySelector('[role="alert"]') : null;
const text = alert ? (alert.textContent || '').trim().slice(0, 2048) : '';
const reasons = {
  'Open this Lightwork page before submitting the form.': 'origin_rejected',
  "Open owner setup on this computer's loopback address.": 'loopback_required',
  'Owner setup does not accept remote or forwarded requests.': 'forwarded_request_rejected',
  'An owner has already been claimed. Sign in to complete or continue setup.': 'already_claimed',
  'Local owner authority is unavailable.': 'authority_unavailable',
  'Authentication policy is unavailable.': 'policy_unavailable',
  'Check the submitted form values.': 'invalid_form',
  'The email or passphrase was not accepted.': 'credentials_rejected'
};
return {ready: document.readyState === 'complete', path, form_rejected: !!alert,
  rejection: alert ? (reasons[text] || 'unclassified_form_rejection') : 'none'};
"""
        fallback = {"ready": False, "path": "unavailable", "form_rejected": False, "rejection": "unavailable"}
        try:
            result = self.view.call("POST", self.view.session + "/execute/sync", {"script": script, "args": []})
            if (not isinstance(result, dict) or set(result) != {"ready", "path", "form_rejected", "rejection"}
                    or type(result["ready"]) is not bool or type(result["form_rejected"]) is not bool
                    or not isinstance(result["path"], str) or not isinstance(result["rejection"], str)
                    or result["path"] not in {"/start", "/auth/local-owner", "/auth/local-login", "other"}
                    or result["rejection"] not in {"none", "origin_rejected", "loopback_required", "forwarded_request_rejected",
                        "already_claimed", "authority_unavailable", "policy_unavailable", "invalid_form", "credentials_rejected",
                        "unclassified_form_rejection"}):
                result = fallback
        except (OSError, RuntimeError, KeyError):
            result = fallback
        return {**result, "claim_exists": (self.state / "dashboard-owner.json").is_file()}

    def owner_progress(self):
        observed = self.owner_diagnostic()
        if observed["ready"] and (observed["path"] == "/start" or observed["form_rejected"]):
            return observed
        return None

    def normal_support(self):
        self.record("normal-support-eight-package-inventory")
        self.view.navigate("http://127.0.0.1:8765/help")
        self.view.click("#support-prepare")
        self.view.wait(lambda: self.view.property("#support-result", "hidden") is False)
        if self.view.property("#support-download", "disabled") is not True:
            raise RuntimeError("Normal support download did not require review and consent.")
        self.view.click("#support-result details summary")
        value = self.view.wait(lambda: self.view.text("#support-preview"))
        if len(value.encode("utf-8")) > 2 * 1024 * 1024:
            raise RuntimeError("The native support preview exceeds its supported size.")
        report = json.loads(value)
        cohort = tomllib.loads((self.workspace / "release-cohort.toml").read_text(encoding="utf-8"))
        inventory = support_inventory(report, self.metadata, cohort)
        if self.password in value or re.search(r"[0-9a-f]{32}:[0-9a-f]{64}", value):
            raise RuntimeError("The native support preview exposed excluded private input.")
        if self.view.call("POST", self.view.session + "/elements", {
                "using": "css selector", "value": "#maintenance-authorization,#wrec-installation-code"}):
            raise RuntimeError("Private maintenance inputs must not appear on the support page.")
        before = set(self.downloads.glob("Lightwork-support-*.json"))
        self.view.click("#support-confirm")
        self.view.click("#support-download")
        self.view.wait(lambda: "reviewed report was downloaded" in self.view.text("#support-status"))

        def downloaded():
            files = set(self.downloads.glob("Lightwork-support-*.json")) - before
            if len(files) != 1:
                return None
            path = files.pop()
            return path if re.fullmatch(r"Lightwork-support-[0-9a-f]{32}\.json", path.name) and path.stat().st_size else None

        path = self.view.wait(downloaded)
        if path.stat().st_size > 2 * 1024 * 1024:
            raise RuntimeError("The native support download exceeds its supported size.")
        text = path.read_text(encoding="utf-8")
        if (json.loads(text) != report or self.password in text
                or re.search(r"[0-9a-f]{32}:[0-9a-f]{64}", text)):
            raise RuntimeError("The native support download differs from the reviewed redacted report.")
        # The actual page verifies API-preview SHA256 against received bytes
        # before saving. Record those saved bytes and compare their full JSON
        # with the visible review without intercepting fetch or replacing IPC.
        inventory["download_sha256"] = digest(path)
        self.report["support_inventory"] = inventory
        self.view.screenshot(self.directory / "normal-support.png")
        self.record("normal-support-eight-package-inventory", passed=True)

    def transition(self, *, rollback=False):
        name = "signed-native-rollback" if rollback else "signed-native-upgrade"
        self.record(name)
        version = self.metadata["version"]
        pieces = version.split(".")
        newer = ".".join(pieces[:2] + [str(int(pieces[2]) + 1)])
        if not rollback:
            # Check for updates records the exact release review that Workspace
            # recovery requires before it authorizes a protected upgrade.
            self.menu("Install & updates")
            self.assert_version(version)
            self.view.click("#check-update")
            self.view.wait(lambda: newer in self.view.text("#update-version"))
        authorization = self.authorization(rollback=rollback)
        self.menu("Install & updates")
        self.assert_version(newer if rollback else version)
        if not rollback:
            self.view.click("#check-update")
            self.view.wait(lambda: newer in self.view.text("#update-version"))
            if self.view.property("#install-update", "disabled") is not True:
                raise RuntimeError("Native upgrade did not require the reviewed administrator authorization.")
            self.reject_invalid_authorization()
            self.record(name)
            # A refused installation consumes the review, not the legitimate
            # administrator grant. Obtain a fresh review with the real control.
            self.view.click("#check-update")
            self.view.wait(lambda: newer in self.view.text("#update-version"))
        self.view.fill("#maintenance-authorization", authorization)
        authorization = ""
        old_pids = {pid for _hwnd, pid in app_windows(self.binary)}
        # Never capture the private grant in a screenshot or test log.
        self.view.click("#rollback-install" if rollback else "#install-update")
        # The real retained helper waits for this native parent, replaces the
        # installer and starts its result window. Reattach to that actual window.
        stage = "process_relaunch"
        try:
            observed = self.view.wait(lambda: self.transition_progress(old_pids), timeout=600)
            if observed != "replacement_ready":
                raise RuntimeError("The native page reported an unsuccessful operation.")
            stage = "driver_reconnect"
            self.restart_driver_after_relaunch()
            stage = "version_verification"
            self.assert_version(version if rollback else newer)
            stage = "completion_receipt"
            text = "returned to " + version if rollback else "updated to " + newer
            observed = self.view.wait(lambda: self.transition_progress(old_pids, text), timeout=600)
            if observed != "completed":
                raise RuntimeError("The native page did not report successful completion.")
        except (OSError, RuntimeError, KeyError):
            self.report["transition"] = {"stage": stage, **self.transition_diagnostic(old_pids)}
            self.record(name)
            raise RuntimeError("Native installation transition did not complete; bounded transition diagnostics were retained.") from None
        self.view.screenshot(self.directory / (name + ".png"))
        self.record(name, passed=True)

    def transition_page_state(self, expected_result=None):
        # Return classifications only. Private authorizations, errors, full
        # URLs and page content must never enter the driver or CI artifacts.
        script = """
if (location.origin !== 'http://tauri.localhost' || location.pathname !== '/maintenance.html'
    || document.readyState !== 'complete') return 'unavailable';
const visibleText = selector => {
  const node = document.querySelector(selector);
  return node && node.getClientRects().length ? (node.textContent || '').trim() : '';
};
const status = visibleText('#maintenance-status');
const result = visibleText('#maintenance-recovery-result');
if (status.startsWith('Lightwork could not complete that step.')) return 'visible_refusal';
if (result.startsWith('An unfinished installation is blocking normal workspace startup.')) return 'incomplete';
return arguments[0] && result.includes(arguments[0]) ? 'completed' : 'pending';
"""
        try:
            value = self.view.call("POST", self.view.session + "/execute/sync", {"script": script, "args": [expected_result]})
            if isinstance(value, str) and value in {"unavailable", "visible_refusal", "incomplete", "completed", "pending"}:
                return value
        except (OSError, RuntimeError, KeyError):
            pass
        return "unavailable"

    # Fixed codes for the reasons the native maintenance commands refuse; the
    # page's own text never leaves the window.
    TRANSITION_REFUSALS = (
        ("Review and confirm the completed-upgrade rollback first", "rollback_unconfirmed"),
        ("Load the protected administrator handoff", "authorization_missing"),
        ("Use the rollback authorization from Workspace recovery", "not_a_rollback_grant"),
        ("Copy the current maintenance authorization", "grant_unreadable"),
        ("expired or was retired", "grant_retired"),
        ("expired or was already used", "grant_expired_or_used"),
        ("no longer matches this completed upgrade", "upgrade_not_recorded_as_completed"),
        ("pre-upgrade snapshot changed", "snapshot_changed"),
        ("still responding", "dashboard_still_responding"),
        ("managed outside the desktop app", "dashboard_not_owned"),
        ("still stopping", "owned_process_still_stopping"),
        ("operation is unsupported", "operation_unsupported"),
        ("Automatic restore is unavailable because spending", "accounting_changed"),
        ("Pause Lightwork from the desktop maintenance controls", "not_paused"),
        ("requires the single control plane lock", "control_plane_locked"),
        ("Installation recovery is unfinished", "recovery_unfinished"),
        ("does not match the verified release", "runtime_not_verified_release"),
    )

    @staticmethod
    def refusal_fingerprint(detail: str) -> str:
        """The page script's fingerprint, for matching a retained code to its product text."""
        sentence = re.sub(r"^Error:\s*", "", detail).split(". ")[0][:200]
        value = 0x811C9DC5
        units = sentence.encode("utf-16-le")  # JavaScript hashes UTF-16 code units
        for index in range(0, len(units), 2):
            value = ((value ^ int.from_bytes(units[index:index + 2], "little")) * 0x01000193) & 0xFFFFFFFF
        return f"other:{value:08x}"

    def transition_refusal(self):
        script = """
const node = document.querySelector('#maintenance-details');
const detail = node ? (node.textContent || '') : '';
for (const [phrase, code] of arguments[0]) if (detail.includes(phrase)) return code;
if (!detail) return 'none';
// An unlisted refusal leaves only an FNV-1a fingerprint of its first sentence,
// which is fixed product text that support matches against the source.
const sentence = detail.replace(/^Error:\\s*/, '').split('. ')[0].slice(0, 200);
let hash = 0x811c9dc5;
for (let i = 0; i < sentence.length; i++) hash = Math.imul(hash ^ sentence.charCodeAt(i), 0x01000193) >>> 0;
return 'other:' + hash.toString(16).padStart(8, '0');
"""
        try:
            value = self.view.call("POST", self.view.session + "/execute/sync",
                                   {"script": script, "args": [list(map(list, self.TRANSITION_REFUSALS))]})
            codes = {code for _phrase, code in self.TRANSITION_REFUSALS} | {"other", "none"}
            if isinstance(value, str) and (value in codes or re.fullmatch(r"other:[0-9a-f]{8}", value)):
                return value
        except (OSError, RuntimeError, KeyError):
            pass
        return "unavailable"

    def transition_progress(self, old_pids, expected_result=None):
        if expected_result is None:
            windows = app_windows(self.binary)
            if windows and all(pid not in old_pids for _hwnd, pid in windows):
                return "replacement_ready"
        state = self.transition_page_state(expected_result)
        return state if state in {"visible_refusal", "incomplete", "completed"} else None

    def transition_diagnostic(self, old_pids):
        page_state = self.transition_page_state()
        result = {"page_state": page_state, "process_state_available": False,
                  "refusal": self.transition_refusal() if page_state == "visible_refusal" else "none",
                  "installed_old_process": False, "installed_new_process": False, "retained_result_windows": 0}
        try:
            windows = app_windows(self.binary)
            result.update(process_state_available=True,
                          installed_old_process=any(pid in old_pids for _hwnd, pid in windows),
                          installed_new_process=any(pid not in old_pids for _hwnd, pid in windows))
            store = self.state / "backups/installation-recovery"
            if store.is_dir():
                # Derive only bounded exact fixture paths; never read a signed
                # record's paths or follow a retained helper through reparse points.
                for point in islice(store.iterdir(), 20):
                    binary = point / "maverick-desktop.exe"
                    if re.fullmatch(r"[0-9a-f]{32}", point.name) and ordinary_file(binary, self.state):
                        result["retained_result_windows"] = min(20, result["retained_result_windows"] + len(app_windows(binary)))
        except (OSError, RuntimeError, KeyError):
            result["process_state_available"] = False
        return result

    def reject_invalid_authorization(self):
        self.record("invalid-maintenance-authorization-refused")
        pids = {pid for _hwnd, pid in app_windows(self.binary)}
        before = (digest(self.binary), digest(self.runtime))
        if not pids:
            raise RuntimeError("The native fixture is not running for its denial check.")
        self.view.fill("#maintenance-authorization", "0" * 32 + ":" + "0" * 64)
        self.view.click("#install-update")
        self.view.wait(lambda: "could not complete that step" in self.view.text("#maintenance-status"))
        if (self.view.property("#maintenance-authorization", "value") != ""
                or self.view.property("#install-update", "disabled") is not True
                or {pid for _hwnd, pid in app_windows(self.binary)} != pids
                or (digest(self.binary), digest(self.runtime)) != before):
            raise RuntimeError("The refused native grant did not preserve the installation and clear private input.")
        self.view.screenshot(self.directory / "invalid-maintenance-authorization.png")
        self.record("invalid-maintenance-authorization-refused", passed=True)

    def repair_damaged_core(self, marker: Path):
        self.record("signed-native-core-repair")
        self.stop()
        for path in (self.recovery_runtime, self.recovery_binary, self.recovery_installer):
            if not path.is_file() or path.is_symlink() or path.stat().st_size < 1:
                raise RuntimeError("The installed package lacks a regular retained recovery artifact.")
        expected_runtime = digest(self.runtime)
        expected_native = digest(self.binary)
        if (digest(self.recovery_runtime) != expected_runtime
                or digest(self.recovery_binary) != expected_native
                or digest(self.recovery_installer) != digest(self.base)):
            raise RuntimeError("The installed recovery set differs from the signed base package and application bytes.")
        channel = json.loads(command([str(self.recovery_binary), "--maintenance-channel"], env=self.env, timeout=30))
        if (channel.get("version") != self.metadata["version"]
                or channel.get("packaged_runtime") is not True):
            raise RuntimeError("The retained native application could not establish its packaged release channel.")
        self.runtime.unlink()
        self.binary.write_bytes(b"synthetic corrupt native shell")
        self.start(self.recovery_binary, "--maintenance-result")
        self.view.wait(lambda: self.view.text("#installed-version") == self.metadata["version"], timeout=120)
        self.view.click("#repair-install")
        self.view.wait(lambda: "Repair version " + self.metadata["version"] in self.view.text("#update-version"), timeout=60)
        if self.view.property("#install-update", "disabled") is not False:
            raise RuntimeError("The reviewed same-version repair was not available without an unrelated upgrade grant.")
        old_pids = {pid for _hwnd, pid in app_windows(self.recovery_binary)}
        if not old_pids:
            raise RuntimeError("The retained native recovery window is unavailable.")
        self.view.click("#install-update")
        stage = "process_relaunch"
        try:
            observed = self.view.wait(lambda: bool(app_windows(self.binary)), timeout=600)
            if not observed:
                raise RuntimeError("The repaired native application did not reopen.")
            if app_windows(self.recovery_binary):
                raise RuntimeError("The retained recovery application remained active after repair.")
            stage = "driver_reconnect"
            self.restart_driver_after_relaunch()
            self.active_binary = self.binary
            stage = "core_byte_verification"
            self.assert_version(self.metadata["version"])
            if (digest(self.runtime) != expected_runtime or digest(self.binary) != expected_native
                    or digest(self.recovery_runtime) != expected_runtime
                    or digest(self.recovery_binary) != expected_native
                    or digest(self.recovery_installer) != digest(self.base)):
                raise RuntimeError("The same-version repair did not restore every exact application and recovery byte.")
            stage = "completion_receipt"
            observed = self.view.wait(
                lambda: self.transition_page_state("repaired " + self.metadata["version"]),
                timeout=300,
            )
            if observed != "completed":
                raise RuntimeError("The native page did not report the completed repair receipt.")
            if marker.read_text(encoding="utf-8") != "before signed repair":
                raise RuntimeError("The application repair changed the protected workspace marker.")
        except (OSError, RuntimeError, KeyError, json.JSONDecodeError):
            self.report["repair"] = {"stage": stage, **self.transition_diagnostic(old_pids)}
            self.record("signed-native-core-repair")
            raise RuntimeError("Native core repair did not complete; bounded repair diagnostics were retained.") from None
        self.view.screenshot(self.directory / "signed-native-core-repair.png")
        self.record("signed-native-core-repair", passed=True)

    def repair_damaged_recovery_set(self, marker: Path):
        self.record("signed-native-recovery-set-repair")
        self.stop()
        expected_runtime = digest(self.runtime)
        expected_native = digest(self.binary)
        if (digest(self.recovery_runtime) != expected_runtime
                or digest(self.recovery_binary) != expected_native
                or digest(self.recovery_installer) != digest(self.base)):
            raise RuntimeError("The installed recovery set differs from the signed base package and application bytes.")
        self.recovery_runtime.unlink()
        self.recovery_binary.write_bytes(b"synthetic corrupt retained native shell")
        self.recovery_installer.unlink()
        self.start()
        # The primary application opens on the dashboard; its maintenance page
        # is reached through the real menu, as the signed upgrade journey does.
        self.menu("Install & updates")
        self.view.wait(lambda: self.view.text("#installed-version") == self.metadata["version"], timeout=120)
        self.view.click("#repair-install")
        self.view.wait(lambda: "Repair version " + self.metadata["version"] in self.view.text("#update-version"), timeout=60)
        if self.view.property("#install-update", "disabled") is not False:
            raise RuntimeError("The primary application did not offer its reviewed same-version repair.")
        old_pids = {pid for _hwnd, pid in app_windows(self.binary)}
        if not old_pids:
            raise RuntimeError("The primary native application window is unavailable.")
        self.view.click("#install-update")
        stage = "process_relaunch"
        try:
            observed = self.view.wait(
                lambda: any(pid not in old_pids for _hwnd, pid in app_windows(self.binary)),
                timeout=600,
            )
            if not observed:
                raise RuntimeError("The repaired primary application did not reopen.")
            stage = "driver_reconnect"
            self.restart_driver_after_relaunch()
            self.active_binary = self.binary
            stage = "recovery_byte_verification"
            self.assert_version(self.metadata["version"])
            if (digest(self.runtime) != expected_runtime or digest(self.binary) != expected_native
                    or digest(self.recovery_runtime) != expected_runtime
                    or digest(self.recovery_binary) != expected_native
                    or digest(self.recovery_installer) != digest(self.base)):
                raise RuntimeError("The primary repair did not restore every exact retained recovery byte.")
            stage = "completion_receipt"
            observed = self.view.wait(
                lambda: self.transition_page_state("repaired " + self.metadata["version"]),
                timeout=300,
            )
            if observed != "completed":
                raise RuntimeError("The native page did not report the completed recovery-set repair receipt.")
            if marker.read_text(encoding="utf-8") != "before signed repair":
                raise RuntimeError("The recovery-set repair changed the protected workspace marker.")
        except (OSError, RuntimeError, KeyError, json.JSONDecodeError):
            self.report["recovery_set_repair"] = {
                "stage": stage,
                **self.transition_diagnostic(old_pids),
            }
            self.record("signed-native-recovery-set-repair")
            raise RuntimeError(
                "Native recovery-set repair did not complete; bounded repair diagnostics were retained."
            ) from None
        self.view.screenshot(self.directory / "signed-native-recovery-set-repair.png")
        self.record("signed-native-recovery-set-repair", passed=True)

    def startup_failure(self):
        self.record("startup-support-with-missing-packaged-runtime")
        self.stop()
        retained = self.install / "maverick.exe.acceptance-retained"
        self.runtime.rename(retained)
        primary = None
        try:
            self.start()
            self.view.wait(lambda: self.view.property("#trouble", "offsetHeight") > 0, timeout=30)
            self.view.click("#trouble details:last-of-type summary")
            self.view.click("#prepare-startup-report")
            value = self.view.wait(lambda: self.view.text("#startup-report"))
            report = json.loads(value)
            if report["schema"] != "lightwork.startup-support.v1" or report["packaged_runtime_available"] is not False:
                raise RuntimeError("Native startup diagnostics did not describe the missing runtime.")
            if self.password in value or str(self.state) in value:
                raise RuntimeError("Native startup report exposed excluded fixture data.")
            self.view.click("#download-startup-report")
            self.view.wait(lambda: "downloaded" in self.view.text("#startup-report-status"))
            downloaded = self.downloads / "Lightwork-startup-support.json"
            self.view.wait(lambda: downloaded.is_file() and downloaded.stat().st_size > 0)
            if json.loads(downloaded.read_text(encoding="utf-8")) != report:
                raise RuntimeError("Downloaded native support bytes differ from the reviewed report.")
            self.report["startup_support_sha256"] = digest(downloaded)
            self.view.screenshot(self.directory / "startup-support.png")
            self.record("startup-support-with-missing-packaged-runtime", passed=True)
        except BaseException as error:
            primary = error
            raise
        finally:
            stopped = self.cleanup_step("startup-probe-stop", self.stop)
            restored = self.cleanup_step("startup-probe-runtime", lambda: retained.rename(self.runtime))
            if primary is None and not (stopped and restored):
                raise RuntimeError("Native startup probe cleanup failed; exact resource names are in its report.")

    def run(self):
        primary = None
        try:
            self.record("install-signed-base")
            self.msi(self.base, "/i")
            version, runtime_directory = webview_runtime()
            self.env["WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"] = str(runtime_directory)
            driver_path = download_driver(self.directory, version)
            self.trust("verify-driver")
            observed_driver = verified_driver_version(self.directory, version, command([str(driver_path), "--version"], timeout=15))
            self.report.update(driver_version=observed_driver, webview_runtime_version=version, driver_sha256=digest(driver_path),
                               base_msi_sha256=digest(self.base), candidate_msi_sha256=digest(self.candidate))
            self.start_driver(driver_path)
            self.thumbprint = make_tls(self.directory)
            self.trust("trust")
            hosts = Path(os.environ["SystemRoot"]) / "System32/drivers/etc/hosts"
            with hosts_mapping(hosts, self.directory.name), update_server(self.directory, self.base, self.candidate, self.metadata) as (requests, _port):
                self.start()
                self.first_owner()
                self.normal_support()
                tenant = self.state / "tenants/native-acceptance"
                tenant.mkdir(parents=True, exist_ok=True)
                marker = tenant / "native-acceptance-state.txt"
                marker.write_text("before signed repair", encoding="utf-8")
                self.repair_damaged_recovery_set(marker)
                self.repair_damaged_core(marker)
                marker.write_text("before signed upgrade", encoding="utf-8")
                self.transition()
                marker.write_text("after signed upgrade", encoding="utf-8")
                self.transition(rollback=True)
                if marker.read_text(encoding="utf-8") != "before signed upgrade":
                    raise RuntimeError("The native rollback did not restore the captured workspace file.")
                self.record("native-rollback-restored-fixture-state", passed=True)
                if requests.count("/base.msi") < 3 or "/next.msi" not in requests:
                    raise RuntimeError("Native repair, upgrade and rollback did not download their signed packages from the compiled HTTPS channel.")
                self.report["https_routes"] = sorted(set(requests))
                self.startup_failure()
            self.report["passed"] = True
        except BaseException as error:
            primary = error
            self.report["failed_phase"] = self.report.get("phase")
            raise
        finally:
            cleanup = [("native-app", self.stop)]
            if self.thumbprint:
                cleanup.append(("fixture-tls-trust", lambda: self.trust("cleanup")))
            cleanup += [("candidate-uninstall", lambda: self.msi(self.candidate, "/x")),
                        ("base-uninstall", lambda: self.msi(self.base, "/x"))]
            for name, operation in cleanup:
                self.cleanup_step(name, operation)
            if self.driver or self.driver_log:
                self.cleanup_step("webview-driver", self.stop_driver)
            self.password = ""
            self.report["journey_passed"] = self.report["passed"]
            self.report["passed"] = self.report["passed"] and not self.report["cleanup_errors"]
            if not self.cleanup_step("acceptance-report", lambda: self.record("complete" if self.report["passed"] else "failed")):
                self.report["passed"] = False
                print("Native acceptance report could not be written; cleanup failure recorded in memory.", flush=True)
            if primary is None and self.report["cleanup_errors"]:
                raise RuntimeError("Native acceptance cleanup failed; exact resource names are in its report.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("workspace", "runner", "base", "candidate"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    Journey(args.workspace.resolve(), args.runner.resolve(), args.base.resolve(), args.candidate.resolve()).run()


if __name__ == "__main__":
    main()
