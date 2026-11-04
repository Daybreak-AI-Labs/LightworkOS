"""Native acceptance control tests: no installer, executable, trust or host mutation."""
from __future__ import annotations

import importlib
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent))
    return (importlib.import_module("native_webview_journey"),
            importlib.import_module("native_webview_driver"))


@pytest.mark.parametrize("mode", ["rejected", "accepted", "missing-claim", "timeout", "malformed"])
@pytest.mark.parametrize("landing_path", ["/start", "/auth/local-owner"])
def test_first_owner_keeps_acceptance_and_records_only_bounded_diagnostics(tmp_path, modules, mode, landing_path):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = journey.state = tmp_path
    journey.password = "synthetic-private-form-value"  # pragma: allowlist secret - noncredential redaction fixture
    journey.report = {"checks": []}
    if mode == "accepted":
        (tmp_path / "dashboard-owner.json").write_text("synthetic claim", encoding="utf-8")
    screenshots, observations, clicks, fills = [], [], [], {}

    class View:
        session = "/session/synthetic"

        def call(self, method, path, payload=None):
            if method == "GET":
                return "http://127.0.0.1:8765" + landing_path
            assert path.endswith("/execute/sync") and payload["args"] == []
            observations.append(True)
            if mode == "malformed":
                return {"private": journey.password}
            return {"ready": mode != "timeout", "path": "/auth/local-owner" if mode == "rejected" else "/start",
                    "form_rejected": mode == "rejected", "rejection": "origin_rejected" if mode == "rejected" else "none"}

        def wait(self, condition, **_kwargs):
            value = condition()
            if value:
                return value
            raise RuntimeError("synthetic private driver error " + journey.password)

        def navigate(self, _address):
            pass

        def click(self, selector):
            clicks.append(selector)

        def fill(self, selector, value):
            fills[selector] = value

        def keyboard(self, _selector, _value):
            pass

        def screenshot(self, path):
            screenshots.append(path)

    journey.view = View()
    if mode == "accepted":
        journey.first_owner()
        assert journey.report["checks"] == ["first-launch-and-named-owner"] and len(screenshots) == 1
    else:
        with pytest.raises(RuntimeError) as error:
            journey.first_owner()
        assert journey.password not in str(error.value)
        assert screenshots == [] and journey.report["checks"] == []
    assert ('a[href="/auth/local-owner"]' in clicks) == (landing_path == "/start")
    # Owner setup asks for the passphrase twice; one box left empty blocks the form.
    assert fills['input[name="password"]'] == fills['input[name="password2"]'] == journey.password
    diagnostic = journey.report["owner_setup"]
    assert set(diagnostic) == {"ready", "path", "form_rejected", "rejection", "claim_exists"}
    assert diagnostic["claim_exists"] == (mode == "accepted")
    assert journey.password not in json.dumps(journey.report)
    if mode == "rejected":
        assert diagnostic["rejection"] == "origin_rejected" and len(observations) == 1
    if mode == "malformed":
        assert diagnostic["path"] == "unavailable"


def test_owner_diagnostic_executes_real_js_without_exporting_private_page_data(tmp_path, modules):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed only for the actual browser-script contract check")
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.state = tmp_path
    scripts = []

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, payload):
            scripts.append(payload["script"])
            return None

    journey.view = View()
    journey.owner_diagnostic()
    source = """
const assert = require('node:assert/strict');
const inspect = new Function(SCRIPT);
global.location = {pathname:'/auth/local-owner', search:'?private-query', hash:'#private-fragment'};
global.document = {readyState:'complete', get cookie(){throw Error('cookie access forbidden')},
  querySelector(selector){assert.equal(selector,'[role="alert"]');return {textContent:message}}};
let message = 'Open this Lightwork page before submitting the form.';
assert.equal(inspect().rejection,'origin_rejected');
message = 'private input should never leave the page';
assert.equal(inspect().rejection,'unclassified_form_rejection');
assert.equal(JSON.stringify(inspect()).includes('private'),false);
location.pathname = '/private-path';
assert.deepEqual(inspect(),{ready:true,path:'other',form_rejected:false,rejection:'none'});
""".replace("SCRIPT", json.dumps(scripts[0]))
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mode", ["accepted", "visible_refusal", "incomplete", "timeout", "reconnect-fails", "missing-receipt", "wrong-version"])
def test_native_transition_diagnostics_never_replace_acceptance_checks(tmp_path, modules, monkeypatch, mode):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = journey.state = tmp_path
    journey.binary = tmp_path / "maverick-desktop.exe"
    journey.metadata = {"version": "0.1.7"}
    journey.report = {"checks": []}
    journey.authorization = lambda **_kwargs: "synthetic-private-grant"
    journey.menu = lambda _label: None
    actions, versions = [], []
    launched = False

    def windows(_path):
        replaced = launched and mode in {"accepted", "reconnect-fails", "missing-receipt", "wrong-version"}
        return [(123, 2 if replaced else 1)]

    def version(expected):
        versions.append(expected)
        if len(versions) == 2 and mode == "wrong-version":
            raise RuntimeError("private runtime details must stay excluded")

    class View:
        session = "/session/synthetic"

        def fill(self, _selector, _value):
            pass

        def click(self, selector):
            nonlocal launched
            assert selector == "#rollback-install"
            launched = True

        def call(self, _method, _path, payload):
            if mode in {"visible_refusal", "incomplete"}:
                return mode
            return "completed" if mode == "accepted" and payload["args"][0] else "pending"

        def wait(self, condition, **_kwargs):
            observed = condition()
            if not observed:
                raise RuntimeError("synthetic private driver error")
            return observed

        def screenshot(self, _path):
            actions.append("screenshot")

    journey.view = View()
    journey.assert_version = version
    def reconnect():
        actions.append("restart-driver")
        if mode == "reconnect-fails":
            raise RuntimeError("synthetic stale driver session")
    journey.restart_driver_after_relaunch = reconnect
    monkeypatch.setattr(module, "app_windows", windows)
    if mode == "accepted":
        journey.transition(rollback=True)
        assert journey.report["checks"] == ["signed-native-rollback"]
        assert actions == ["restart-driver", "screenshot"]
        assert versions == ["0.1.8", "0.1.7"]
    else:
        with pytest.raises(RuntimeError, match="bounded transition diagnostics") as error:
            journey.transition(rollback=True)
        assert "private" not in str(error.value)
        assert "private" not in json.dumps(journey.report)
        assert journey.report["checks"] == [] and "screenshot" not in actions
        diagnostic = journey.report["transition"]
        assert set(diagnostic) == {"stage", "page_state", "refusal", "process_state_available", "installed_old_process",
                                   "installed_new_process", "retained_result_windows"}
        expected = ("completion_receipt" if mode == "missing-receipt" else
                    "version_verification" if mode == "wrong-version" else
                    "driver_reconnect" if mode == "reconnect-fails" else "process_relaunch")
        assert diagnostic["stage"] == expected
        assert diagnostic["installed_old_process"] == (expected == "process_relaunch")


def test_native_upgrade_checks_for_updates_before_recovery_authorizes_it(tmp_path, modules):
    # Workspace recovery authorizes an upgrade only for the exact release the
    # native app reviewed, so Check for updates must come first.
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.metadata = {"version": "0.1.7"}
    journey.report = {"checks": []}
    journey.directory = tmp_path
    steps = []

    class Stop(Exception):
        pass

    class View:
        def click(self, selector):
            steps.append(("click", selector))

        def text(self, selector):
            assert selector == "#update-version"
            return "Version 0.1.8 is available."

        def wait(self, condition, **_kwargs):
            return condition()

    def authorization(**kwargs):
        steps.append(("authorization", kwargs))
        raise Stop

    journey.view = View()
    journey.menu = lambda label: steps.append(("menu", label))
    journey.assert_version = lambda expected: steps.append(("version", expected))
    journey.authorization = authorization
    with pytest.raises(Stop):
        journey.transition()
    assert steps == [("menu", "Install & updates"), ("version", "0.1.7"), ("click", "#check-update"),
                     ("authorization", {"rollback": False})]
    # A rollback needs no new release review.
    steps.clear()
    with pytest.raises(Stop):
        journey.transition(rollback=True)
    assert steps == [("authorization", {"rollback": True})]


class _RecoveryPage:
    """Synthetic Workspace recovery controls: the handoff box starts checked, as shipped."""

    def __init__(self, *, review=True, handoff_toggles=True):
        self.review, self.handoff_toggles = review, handoff_toggles
        self.handoff, self.confirmed, self.code, self.clicks = True, False, "", []

    def click(self, selector):
        self.clicks.append(selector)
        if selector == "#wrec-installation-handoff" and self.handoff_toggles:
            self.handoff = not self.handoff
        if selector == "#wrec-installation-confirm":
            self.confirmed = not self.confirmed
        if selector in {"#wrec-installation-authorize", "#wrec-installation-rollback"} and self.confirmed:
            # The page issues a visible code only for the manual fallback.
            self.code = "" if self.handoff else "a" * 32 + ":" + "b" * 64

    def keyboard(self, selector, _text):
        self.clicks.append(selector)
        if selector == "#wrec-installation-point":
            # As shipped: choosing another point clears the confirmation.
            self.confirmed = False

    def property(self, selector, name):
        return {("#wrec-installation-handoff", "checked"): self.handoff,
                ("#wrec-installation-authorize", "disabled"): not self.review,
                ("#wrec-installation-code", "value"): self.code}[(selector, name)]

    def wait(self, condition, **_kwargs):
        value = condition()
        if not value:
            raise RuntimeError("The expected native UI transition did not complete before its deadline.")
        return value


def _authorizing_journey(module, page):
    journey = module.Journey.__new__(module.Journey)
    journey.recovery = lambda: None
    journey.view = page
    return journey


@pytest.mark.parametrize("rollback", [False, True])
def test_recovery_authorization_takes_the_manual_code_instead_of_the_default_handoff(modules, rollback):
    module, _ = modules
    page = _RecoveryPage()
    assert _authorizing_journey(module, page).authorization(rollback=rollback) == "a" * 32 + ":" + "b" * 64
    assert page.clicks == (["#wrec-installation-handoff", "#wrec-installation-point", "#wrec-installation-confirm",
                            "#wrec-installation-rollback"] if rollback else
                           ["#wrec-installation-handoff", "#wrec-installation-confirm", "#wrec-installation-authorize"])
    assert page.handoff is False


def test_recovery_without_a_manual_code_choice_stops_before_authorizing(modules):
    module, _ = modules
    page = _RecoveryPage(handoff_toggles=False)
    with pytest.raises(RuntimeError, match="did not offer its manual approval code"):
        _authorizing_journey(module, page).authorization()
    assert page.clicks == ["#wrec-installation-handoff"]


def test_recovery_without_a_native_review_names_the_missing_upgrade_authorization(modules):
    module, _ = modules
    page = _RecoveryPage(review=False)
    with pytest.raises(RuntimeError, match="native release review is missing or expired"):
        _authorizing_journey(module, page).authorization()
    assert page.clicks == ["#wrec-installation-handoff", "#wrec-installation-confirm"]


def test_relaunch_uses_fresh_driver_without_deleting_dead_browser_session(tmp_path, modules, monkeypatch):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = tmp_path
    journey.env = {"FIXTURE": "bounded"}
    journey.driver_path = tmp_path / "msedgedriver.exe"
    journey.driver_port = 1000
    journey.driver_log = (tmp_path / "driver.log").open("wb")
    actions = []

    class OldView:
        session = "/session/stale"

        def close(self):
            raise AssertionError("A dead browser session must not receive DELETE")

    class Driver:
        def kill(self):
            actions.append("kill-stale-driver")

        def wait(self, *, timeout):
            actions.append(("wait-stale-driver", timeout))

    journey.view, journey.driver = OldView(), Driver()
    monkeypatch.setattr(module, "available_port", lambda: 2000)

    class NewView:
        def __init__(self, port):
            actions.append(("new-view", port))
            self.session = ""

    class NewDriver:
        def __init__(self, command, **kwargs):
            actions.append(("new-driver", command, kwargs["env"]))

    monkeypatch.setattr(module, "WebView", NewView)
    monkeypatch.setattr(module.subprocess, "Popen", NewDriver)
    journey.attach = lambda: actions.append("attach-replacement")
    journey.restart_driver_after_relaunch()

    assert journey.driver_port == 2000
    assert journey.view.session == ""
    assert actions[:3] == ["kill-stale-driver", ("wait-stale-driver", 15), ("new-view", 2000)]
    assert actions[-1] == "attach-replacement"
    assert b"WebDriver restarted after native relaunch" in (tmp_path / "driver.log").read_bytes()
    journey.driver_log.close()


@pytest.mark.parametrize("mode", ["accepted", "refused", "timeout", "malformed"])
def test_recovery_entry_keeps_controls_and_records_only_bounded_diagnostics(tmp_path, modules, mode):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = tmp_path
    journey.report = {"phase": "signed-native-upgrade", "checks": []}
    actions = []
    journey.menu = lambda label: actions.append(label)

    class View:
        session = "/session/synthetic"

        def click(self, selector):
            actions.append(selector)

        def call(self, _method, _path, _payload):
            if mode == "malformed":
                return {"private": "excluded input"}
            return {"page": "/workspace/recovery" if mode == "accepted" else "bundled_recovery",
                    "reason": "previous_workspace_running" if mode == "refused" else "none",
                    "controls_present": mode == "accepted", "ready": True}

        def wait(self, condition, **_kwargs):
            result = condition()
            if not result:
                raise RuntimeError("private driver error must not leave the fixture")
            return result

        def element(self, selector):
            actions.append(selector)

        def property(self, selector, name):
            actions.append((selector, name))
            return False

    journey.view = View()
    journey.startup_process = lambda: {"process_state": "unreported", "markers": ["drain_requested"]}
    if mode == "accepted":
        journey.recovery()
        assert actions[-2:] == ["#wrec-installation-confirm", ("#wrec-refresh", "disabled")]
        assert "recovery_startup" not in journey.report
    else:
        with pytest.raises(RuntimeError, match="bounded recovery_entry diagnostics") as error:
            journey.recovery()
        assert "private" not in str(error.value)
        assert "#wrec-installation-confirm" not in actions
        # The shell's own startup lines say whether the previous workspace drained.
        assert journey.report["recovery_startup"] == {"process_state": "unreported", "markers": ["drain_requested"]}
    assert "private" not in json.dumps(journey.report)
    assert set(journey.report["recovery_entry"]) == {"page", "reason", "controls_present", "ready"}
    assert journey.report["checks"] == []


def test_recovery_diagnostic_classifies_actual_script_without_exporting_private_details(modules):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the actual browser-script contract check")
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    scripts = []

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, payload):
            scripts.append(payload["script"])
            return None

    journey.view = View()
    assert journey.recovery_diagnostic()["page"] == "unavailable"
    source = """
const assert = require('node:assert/strict');
const inspect = new Function(SCRIPT);
global.location = {origin:'http://tauri.localhost', pathname:'/recovery.html',search:'?private',hash:'#private'};
let detail = 'No errors recorded.', controls = true;
global.document = {readyState:'complete',get cookie(){throw Error('cookie access forbidden')},
  querySelector(selector){if(selector==='#details')return {textContent:detail};
    assert.equal(selector,'#wrec-installation-confirm'); return controls?{}:null}};
assert.deepEqual(inspect(),{page:'bundled_recovery',reason:'none',controls_present:false,ready:true});
detail = 'The previous workspace is still responding. private excluded context';
assert.equal(inspect().reason,'previous_workspace_running');
detail = 'The owned Lightwork process is still stopping. Maintenance and recovery have not started.';
assert.equal(inspect().reason,'previous_process_stopping');
detail = 'Dashboard shutdown timeout must be finite and between 0 and 300 seconds.';
assert.equal(inspect().reason,'shutdown_timeout_invalid');
detail = 'Port 8765 belongs to an unrecognized service; no process was stopped.';
assert.equal(inspect().reason,'port_conflict');
detail = 'switch_recovery_mode not allowed. Permissions associated with this command: private';
assert.equal(inspect().reason,'command_refused');
detail = 'Error: ' + DEADLINE;
assert.equal(inspect().reason,'startup_deadline');
detail = 'Error: private arbitrary error';
assert.equal(inspect().reason,'unclassified_refusal');
assert.equal(JSON.stringify(inspect()).includes('private'),false);
location.origin='http://127.0.0.1:8765'; location.pathname='/workspace/recovery';
assert.deepEqual(inspect(),{page:'/workspace/recovery',reason:'none',controls_present:true,ready:true});
controls=false; assert.equal(inspect().controls_present,false);
location.origin='https://example.test'; assert.equal(inspect().controls_present,false);
location.pathname='/private'; assert.equal(inspect().page,'other');
""".replace("SCRIPT", json.dumps(scripts[0]))
    # The shell's own deadline message, read from the page that throws it.
    recovery_page = (Path(__file__).parents[1] / "desktop" / "ui" / "recovery.js").read_text(encoding="utf-8")
    deadline = re.search(r'throw new Error\("(The selected workspace mode did not [^"]+)"\)', recovery_page)
    assert deadline is not None
    source = source.replace("DEADLINE", json.dumps(deadline.group(1)))
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr


def test_transition_page_script_classifies_visible_fixed_messages_without_private_data(modules):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the actual browser-script contract check")
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    scripts = []

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, payload):
            scripts.append(payload["script"])
            return {"private": "unexpected driver payload"}

    journey.view = View()
    assert journey.transition_page_state() == "unavailable"
    source = """
const assert = require('node:assert/strict');
const inspect = new Function(SCRIPT);
global.location = {origin:'http://tauri.localhost',pathname:'/maintenance.html',search:'?private',hash:'#private'};
let visible = true, status = '', result = '';
global.document = {readyState:'complete',get cookie(){throw Error('cookie access forbidden')},
  querySelector(selector){assert.ok(['#maintenance-status','#maintenance-recovery-result'].includes(selector));
    return {getClientRects:()=>visible?[{}]:[],textContent:selector==='#maintenance-status'?status:result}}};
status = 'Lightwork could not complete that step. Open Details for support to see why, then try again or contact your administrator.';
assert.equal(inspect(), 'visible_refusal');
status = 'Lightwork could not complete that step. The approval code has expired or was already used. Get a new code in Workspace recovery mode and paste it again.';
assert.equal(inspect(), 'visible_refusal');
status = 'Lightwork could not complete that step. Open Details for support to see why, then try again or contact your administrator.';
visible = false; assert.equal(inspect(), 'pending'); visible = true;
status = 'private arbitrary error'; result = 'An unfinished installation is blocking normal workspace startup. private';
assert.equal(inspect(), 'incomplete');
result = 'Completed operations: returned to 0.1.7'; assert.equal(inspect('returned to 0.1.7'),'completed');
assert.equal(inspect('returned to 0.1.6'),'pending');
location.origin = 'http://127.0.0.1:8765'; assert.equal(inspect(),'unavailable');
""".replace("SCRIPT", json.dumps(scripts[0]))
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr


def test_transition_diagnostic_enumerates_only_bounded_exact_retained_fixture_paths(tmp_path, modules, monkeypatch):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.state = tmp_path
    journey.binary = tmp_path / "installed/maverick-desktop.exe"
    journey.transition_page_state = lambda: "unavailable"
    store = tmp_path / "backups/installation-recovery"
    for name in ["private-invalid-point", *[f"{index:032x}" for index in range(25)]]:
        point = store / name
        point.mkdir(parents=True)
        (point / "maverick-desktop.exe").write_bytes(b"synthetic native; never executed")
        (point / "record.json").write_text("private record must not be read")
    called = []

    def windows(binary):
        called.append(binary)
        if binary == journey.binary:
            return [(11, 7), (12, 9)]
        assert binary.parent.parent == store and re.fullmatch(r"[0-9a-f]{32}", binary.parent.name)
        return [(13, 10), (14, 11)]

    monkeypatch.setattr(module, "app_windows", windows)
    diagnostic = journey.transition_diagnostic({7})
    assert len(called) <= 21
    assert diagnostic == {"page_state": "unavailable", "process_state_available": True, "refusal": "none",
                          "installed_old_process": True, "installed_new_process": True, "retained_result_windows": 20}
    assert "private" not in json.dumps(diagnostic)


def test_transition_refusal_names_only_a_fixed_reason_code(modules):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the actual browser-script contract check")
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    scripts = []

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, payload):
            scripts.append(payload)
            return "private page text"

    journey.view = View()
    assert journey.transition_refusal() == "unavailable"
    payload = scripts[0]
    source = """
const assert = require('node:assert/strict');
const classify = new Function(SCRIPT);
let detail = '';
global.document = {querySelector(selector){assert.equal(selector, '#maintenance-details');
  return {textContent: detail}}};
const table = ARGS[0];
detail = 'Error: This maintenance authorization expired or was already used. Review it again in Workspace recovery. private';
assert.equal(classify(table), 'grant_expired_or_used');
detail = 'Error: Lightwork is still responding. Installation has not started; retry after it closes.';
assert.equal(classify(table), 'dashboard_still_responding');
detail = 'Error: Use the rollback authorization from Workspace recovery.';
assert.equal(classify(table), 'not_a_rollback_grant');
detail = 'Error: Automatic restore is unavailable because spending differs. Protected files: world.db';
assert.equal(classify(table), 'accounting_changed');
detail = 'Error: A private unknown failure. More private text'; console.log(classify(table));
detail = 'Error: Ünïcode refusal'; console.log(classify(table));
detail = ''; assert.equal(classify(table), 'none');
""".replace("SCRIPT", json.dumps(payload["script"])).replace("ARGS", json.dumps(payload["args"]))
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr
    # Only a fixed-width fingerprint of the first sentence leaves the window,
    # and it matches the support-side computation exactly.
    assert result.stdout.split() == [module.Journey.refusal_fingerprint("Error: A private unknown failure. More"),
                                     module.Journey.refusal_fingerprint("Ünïcode refusal")]
    assert "private" not in result.stdout


def test_startup_probe_restores_runtime_and_preserves_primary_failure(tmp_path, modules):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.install = tmp_path
    journey.runtime = tmp_path / "maverick.exe"
    journey.runtime.write_bytes(b"synthetic runtime; never executed")
    journey.report = {"cleanup_errors": []}
    journey.record = lambda *_args, **_kwargs: None
    stops = []

    def stop():
        stops.append(True)
        if len(stops) > 1:
            raise RuntimeError("synthetic stop failure")

    def start():
        raise ValueError("original startup failure")

    journey.stop, journey.start = stop, start
    with pytest.raises(ValueError, match="original startup failure"):
        journey.startup_failure()
    assert journey.runtime.read_bytes() == b"synthetic runtime; never executed"
    assert not (tmp_path / "maverick.exe.acceptance-retained").exists()
    assert journey.report["cleanup_errors"] == ["startup-probe-stop"]


def test_driver_cleanup_timeout_keeps_original_failure_and_writes_report(tmp_path, modules):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory, journey.base, journey.candidate = tmp_path, Path("base"), Path("next")
    journey.thumbprint, journey.password = "", "synthetic private passphrase"
    journey.report = {"passed": False, "checks": [], "cleanup_errors": []}
    journey.stop = lambda: None
    calls = []

    def msi(package, action):
        calls.append((package, action))
        if action == "/i":
            raise ValueError("original installer failure")

    class Driver:
        def kill(self):
            pass

        def wait(self, *, timeout):
            raise subprocess.TimeoutExpired("synthetic driver", timeout)

    journey.msi, journey.driver, journey.driver_log = msi, Driver(), None
    with pytest.raises(ValueError, match="original installer failure"):
        journey.run()
    assert calls == [(Path("base"), "/i"), (Path("next"), "/x"), (Path("base"), "/x")]
    assert journey.report["failed_phase"] == "install-signed-base"
    assert journey.report["cleanup_errors"] == ["webview-driver"]
    assert journey.password == ""
    assert (tmp_path / "acceptance.json").is_file()


def test_click_reacquires_element_after_page_replaces_disabled_control(modules):
    _, module = modules
    view = module.WebView(1)
    view.session = "/session/synthetic"
    finds, clicks = [], []

    def call(method, path, payload=None):
        if path.endswith("/execute/sync"):
            return True
        if path.endswith("/element"):
            finds.append(True)
            return {module.ELEMENT: "old" if len(finds) == 1 else "current"}
        if path.endswith("/enabled"):
            return "/current/" in path
        if path.endswith("/click"):
            clicks.append(path)

    def wait(condition, **_kwargs):
        for _ in range(3):
            if result := condition():
                return result
        raise AssertionError("The control was never reacquired after replacement")

    view.call, view.wait = call, wait
    view.click("#continue")
    assert clicks == ["/session/synthetic/element/current/click"]


def test_host_guard_precedes_any_journey_directory_or_process_creation(tmp_path, modules, monkeypatch):
    module, _ = modules
    def deny():
        raise RuntimeError("hosted runner required")
    monkeypatch.setattr(module, "hosted_only", deny)
    with pytest.raises(RuntimeError, match="hosted runner required"):
        module.Journey(tmp_path, tmp_path, tmp_path / "base", tmp_path / "next")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("selected,runtime,output,accepted", [
    ("140.0.3485.50", "140.0.3485.50", "MSEdgeDriver 140.0.3485.50", True),
    ("140.0.3485.50", "140.0.3485.52", "MSEdgeDriver 140.0.3485.50", True),
    ("140.0.3486.50", "140.0.3485.52", "MSEdgeDriver 140.0.3486.50", False),
    ("140.0.3485.50", "140.0.3485.52", "MSEdgeDriver 140.0.3485.51", False),
    ("140.0.3485.50", "140.0.3485.52", "140.0.3485.50 140.0.3485.52", False),
    ("140.0.3485", "140.0.3485.52", "MSEdgeDriver 140.0.3485.50", False),
])
def test_observed_driver_is_exact_download_and_same_runtime_build(tmp_path, modules, selected, runtime, output, accepted):
    module, _ = modules
    (tmp_path / "driver-version.txt").write_text(selected, encoding="utf-8")
    if accepted:
        assert module.verified_driver_version(tmp_path, runtime, output) == selected
    else:
        with pytest.raises(RuntimeError, match="downloaded version and runtime build"):
            module.verified_driver_version(tmp_path, runtime, output)


@pytest.mark.parametrize("leak,changed", [(False, False), (True, False), (False, True)])
def test_invalid_grant_journey_requires_cleared_input_and_unchanged_bytes(tmp_path, modules, monkeypatch, leak, changed):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = tmp_path
    journey.binary, journey.runtime = tmp_path / "native.exe", tmp_path / "runtime.exe"
    journey.binary.write_bytes(b"synthetic native")
    journey.runtime.write_bytes(b"synthetic runtime")
    journey.report = {"checks": []}
    monkeypatch.setattr(module, "app_windows", lambda _path: [(123, 456)])
    actions = []

    class View:
        def fill(self, selector, value):
            actions.append(("fill", selector))
            assert re.fullmatch(r"0{32}:0{64}", value)

        def click(self, selector):
            actions.append(("click", selector))
            if changed:
                journey.runtime.write_bytes(b"unexpected changed runtime")

        def wait(self, condition):
            assert condition()

        def text(self, selector):
            assert selector == "#maintenance-status"
            return "Lightwork could not complete that step."

        def property(self, selector, name):
            return ("private fixture input" if leak else "") if name == "value" else True

        def screenshot(self, path):
            actions.append(("screenshot", path.name))

    journey.view = View()
    if leak or changed:
        with pytest.raises(RuntimeError, match="preserve the installation and clear private input"):
            journey.reject_invalid_authorization()
        assert not any(action[0] == "screenshot" for action in actions)
    else:
        journey.reject_invalid_authorization()
        assert actions == [("fill", "#maintenance-authorization"), ("click", "#install-update"),
                           ("screenshot", "invalid-maintenance-authorization.png")]
        assert journey.report["checks"] == ["invalid-maintenance-authorization-refused"]


def test_journey_id_selectors_exist_in_actual_bundled_and_dashboard_pages(modules):
    module, _ = modules
    root = Path(__file__).parents[2]
    ids = set()

    class Page(HTMLParser):
        def handle_starttag(self, _tag, attrs):
            for key, value in attrs:
                if key == "id":
                    ids.add(value)

    parser = Page()
    for path in (root / "apps/desktop/ui/index.html", root / "apps/desktop/ui/maintenance.html",
                 root / "apps/desktop/ui/recovery.html",
                 root / "packages/maverick-dashboard/maverick_dashboard/templates/support.html",
                 root / "packages/maverick-dashboard/maverick_dashboard/templates/workspace_recovery.html"):
        parser.feed(path.read_text(encoding="utf-8"))
    selectors = set(re.findall(r'["\']#([a-z][a-z0-9-]*)', Path(module.__file__).read_text(encoding="utf-8")))
    assert selectors and selectors <= ids, f"Missing real controls: {selectors - ids}"


def test_journey_fills_every_required_owner_setup_field(modules):
    module, _ = modules
    templates = Path(__file__).parents[2] / "packages/maverick-dashboard/maverick_dashboard/templates"
    required = set()

    class Form(HTMLParser):
        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if tag == "input" and "required" in values and values.get("name"):
                required.add(values["name"])

    for name in ("local_owner.html", "_passphrase_fields.html"):
        Form().feed((templates / name).read_text(encoding="utf-8"))
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert required == {"email", "password", "password2", "confirm"}
    missing = {name for name in required if f'input[name="{name}"]' not in source}
    assert not missing, f"The native journey leaves required owner setup fields empty: {missing}"


def test_failed_final_report_does_not_replace_original_error(tmp_path, modules, monkeypatch):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory, journey.base, journey.candidate = tmp_path, Path("base"), Path("next")
    journey.thumbprint, journey.password = "", "synthetic passphrase"
    journey.driver = journey.driver_log = None
    journey.report = {"passed": False, "checks": [], "cleanup_errors": []}
    journey.stop = lambda: None
    def msi(_package, action):
        if action == "/i":
            raise ValueError("original failure")
    def record(phase):
        journey.report["phase"] = phase
        if phase == "failed":
            raise OSError("synthetic read-only report destination")
    journey.msi, journey.record = msi, record
    with pytest.raises(ValueError, match="original failure"):
        journey.run()
    assert journey.password == ""
    assert journey.report["cleanup_errors"] == ["acceptance-report"]
    assert "synthetic passphrase" not in json.dumps(journey.report)


@pytest.mark.parametrize("quit_fails,close_fails", [(False, False), (True, False), (True, True)])
def test_stop_quits_owned_native_window_before_closing_driver(modules, monkeypatch, quit_fails, close_fails):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.binary = Path("synthetic-owned-app.exe")
    journey.report = {"cleanup_errors": []}
    calls = []
    running = True

    def windows(binary):
        assert binary == journey.binary
        calls.append("window-present" if running else "window-exited")
        return [(123, 456)] if running else []

    def quit_menu(binary, label):
        nonlocal running
        assert binary == journey.binary and label == "Quit Lightwork"
        calls.append("native-quit")
        if quit_fails:
            raise ValueError("original Quit failure")
        running = False

    class View:
        def close(self):
            calls.append("driver-close")
            if close_fails:
                raise RuntimeError("secondary driver failure")

    journey.view = View()
    monkeypatch.setattr(module, "app_windows", windows)
    monkeypatch.setattr(module, "menu", quit_menu)
    if quit_fails:
        with pytest.raises(ValueError, match="original Quit failure"):
            journey.stop()
    else:
        journey.stop()
        assert "window-exited" in calls
        assert calls.index("window-exited") < calls.index("driver-close")
    assert calls.index("native-quit") < calls.index("driver-close")
    assert calls[-1] == "driver-close"
    assert journey.report["cleanup_errors"] == (["webview-session"] if close_fails else [])


@pytest.mark.parametrize("failure", [None, "missing-package", "not-installed", "wrong-version", "extra-package",
                                     "cohort-mismatch", "incomplete-build", "manifest-duplicate", "private-control",
                                     "private-grant", "private-password", "download-changed", "unconfirmed-download"])
def test_normal_support_journey_reviews_exact_cohort_and_download(tmp_path, modules, failure):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.workspace = Path(__file__).parents[2]
    journey.directory, journey.downloads = tmp_path, tmp_path / "downloads"
    journey.downloads.mkdir()
    journey.password = "synthetic-private-passphrase"  # pragma: allowlist secret - noncredential redaction fixture
    journey.report = {"checks": []}
    cohort = module.tomllib.loads((journey.workspace / "release-cohort.toml").read_text(encoding="utf-8"))
    journey.metadata = {"complete_release_cohort": failure != "incomplete-build", "cohort_version": cohort["version"], "packages": cohort["packages"]}
    report = {"versions": {row["distribution"]: cohort["version"] for row in cohort["packages"]}, "config_redacted": {}}
    if failure == "missing-package":
        del report["versions"]["maverick-knowledge"]
    elif failure == "not-installed":
        report["versions"]["maverick-knowledge"] = "not installed"
    elif failure == "wrong-version":
        report["versions"]["maverick-installer"] = "99.0.0"
    elif failure == "extra-package":
        report["versions"]["unexpected"] = cohort["version"]
    elif failure == "cohort-mismatch":
        journey.metadata["cohort_version"] = "99.0.0"
    elif failure == "manifest-duplicate":
        journey.metadata["packages"] = [cohort["packages"][0]] * 8
    elif failure == "private-grant":
        report["config_redacted"]["fixture"] = "a" * 32 + ":" + "b" * 64
    elif failure == "private-password":
        report["config_redacted"]["fixture"] = journey.password
    actions = []

    class View:
        def navigate(self, address):
            actions.append(("navigate", address))

        def click(self, selector):
            actions.append(("click", selector))
            if selector == "#support-download":
                value = dict(report)
                if failure == "download-changed":
                    value["unexpected"] = "unreviewed"
                (journey.downloads / ("Lightwork-support-" + "a" * 32 + ".json")).write_text(json.dumps(value), encoding="utf-8")

        def wait(self, condition, **_kwargs):
            result = condition()
            assert result
            return result

        def property(self, selector, name):
            if selector == "#support-result":
                assert name == "hidden"
                return False
            assert selector == "#support-download" and name == "disabled"
            return failure != "unconfirmed-download"

        def text(self, selector):
            return json.dumps(report) if selector == "#support-preview" else "The reviewed report was downloaded."

        def call(self, method, path, payload):
            assert method == "POST" and path.endswith("/elements")
            assert payload["using"] == "css selector"
            return [{"synthetic-private-control": True}] if failure == "private-control" else []

        def screenshot(self, path):
            actions.append(("screenshot", path.name))

        session = "/session/synthetic"

    journey.view = View()
    if failure:
        with pytest.raises(RuntimeError):
            journey.normal_support()
        assert not any(action[0] == "screenshot" for action in actions)
        assert "normal-support-eight-package-inventory" not in journey.report["checks"]
    else:
        journey.normal_support()
        assert actions == [("navigate", "http://127.0.0.1:8765/help"), ("click", "#support-prepare"),
                           ("click", "#support-result details summary"), ("click", "#support-confirm"),
                           ("click", "#support-download"), ("screenshot", "normal-support.png")]
        assert journey.report["support_inventory"]["package_count"] == 8
        assert journey.report["support_inventory"]["versions"] == report["versions"]
        assert journey.report["checks"] == ["normal-support-eight-package-inventory"]


def test_recovery_set_repair_opens_install_and_updates_before_reading_the_version(tmp_path, modules, monkeypatch):
    # The primary application opens on the dashboard. Its maintenance page,
    # the only page with #installed-version, is reached through the real
    # "Install & updates" menu, exactly as the signed upgrade journey does.
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory, journey.state = tmp_path, tmp_path / "state"
    journey.report = {"checks": []}
    install = tmp_path / "install"
    install.mkdir()
    journey.install = install
    journey.binary, journey.runtime = install / "maverick-desktop.exe", install / "maverick.exe"
    journey.recovery_binary = install / "maverick-recovery-desktop.exe"
    journey.recovery_runtime = install / "maverick-recovery.exe"
    journey.recovery_installer = install / "Lightwork-recovery.msi"
    journey.base = tmp_path / "base.msi"
    native, runtime, package = b"synthetic native shell", b"synthetic runtime", b"synthetic base package"
    for path, content in ((journey.binary, native), (journey.recovery_binary, native), (journey.runtime, runtime),
                          (journey.recovery_runtime, runtime), (journey.base, package), (journey.recovery_installer, package)):
        path.write_bytes(content)
    journey.metadata = {"version": "0.1.7", "runtime": {"sha256": module.digest(journey.runtime)}}
    marker = tmp_path / "marker.txt"
    marker.write_text("before signed repair", encoding="utf-8")
    actions = []
    state = {"page": "dashboard", "repair_offered": False, "repaired": False}
    journey.stop = lambda: actions.append("stop")
    journey.start = lambda *arguments: (actions.append(("start", arguments)), state.update(page="dashboard"))
    journey.restart_driver_after_relaunch = lambda: actions.append("restart-driver")

    def open_menu(binary, label):
        assert binary == journey.binary
        actions.append(("menu", label))
        if label == "Install & updates":
            state["page"] = "maintenance"

    monkeypatch.setattr(module, "menu", open_menu)
    monkeypatch.setattr(module, "app_windows", lambda _path: [(2, 2)] if state["repaired"] else [(1, 1)])

    class View:
        session = "/session/synthetic"

        def wait(self, condition, **_kwargs):
            try:
                value = condition()
            except (OSError, RuntimeError, KeyError):
                value = None
            if not value:
                raise RuntimeError("The expected native UI transition did not complete before its deadline.")
            return value

        def text(self, selector):
            actions.append(("text", selector))
            if state["page"] != "maintenance":
                raise RuntimeError("WebView command element failed (404).")
            if selector == "#installed-version":
                return "0.1.7"
            if selector == "#update-version":
                return "Repair version 0.1.7" if state["repair_offered"] else ""
            raise AssertionError(selector)

        def property(self, selector, name):
            assert (selector, name) == ("#install-update", "disabled")
            return not state["repair_offered"]

        def click(self, selector):
            actions.append(("click", selector))
            if selector == "#repair-install":
                state["repair_offered"] = True
            if selector == "#install-update":
                # The real repair restores the retained recovery set and reopens
                # the primary application on its maintenance result page.
                journey.recovery_binary.write_bytes(native)
                journey.recovery_runtime.write_bytes(runtime)
                journey.recovery_installer.write_bytes(package)
                state["repaired"] = True

        def call(self, method, path, payload):
            assert method == "POST" and path.endswith("/execute/sync")
            return "completed" if state["repaired"] and payload["args"] == ["repaired 0.1.7"] else "pending"

        def screenshot(self, path):
            actions.append(("screenshot", path.name))

    journey.view = View()
    journey.repair_damaged_recovery_set(marker)

    assert journey.report["checks"] == ["signed-native-recovery-set-repair"]
    assert actions[:3] == ["stop", ("start", ()), ("menu", "Install & updates")]
    assert actions.index(("menu", "Install & updates")) < actions.index(("text", "#installed-version"))
    assert actions[-1] == ("screenshot", "signed-native-recovery-set-repair.png")
    assert module.digest(journey.recovery_binary) == module.digest(journey.binary)
    assert module.digest(journey.recovery_runtime) == module.digest(journey.runtime)
    assert module.digest(journey.recovery_installer) == module.digest(journey.base)
    assert marker.read_text(encoding="utf-8") == "before signed repair"


def test_startup_diagnostic_executes_real_js_with_fixed_vocabulary(modules):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the actual browser-script contract check")
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    scripts = []

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, payload):
            scripts.append(payload["script"])
            return {"private": "unexpected driver payload"}

    journey.view = View()
    assert journey.startup_diagnostic() == {
        "page": "unavailable", "splash_status": "none", "trouble_visible": False, "ready": False}
    source = """
const assert = require('node:assert/strict');
const inspect = new Function(SCRIPT);
global.location = {origin:'http://tauri.localhost', pathname:'/', search:'?private', hash:'#private'};
let status = 'Still starting\\u2026', trouble = true;
global.document = {readyState:'complete', get cookie(){throw Error('cookie access forbidden')},
  querySelector(selector){assert.ok(['#status-text', '#trouble'].includes(selector));
    return selector === '#status-text' ? {textContent: status} : {getClientRects: () => trouble ? [{}] : []}}};
assert.deepEqual(inspect(), {page:'bundled_splash', splash_status:'still_starting', trouble_visible:true, ready:true});
status = 'Starting Lightwork\\u2026'; trouble = false;
assert.deepEqual(inspect(), {page:'bundled_splash', splash_status:'starting', trouble_visible:false, ready:true});
status = 'Opening your workspace\\u2026'; assert.equal(inspect().splash_status, 'opening_workspace');
status = 'Trying again\\u2026'; assert.equal(inspect().splash_status, 'retrying');
status = 'Port 8765 is occupied by an unrecognized service. private excluded context';
assert.equal(inspect().splash_status, 'port_occupied');
status = 'private arbitrary startup text'; assert.equal(inspect().splash_status, 'unclassified');
assert.equal(JSON.stringify(inspect()).includes('private'), false);
location.pathname = '/index.html'; assert.equal(inspect().page, 'bundled_splash');
location.pathname = '/recovery.html';
assert.deepEqual(inspect(), {page:'bundled_recovery', splash_status:'none', trouble_visible:false, ready:true});
location.pathname = '/maintenance.html'; assert.equal(inspect().page, 'bundled_maintenance');
location.pathname = '/private-bundled-page'; assert.equal(inspect().page, 'bundled_other');
location.origin = 'http://127.0.0.1:8765'; location.pathname = '/private-path';
assert.deepEqual(inspect(), {page:'dashboard', splash_status:'none', trouble_visible:false, ready:true});
location.origin = 'https://example.test'; assert.equal(inspect().page, 'other');
""".replace("SCRIPT", json.dumps(scripts[0]))
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("behavior,expected", [
    ("ready", "answered_ready"), ("setup", "answered_setup_required"), ("other", "answered_other_status"),
    ("no-identity", "answered_without_identity"), ("duplicate-identity", "answered_without_identity"),
    ("wrong-identity", "answered_without_identity"), ("refused", "not_listening"), ("hang", "no_answer")])
def test_loopback_probe_uses_the_desktop_shell_identity_handshake(modules, behavior, expected):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            requests.append((self.path, self.headers.get("Cache-Control")))
            if behavior == "hang":
                import time
                time.sleep(2)
                return
            self.send_response({"ready": 200, "setup": 503, "other": 404}.get(behavior, 200))
            if behavior in {"ready", "setup", "other", "duplicate-identity"}:
                self.send_header("X-Lightwork-Service", "dashboard-v1")
            if behavior == "duplicate-identity":
                self.send_header("X-Lightwork-Service", "dashboard-v1")
            if behavior == "wrong-identity":
                self.send_header("X-Lightwork-Service", "somebody-else")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    if behavior == "refused":
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0))
            port = free.getsockname()[1]
        server = None
    else:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        observed = journey.loopback_probe(port=port, timeout=.4 if behavior == "hang" else 5.0)
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
    assert set(observed) == {"listener", "latency_ms"}
    assert observed["listener"] == expected
    assert type(observed["latency_ms"]) is int and 0 <= observed["latency_ms"] <= 5000
    if behavior != "refused":
        assert requests == [("/healthz", "no-cache")]


def test_first_owner_records_the_window_and_port_when_the_dashboard_is_never_reached(tmp_path, modules, monkeypatch):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = journey.state = tmp_path
    journey.password = "synthetic-private-form-value"  # pragma: allowlist secret - noncredential redaction fixture
    journey.report = {"checks": []}
    deadlines = []

    class View:
        session = "/session/synthetic"

        def call(self, method, path, payload=None):
            if method == "GET":
                return "http://tauri.localhost/private-path?token=private-query"
            assert path.endswith("/execute/sync") and payload["args"] == []
            return {"page": "bundled_splash", "splash_status": "still_starting", "trouble_visible": True, "ready": True}

        def wait(self, _condition, **kwargs):
            deadlines.append(kwargs["timeout"])
            raise RuntimeError("synthetic private driver error " + journey.password)

        def navigate(self, _address):
            raise AssertionError("must not navigate before the dashboard answered")

    journey.view = View()
    monkeypatch.setattr(journey, "loopback_probe", lambda: {"listener": "not_listening", "latency_ms": 3})
    process = {"process_state": "exited", "packaged_runtime": "present", "exit_code": "3", "markers": ["traceback"],
               "error_type": "RuntimeError", "frames": ["_server.py:57:serve"], "output_kb": 2}
    monkeypatch.setattr(journey, "startup_process", lambda: process)
    with pytest.raises(RuntimeError, match="bounded window_at_deadline diagnostics") as error:
        journey.first_owner()
    assert deadlines == [120]
    assert journey.password not in str(error.value) and "private" not in str(error.value)
    expected = {"page": "bundled_splash", "splash_status": "still_starting", "trouble_visible": True,
                "ready": True, "listener": "not_listening", "latency_ms": 3, "startup_process": process,
                "dashboard_stacks": "not_running"}
    assert journey.report["window_at_deadline"] == expected
    assert journey.report["checks"] == [] and "owner_setup" not in journey.report
    written = json.loads((tmp_path / "acceptance.json").read_text(encoding="utf-8"))
    assert written["window_at_deadline"] == expected and written["phase"] == "first-launch-and-named-owner"


def test_startup_process_reads_the_app_startup_state_with_fixed_vocabulary(modules):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the actual browser-script contract check")
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    scripts = []

    class View:
        session = "/session/synthetic"

        def call(self, _method, path, payload):
            assert path.endswith("/execute/sync") and payload["args"] == []
            scripts.append(payload["script"])
            return {"private": "unexpected driver payload"}

    journey.view = View()
    assert journey.startup_process() == {
        "process_state": "unavailable_to_driver", "packaged_runtime": "unknown", "exit_code": "none",
        "markers": [], "error_type": "none", "frames": [], "output_kb": 0}
    source = """
const assert = require('node:assert/strict');
const inspect = new Function(SCRIPT);
let report = null, log = '', calls = [];
global.window = {__TAURI__: {core: {invoke(name) {
  calls.push(name);
  if (name === 'startup_support_report') return report instanceof Error ? Promise.reject(report) : Promise.resolve(report);
  if (name === 'dashboard_diagnostics') return log instanceof Error ? Promise.reject(log) : Promise.resolve(log);
  throw Error('unexpected command ' + name);
}}}};
(async () => {
  report = {schema: 'lightwork.startup-support.v1', process_state: 'exited', packaged_runtime_available: true,
    correlation_id: 'private-correlation'};
  log = [
    'Starting Lightwork on this computer.',
    'INFO:     Started server process [4242]',
    'INFO:     Waiting for application startup.',
    'Traceback (most recent call last):',
    '  File "C:\\\\Users\\\\private-person\\\\AppData\\\\Local\\\\Lightwork\\\\_internal\\\\maverick_dashboard\\\\_server.py", line 57, in serve',
    '  File "C:\\\\private\\\\weird name.py", line 9, in <module>',
    'RuntimeError: owned desktop control pipe is unavailable at C:\\\\Users\\\\private-person',
    'Lightwork exited: exit code: 0xC0000005',
  ].join('\\r\\n');
  let observed = await inspect();
  assert.deepEqual(calls, ['startup_support_report', 'dashboard_diagnostics']);
  assert.deepEqual(observed, {process_state: 'exited', packaged_runtime: 'present', exit_code: '0xc0000005',
    markers: ['startup_begun', 'server_process', 'waiting_for_startup', 'control_unavailable', 'traceback', 'exited'],
    error_type: 'RuntimeError', frames: ['_server.py:57:serve', 'other:9:<module>'], output_kb: 1});
  assert.equal(JSON.stringify(observed).includes('private'), false);
  report = {process_state: 'running', packaged_runtime_available: null};
  log = 'Starting Lightwork on this computer.\\nINFO:     Application startup complete.\\nINFO:     Uvicorn running on http://127.0.0.1:8765';
  observed = await inspect();
  assert.equal(observed.process_state, 'running'); assert.equal(observed.packaged_runtime, 'not_pinned');
  assert.deepEqual(observed.markers, ['startup_begun', 'startup_complete', 'listening']);
  assert.equal(observed.exit_code, 'none'); assert.equal(observed.error_type, 'none'); assert.deepEqual(observed.frames, []);
  report = {process_state: 'private-state', packaged_runtime_available: false};
  log = 'ValueError: private\\nmaverick.crypto_at_rest.EncryptionUnavailable: private\\nPrivateCustomError: private\\nLightwork exited: exit code: 3';
  observed = await inspect();
  assert.equal(observed.process_state, 'unreported'); assert.equal(observed.packaged_runtime, 'missing');
  assert.equal(observed.error_type, 'other'); assert.equal(observed.exit_code, '3');
  log = 'maverick.crypto_at_rest.EncryptionUnavailable: private detail';
  assert.equal((await inspect()).error_type, 'EncryptionUnavailable');
  report = new Error('private refusal'); log = new Error('private refusal');
  assert.deepEqual(await inspect(), {process_state: 'unreported', packaged_runtime: 'unknown', exit_code: 'none',
    markers: [], error_type: 'none', frames: [], output_kb: 0});
  report = {process_state: 'not_started', packaged_runtime_available: true};
  log = 'No startup output was recorded. Lightwork may already be running independently.';
  observed = await inspect();
  assert.equal(observed.process_state, 'not_started'); assert.deepEqual(observed.markers, ['no_output']);
  // The shell refuses its startup report on the recovery page: say so.
  global.location = {origin: 'http://tauri.localhost', pathname: '/recovery.html'};
  calls = []; report = {process_state: 'running', packaged_runtime_available: true};
  log = 'Starting Lightwork on this computer.';
  observed = await inspect();
  assert.deepEqual(calls, ['dashboard_diagnostics']);
  assert.equal(observed.process_state, 'not_offered_on_recovery_page');
  assert.deepEqual(observed.markers, ['startup_begun']);
  delete global.location;
  delete global.window.__TAURI__;
  assert.deepEqual(await inspect(), {process_state: 'bridge_unavailable', packaged_runtime: 'unknown', exit_code: 'none',
    markers: [], error_type: 'none', frames: [], output_kb: 0});
})().catch((error) => { console.error(error); process.exit(1); });
""".replace("SCRIPT", json.dumps(scripts[0]))
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("value", [
    {"process_state": "running", "packaged_runtime": "present", "exit_code": "none", "markers": ["startup_begun"],
     "error_type": "none", "frames": [], "output_kb": 1},
    {"process_state": "exited", "packaged_runtime": "missing", "exit_code": "-1", "markers": ["traceback", "exited"],
     "error_type": "ModuleNotFoundError", "frames": ["app.py:1350:_lifespan", "other:9:<module>"], "output_kb": 256},
])
def test_startup_process_keeps_a_well_formed_classification(modules, value):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, _payload):
            return value

    journey.view = View()
    assert journey.startup_process() == value


@pytest.mark.parametrize("change", [
    {"process_state": "private"}, {"packaged_runtime": True}, {"exit_code": "C:\\private"}, {"exit_code": 3},
    {"markers": ["private"]}, {"markers": ["traceback", "traceback"]}, {"markers": "traceback"},
    {"error_type": "PrivateError"}, {"frames": ["C:\\private\\app.py:1:f"]}, {"frames": ["app.py:1:f"] * 9},
    {"output_kb": True}, {"output_kb": 257}, {"extra": "private"},
])
def test_startup_process_refuses_anything_outside_its_vocabulary(modules, change):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    value = {"process_state": "running", "packaged_runtime": "present", "exit_code": "none", "markers": [],
             "error_type": "none", "frames": [], "output_kb": 0, **change}

    class View:
        session = "/session/synthetic"

        def call(self, _method, _path, _payload):
            return value

    journey.view = View()
    assert journey.startup_process()["process_state"] == "unavailable_to_driver"


def test_first_launch_records_who_answered_the_dashboard_port_beforehand(tmp_path, modules, monkeypatch):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.binary, journey.env, journey.report = tmp_path / "maverick-desktop.exe", {}, {"checks": []}
    probes, launched = [], []
    monkeypatch.setattr(journey, "loopback_probe", lambda: probes.append(1) or {"listener": "answered_ready", "latency_ms": 4})
    monkeypatch.setattr(journey, "attach", lambda: None)
    monkeypatch.setattr(module.subprocess, "Popen", lambda arguments, **_kwargs: launched.append(arguments) or object())
    journey.start()
    journey.start(tmp_path / "maverick-recovery-desktop.exe", "--maintenance-result")
    assert probes == [1]
    assert journey.report["port_before_first_launch"] == "answered_ready"
    assert launched == [[str(tmp_path / "maverick-desktop.exe")],
                        [str(tmp_path / "maverick-recovery-desktop.exe"), "--maintenance-result"]]


SPY_DUMP = """Process 4242: C:\\Users\\private-person\\AppData\\Local\\Lightwork\\maverick.exe dashboard --private-token abc
Python v3.12.10 (C:\\Users\\private-person\\AppData\\Local\\Temp\\_MEI1234\\python312.dll)

Thread 0x1A2C (idle): "MainThread"
    select (selectors.py:314)
    _run_once (asyncio\\base_events.py:1898)
    _lifespan (C:\\Users\\private-person\\AppData\\Local\\Temp\\_MEI1234\\maverick_dashboard\\app.py:1350)
Thread 7788 (active+gil): "desktop-control"
    readline (C:\\private dir\\odd name.py:12)
    _read_desktop_control (maverick_dashboard\\_server.py:20)
Thread 0x9 (idle): "private name with \\"quote"
    run (threading.py:982)
"""


def test_reduced_stacks_keep_only_thread_names_and_code_locations(modules):
    module, _ = modules
    assert module.reduced_stacks(SPY_DUMP) == [
        "thread MainThread (idle)",
        "  selectors.py:314:select",
        "  base_events.py:1898:_run_once",
        "  app.py:1350:_lifespan",
        "thread desktop-control (active+gil)",
        "  other:12:readline",
        "  _server.py:20:_read_desktop_control",
        "thread other (unknown)",
        "  threading.py:982:run",
    ]
    assert "private" not in "\n".join(module.reduced_stacks(SPY_DUMP))
    many = "".join(f'Thread {index} (idle): "worker-{index}"\n    run (threading.py:982)\n' for index in range(60))
    bounded = module.reduced_stacks(many, threads=3, frames=1)
    assert bounded == ["thread worker-0 (idle)", "  threading.py:982:run", "thread worker-1 (idle)",
                       "  threading.py:982:run", "thread worker-2 (idle)", "  threading.py:982:run"]


def test_dashboard_processes_are_only_this_apps_frozen_dashboard_tree(modules):
    module, _ = modules
    listing = [
        {"ProcessId": 10, "ParentProcessId": 1, "Name": "maverick-desktop.exe"},
        {"ProcessId": 20, "ParentProcessId": 10, "Name": "maverick.exe"},
        {"ProcessId": 21, "ParentProcessId": 20, "Name": "maverick.exe"},
        {"ProcessId": 22, "ParentProcessId": 10, "Name": "msedgewebview2.exe"},
        {"ProcessId": 30, "ParentProcessId": 99, "Name": "maverick.exe"},
        {"ProcessId": "40", "ParentProcessId": 10, "Name": "maverick.exe"},
        "private",
    ]
    assert module.dashboard_processes(listing, 10) == [20, 21]
    assert module.dashboard_processes({"ProcessId": 20, "ParentProcessId": 10, "Name": "MAVERICK.EXE"}, 10) == [20]
    assert module.dashboard_processes(listing, 99) == [30]
    assert module.dashboard_processes(listing, 5) == []


@pytest.mark.parametrize("failure,expected", [
    (None, "captured"), ("listing", "listing_unavailable"), ("empty", "no_dashboard_process"),
    ("install", "tool_unavailable"), ("install_decode", "tool_unavailable"), ("dump", "dump_failed"),
    ("dump_decode", "dump_failed"), ("write", "write_failed"),
])
def test_dashboard_stacks_capture_only_reduced_frames(tmp_path, modules, monkeypatch, failure, expected):
    import types
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = tmp_path
    journey.app = types.SimpleNamespace(pid=10)
    calls = []

    def command(arguments, *, env=None, timeout=90):
        calls.append(arguments)
        name = Path(arguments[0]).name
        if name.startswith("pwsh"):
            if failure == "listing":
                raise RuntimeError("synthetic listing failure")
            rows = [] if failure == "empty" else [{"ProcessId": 20, "ParentProcessId": 10, "Name": "maverick.exe"}]
            return json.dumps(rows)
        undecodable = UnicodeDecodeError("cp1252", b"\x81", 0, 1, "synthetic private bytes")
        if "pip" in arguments:
            if failure == "install":
                raise RuntimeError("synthetic install failure")
            if failure == "install_decode":
                raise undecodable
            target = Path(arguments[arguments.index("--target") + 1])
            (target / "bin").mkdir(parents=True)
            (target / "bin/py-spy.exe").write_bytes(b"synthetic")
            return ""
        assert arguments[1:] == ["dump", "--pid", "20"]
        if failure == "dump":
            raise RuntimeError("synthetic dump failure")
        if failure == "dump_decode":
            raise undecodable
        return SPY_DUMP

    monkeypatch.setattr(module, "command", command)
    monkeypatch.setattr(module.shutil, "which", lambda _name: "C:/tools/pwsh.exe")
    written = tmp_path / "dashboard-stacks.txt"
    if failure == "write":
        written.mkdir()
    assert journey.dashboard_stacks() == expected
    if expected != "captured":
        assert not written.is_file()
        return
    text = written.read_text(encoding="utf-8")
    assert "private" not in text
    assert text.startswith("process 0\nthread MainThread (idle)\n  selectors.py:314:select\n")
    install = next(arguments for arguments in calls if "pip" in arguments)
    assert install[-1] == module.PY_SPY == "py-spy==0.4.0" and "--only-binary=:all:" in install


@pytest.mark.parametrize("state,expected", [
    ("running", "captured"), ("unreported", "captured"), ("unavailable", "captured"),
    ("bridge_unavailable", "captured"), ("unavailable_to_driver", "captured"),
    ("exited", "not_running"), ("not_started", "not_running"),
])
def test_deadline_skips_stacks_only_when_the_shell_reports_no_live_dashboard(tmp_path, modules, monkeypatch, state, expected):
    module, _ = modules
    journey = module.Journey.__new__(module.Journey)
    journey.directory = journey.state = tmp_path
    journey.password = "synthetic-private-form-value"  # pragma: allowlist secret - noncredential redaction fixture
    journey.report = {"checks": []}

    class View:
        session = "/session/synthetic"

        def wait(self, _condition, **_kwargs):
            raise RuntimeError("synthetic deadline")

    journey.view = View()
    monkeypatch.setattr(journey, "startup_diagnostic", lambda: {"page": "bundled_splash"})
    monkeypatch.setattr(journey, "loopback_probe", lambda: {"listener": "not_listening", "latency_ms": 3})
    monkeypatch.setattr(journey, "startup_process", lambda: {"process_state": state})
    monkeypatch.setattr(journey, "dashboard_stacks", lambda: "captured")
    with pytest.raises(RuntimeError, match="bounded window_at_deadline diagnostics"):
        journey.first_owner()
    assert journey.report["window_at_deadline"]["dashboard_stacks"] == expected
