"""a11y `check` must refuse file:// and private/metadata URLs (LFI / SSRF):
pa11y and axe drive a real headless browser, so the target URL is attacker-
reachable just like an http_fetch."""
from __future__ import annotations

import pytest
from maverick.tools.a11y import _check_url, _pin_url, a11y


def test_rejects_file_scheme():
    out = _check_url("file:///etc/passwd")
    assert out is not None and "http(s)" in out


def test_rejects_non_http_scheme():
    assert _check_url("ftp://example.com/x") is not None


def test_rejects_loopback_host():
    assert _check_url("http://127.0.0.1/") is not None


def test_rejects_metadata_ip():
    assert _check_url("http://169.254.169.254/latest/meta-data/") is not None


def test_allow_private_override_permits_loopback(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    assert _check_url("http://127.0.0.1/") is None


def test_check_op_blocks_file_url_before_runner():
    # The URL guard runs BEFORE _ensure_runner, so a file:// target is refused
    # with the SSRF error even when no pa11y/axe binary is installed.
    out = a11y().fn({"op": "check", "url": "file:///etc/passwd"})
    assert out.startswith("ERROR") and "http(s)" in out


def test_pin_url_rewrites_host_to_pinned_ip(monkeypatch):
    # _pin_url must swap the hostname for a single validated public IP so the
    # headless browser cannot re-resolve and DNS-rebind after the guard passes.
    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", lambda host: "93.184.216.34")
    assert _pin_url("http://evil.example:8080/x") == "http://93.184.216.34:8080/x"
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", lambda host: "2606:4700:4700::1111")
    assert _pin_url("http://v6.example:8080/x") == "http://[2606:4700:4700::1111]:8080/x"


def test_pin_url_refuses_rebind_to_private_ip(monkeypatch):
    # If the second resolution now returns a private/metadata IP, resolve_pinned_ip
    # raises BlockedHost; _pin_url propagates it so the caller fails closed rather
    # than handing the browser a fetchable rebound URL.
    import maverick.tools._ssrf as _ssrf

    def _rebind(host):
        raise _ssrf.BlockedHost("rebound to 169.254.169.254")

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", _rebind)
    with pytest.raises(_ssrf.BlockedHost):
        _pin_url("http://evil.example/")


def test_pin_url_keeps_hostname_for_https(monkeypatch):
    # For HTTPS the host must NOT be rewritten to an IP literal: the browser
    # validates the TLS cert against the netloc, and an IP won't match the
    # cert's SAN, so every real HTTPS target would fail. resolve_pinned_ip still
    # runs (re-validates the host is public), but the URL is handed back intact.
    import maverick.tools._ssrf as _ssrf
    calls = []
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip",
                        lambda host: calls.append(host) or "93.184.216.34")
    assert _pin_url("https://example.com/x") == "https://example.com/x"
    assert calls == ["example.com"]  # the public-IP re-validation still happened


def test_pin_url_refuses_https_rebind_to_private_ip(monkeypatch):
    # HTTPS still fails closed when re-resolution now returns a private IP.
    import maverick.tools._ssrf as _ssrf

    def _rebind(host):
        raise _ssrf.BlockedHost("rebound to 169.254.169.254")

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", _rebind)
    with pytest.raises(_ssrf.BlockedHost):
        _pin_url("https://evil.example/")


def test_check_html_path_still_allowed_without_url_guard(monkeypatch):
    # check_html takes a confined local path, not a URL -- the url guard must
    # not interfere with it. With no sandbox and no binary, we just get the
    # runner-missing error (not an SSRF rejection).
    out = a11y().fn({"op": "check_html", "path": "report.html"})
    assert out.startswith("ERROR")
    assert "http(s)" not in out


def _socks_connect(proxy_url: str, ip: str, port: int = 80) -> int:
    """Ask the proxy to open ``ip:port`` the way Chromium would; return its reply code."""
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(proxy_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert sock.recv(2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + port.to_bytes(2, "big"))
        return sock.recv(10)[1]


def test_runner_browser_can_only_reach_what_the_pinned_proxy_admits(monkeypatch):
    """The page under test decides what the runner's browser loads next: its
    redirects, frames and scripts. Checking the first URL is not enough, so
    the browser gets a proxy that refuses internal addresses and asks the
    destination policy about every host."""
    import json
    import socket
    from pathlib import Path

    import maverick.tools as tools_mod
    from maverick.tenant import egress

    asked: list[tuple[str, str]] = []
    monkeypatch.setattr(egress, "egress_allowed",
                        lambda tool, host, **_kw: asked.append((tool, host)) or True)
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    seen: dict[str, dict] = {}

    def _runner(sandbox, cmd, **_kw):
        options = cmd[: cmd.index("--")]
        if cmd[0] == "axe":
            flags = options[options.index("--chrome-options") + 1].split(",")
            config = None
        else:
            config = Path(options[options.index("--config") + 1])
            flags = [a.removeprefix("--") for a in
                     json.loads(config.read_text(encoding="utf-8"))["chromeLaunchConfig"]["args"]]
        proxy = next(f for f in flags if f.startswith("proxy-server=")).split("=", 1)[1]
        seen[cmd[0]] = {
            "flags": flags, "proxy": proxy, "config": config, "target": cmd[-1],
            "metadata": _socks_connect(proxy, "169.254.169.254"),
            "loopback": _socks_connect(proxy, "127.0.0.1"),
        }
        return 0, "[]", ""

    monkeypatch.setattr(tools_mod, "sandbox_run", _runner)
    for runner in ("pa11y", "axe"):
        out = a11y().fn({"op": "check", "url": "http://example.com/page", "runner": runner})
        assert out == "no a11y issues", out
        run = seen[runner]
        # Loopback is not exempt from the proxy, and both internal targets are refused.
        assert "proxy-bypass-list=<-loopback>" in run["flags"]
        assert run["metadata"] == 2 and run["loopback"] == 2
        # The proxy pins each connection, so the name is left for the policy to judge.
        assert run["target"] == "http://example.com/page"
        # Nothing outlives the check.
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", int(run["proxy"].rsplit(":", 1)[1])), timeout=1)
        assert run["config"] is None or not run["config"].exists()
    assert ("a11y", "example.com") in asked and ("a11y", "169.254.169.254") in asked

    # A site on another port cannot go through the proxy: say so before the browser starts.
    out = a11y().fn({"op": "check", "url": "http://example.com:8080/"})
    assert out.startswith("ERROR") and "443" in out
    # ...without pointing the person at the switch that opens private addresses.
    assert "ALLOW_PRIVATE" not in out


def test_project_pa11y_settings_are_kept_but_cannot_undo_the_proxy(tmp_path, monkeypatch):
    """pa11y is given a private config that carries the proxy, so it no longer
    reads the project's own ``pa11y.json``. Its harmless settings are carried
    over; anything that chooses the browser or its network is not."""
    import json
    from pathlib import Path

    import maverick.tools as tools_mod
    from maverick.sandbox.local import LocalBackend
    from maverick.tenant import egress

    (tmp_path / "pa11y.json").write_text(json.dumps({
        "standard": "WCAG2AAA", "ignore": ["notice"], "timeout": 5000,
        "runners": ["axe", "../evil-runner"],
        "actions": ["navigate to http://169.254.169.254/"],
        "chromeLaunchConfig": {
            "executablePath": "/tmp/not-a-browser",
            "args": ["--no-sandbox", "--no-proxy-server", "--proxy-server=direct://"],
        },
    }), encoding="utf-8")
    monkeypatch.setattr(egress, "egress_allowed", lambda tool, host, **_kw: True)
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    seen: dict = {}

    def _runner(sandbox, cmd, **_kw):
        seen.update(json.loads(Path(cmd[cmd.index("--config") + 1]).read_text(encoding="utf-8")))
        return 0, "[]", ""

    monkeypatch.setattr(tools_mod, "sandbox_run", _runner)
    out = a11y(LocalBackend(workdir=tmp_path)).fn({"op": "check", "url": "https://example.com/"})

    assert out == "no a11y issues", out
    assert (seen["standard"], seen["ignore"], seen["timeout"]) == ("WCAG2AAA", ["notice"], 5000)
    assert seen["runners"] == ["axe"]
    assert "actions" not in seen and "executablePath" not in seen["chromeLaunchConfig"]
    args = seen["chromeLaunchConfig"]["args"]
    assert "--no-sandbox" in args and "--no-proxy-server" not in args
    assert [a for a in args if a.startswith("--proxy-server=")] == [args[0]]
    assert args[0].startswith("--proxy-server=socks5://127.0.0.1:")


def test_check_is_refused_when_the_browser_cannot_be_limited(tmp_path, monkeypatch):
    """Refused before any browser starts: a host the destination policy blocks,
    and a sandbox with its own network that the host's proxy cannot reach."""
    from maverick.tenant import egress

    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)

    class _Container:
        def __init__(self, allow_network):
            self.workdir, self.allow_network, self.commands = str(tmp_path), allow_network, []

        def exec(self, cmd, timeout=None):
            self.commands.append(cmd)
            return type("R", (), {"exit_code": 0, "stdout": "[]", "stderr": ""})()

    networked = _Container(allow_network=True)
    out = a11y(networked).fn({"op": "check_html", "path": "page.html"})
    assert out.startswith("ERROR") and "network" in out and networked.commands == []

    offline = _Container(allow_network=False)
    assert a11y(offline).fn({"op": "check_html", "path": "page.html"}) == "no a11y issues"
    assert len(offline.commands) == 1 and "proxy" not in offline.commands[0]

    monkeypatch.setattr(egress, "egress_allowed", lambda tool, host, **_kw: False)
    ran = []
    monkeypatch.setattr("subprocess.run", lambda *a, **k: ran.append(a))
    out = a11y().fn({"op": "check", "url": "https://example.com/"})
    assert out.startswith("ERROR") and "example.com" in out and ran == []
