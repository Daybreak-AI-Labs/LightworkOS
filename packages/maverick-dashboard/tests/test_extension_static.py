"""Static validation of the bundled WebExtension (extensions/browser/).

The extension ships as plain unbuilt JS, so CI can't compile-check it; these
tests pin the structural invariants instead: the manifest parses and carries
the required MV3 keys, every referenced script exists locally, the host
permission is loopback-only, and no script pulls remote code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

EXT_DIR = Path(__file__).resolve().parents[3] / "extensions" / "browser"


def _manifest() -> dict:
    return json.loads((EXT_DIR / "manifest.json").read_text(encoding="utf-8"))


def test_manifest_parses_and_is_mv3():
    m = _manifest()
    assert m["manifest_version"] == 3
    assert m["name"] and m["version"]


def test_manifest_required_keys():
    m = _manifest()
    assert m["action"]["default_popup"] == "popup.html"
    assert m["background"]["service_worker"] == "background.js"
    assert m["content_scripts"], "page-context capture content script missing"
    assert m["content_scripts"][0]["js"] == ["content.js"]


def test_host_permissions_loopback_only():
    m = _manifest()
    assert m["host_permissions"], "host_permissions missing"
    for perm in m["host_permissions"]:
        assert perm.startswith("http://127.0.0.1"), f"non-loopback host permission: {perm}"
    # Keep the permission surface minimal: storage only.
    assert set(m.get("permissions") or []) <= {"storage"}


def test_extension_pages_csp_blocks_remote_script():
    m = _manifest()
    csp = m["content_security_policy"]["extension_pages"]
    assert "script-src 'self'" in csp


def test_referenced_files_exist():
    for name in ("popup.html", "popup.js", "background.js", "content.js", "README.md"):
        assert (EXT_DIR / name).is_file(), f"{name} missing"


_URL_RE = re.compile(r"https?://[^\s\"'`)]+")


def test_content_script_guards_message_sender():
    # The page-context handler must reject messages whose sender is not THIS
    # extension, so a future externally_connectable change can't let an attacker
    # page harvest page context.
    src = (EXT_DIR / "content.js").read_text(encoding="utf-8")
    assert "chrome.runtime.id" in src, "content.js: no sender-id guard on onMessage"
    assert "getPageContext" in src


def test_no_remote_code_in_scripts():
    for js in EXT_DIR.glob("*.js"):
        src = js.read_text(encoding="utf-8")
        assert "importScripts" not in src, f"{js.name}: importScripts"
        assert "eval(" not in src, f"{js.name}: eval"
        assert "new Function" not in src, f"{js.name}: Function constructor"
        for url in _URL_RE.findall(src):
            assert url.startswith("http://127.0.0.1"), f"{js.name}: non-loopback URL {url}"


def test_popup_html_scripts_are_local_files_only():
    html = (EXT_DIR / "popup.html").read_text(encoding="utf-8")
    scripts = re.findall(r"<script\b[^>]*>", html)
    assert scripts, "popup must load popup.js"
    for tag in scripts:
        src = re.search(r'src="([^"]+)"', tag)
        assert src, f"inline <script> forbidden (MV3 CSP): {tag}"
        assert not src.group(1).startswith(("http:", "https:", "//")), \
            f"remote script: {src.group(1)}"
        assert (EXT_DIR / src.group(1)).is_file()
    assert "javascript:" not in html
