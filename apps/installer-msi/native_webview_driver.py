"""Small W3C client for the real installed WebView; no synthetic IPC handlers."""
from __future__ import annotations

import base64
import ctypes
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from native_webview_fixture import hosted_only

ELEMENT = "element-6066-11e4-a52e-4f735466cecf"


class WebView:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"
        self.session = ""

    def call(self, method: str, path: str, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=body, method=method,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                raw = response.read(12 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            # Driver error text can contain input fields; keep it out of CI logs.
            raise RuntimeError(f"WebView command {method} {path.rsplit('/', 1)[-1]} failed ({error.code}).") from None
        if len(raw) > 12 * 1024 * 1024:
            raise RuntimeError("WebView response exceeds its bound.")
        value = json.loads(raw)["value"]
        if isinstance(value, dict) and value.get("error"):
            raise RuntimeError("WebView command returned " + str(value["error"]))
        return value

    def attach(self, debugger_port: int) -> dict:
        value = self.call("POST", "/session", {"capabilities": {"alwaysMatch": {
            "browserName": "webview2", "ms:edgeOptions": {"debuggerAddress": f"127.0.0.1:{debugger_port}"}}}})
        self.session = "/session/" + value["sessionId"]
        self.call("POST", self.session + "/timeouts", {"implicit": 0, "pageLoad": 60000, "script": 15000})
        return value["capabilities"]

    def close(self):
        if self.session:
            try:
                self.call("DELETE", self.session)
            except (OSError, RuntimeError):
                pass
            self.session = ""

    def wait(self, condition, *, timeout: int = 90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = condition()
                if value:
                    return value
            except (OSError, RuntimeError, KeyError):
                pass
            time.sleep(.25)
        raise RuntimeError("The expected native UI transition did not complete before its deadline.")

    def element(self, selector: str) -> str:
        return self.call("POST", self.session + "/element", {"using": "css selector", "value": selector})[ELEMENT]

    def interactable(self, selector: str) -> str:
        def ready():
            if not self.call("POST", self.session + "/execute/sync", {
                    "script": "return document.readyState === 'complete'", "args": []}):
                return None
            element = self.element(selector)
            return element if self.call("GET", self.session + f"/element/{element}/enabled") else None
        # Resolve again on each poll: navigation and async rendering can replace
        # a control while the old reference is still disabled or stale.
        return self.wait(ready)

    def click(self, selector: str):
        element = self.interactable(selector)
        self.call("POST", self.session + f"/element/{element}/click", {})

    def fill(self, selector: str, text: str):
        element = self.interactable(selector)
        self.call("POST", self.session + f"/element/{element}/clear", {})
        self.call("POST", self.session + f"/element/{element}/value", {"text": text})

    def property(self, selector: str, name: str):
        element = self.element(selector)
        return self.call("GET", self.session + f"/element/{element}/property/{name}")

    def text(self, selector: str):
        return self.call("GET", self.session + f"/element/{self.element(selector)}/text")

    def navigate(self, address: str):
        # The journey navigates only this fixture's app, never an external site.
        if not address.startswith("http://127.0.0.1:8765/"):
            raise ValueError("Use the actual native menu for bundled control pages.")
        self.call("POST", self.session + "/url", {"url": address})

    def screenshot(self, path: Path):
        encoded = self.call("GET", self.session + "/screenshot")
        path.write_bytes(base64.b64decode(encoded, validate=True))

    def keyboard(self, selector: str, text: str):
        element = self.interactable(selector)
        self.call("POST", self.session + f"/element/{element}/value", {"text": text})


def _windows():
    from ctypes import wintypes

    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback, wintypes.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetMenu.argtypes = [wintypes.HWND]
    user.GetMenu.restype = wintypes.HMENU
    user.GetSubMenu.argtypes = [wintypes.HMENU, ctypes.c_int]
    user.GetSubMenu.restype = wintypes.HMENU
    user.GetMenuItemCount.argtypes = [wintypes.HMENU]
    user.GetMenuItemID.argtypes = [wintypes.HMENU, ctypes.c_int]
    user.GetMenuItemID.restype = wintypes.UINT
    user.GetMenuStringW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.LPWSTR, ctypes.c_int, wintypes.UINT]
    user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return user, kernel, callback, wintypes


def app_windows(binary: Path) -> list:
    hosted_only()
    user, kernel, callback, types = _windows()
    expected = os.path.normcase(str(binary.resolve()))
    found = []

    def inspect(hwnd, _data):
        pid = types.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        handle = kernel.OpenProcess(0x1000, False, pid.value)
        if handle:
            try:
                buffer = ctypes.create_unicode_buffer(32768)
                length = types.DWORD(len(buffer))
                if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
                    if os.path.normcase(buffer.value) == expected and user.GetMenu(hwnd):
                        found.append((hwnd, pid.value))
            finally:
                kernel.CloseHandle(handle)
        return True

    user.EnumWindows(callback(inspect), 0)
    return found


def menu(binary: Path, label: str):
    """Dispatch the real Win32 menu command to the exact fixture executable."""
    hosted_only()
    user, _kernel, _callback, _types = _windows()
    windows = app_windows(binary)
    if len(windows) != 1:
        raise RuntimeError("Expected one native fixture window with the installed executable identity.")
    hwnd, _pid = windows[0]

    def search(handle):
        for index in range(user.GetMenuItemCount(handle)):
            text = ctypes.create_unicode_buffer(512)
            user.GetMenuStringW(handle, index, text, len(text), 0x400)
            submenu = user.GetSubMenu(handle, index)
            if submenu:
                found = search(submenu)
                if found is not None:
                    return found
            elif text.value.replace("&", "").split("\t")[0] == label.replace("&", ""):
                return user.GetMenuItemID(handle, index)
        return None

    selected = search(user.GetMenu(hwnd))
    if selected is None or selected == 0xFFFFFFFF or not user.PostMessageW(hwnd, 0x111, selected, 0):
        raise RuntimeError("The expected native menu command is unavailable.")
