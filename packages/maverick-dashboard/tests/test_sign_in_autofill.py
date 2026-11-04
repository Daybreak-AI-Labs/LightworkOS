"""Sign-in never fights paste, password managers or memory (WCAG 2.2 SC 3.3.8).

Every Lightwork form that signs someone in or sets their passphrase -- owner
setup, sign-in, invitation acceptance and the supplier questionnaire's access
code -- must let a password manager fill it and let people paste into it, and
must never ask them to solve a puzzle. These tests read the rendered pages and
the scripts each page loads: the right ``type`` and ``autocomplete`` on every
field, no paste, copy or drop blocking in markup or script, no CAPTCHA or
arithmetic check, and a way to show the passphrase so it need not be retyped
blind. Company sign-in (OIDC/SAML) hands the person to their identity provider,
so its second-factor screens are the provider's, not Lightwork's.
"""
from __future__ import annotations

import os
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

LOCAL = "http://127.0.0.1:8765"
REMOTE = "https://lightwork.example"
OWNER = "owner@example.test"
OWNER_PASS = "Synthetic owner passphrase for autofill"  # pragma: allowlist secret
COLLEAGUE = "kim@example.test"
STATIC = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"

# Script that cancels or rewires clipboard and drop events in a sign-in form.
_BLOCKING_SCRIPT = re.compile(
    r"""addEventListener\(\s*['"](?:paste|copy|cut|drop|beforeinput)['"]"""
    r"""|\.on(?:paste|copy|cut|drop)\s*="""
    r"""|clipboardData\.(?:clearData|setData)""", re.IGNORECASE)
_BLOCKING_ATTRIBUTES = {"onpaste", "oncopy", "oncut", "ondrop", "oncontextmenu", "onbeforeinput"}
_PUZZLE = re.compile(r"captcha|challenge|puzzle|recaptcha|hcaptcha|turnstile", re.IGNORECASE)
_ARITHMETIC = re.compile(r"\bwhat is\s+\d+\s*(?:\+|-|plus|minus|times|x)\s*\d+", re.IGNORECASE)


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements: list[tuple[str, dict]] = []
        self.inline_scripts: list[str] = []
        self.script_sources: list[str] = []
        self._in_script = False
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = {name: (value or "") for name, value in attrs}
        self.elements.append((tag, values))
        if tag == "script":
            if values.get("src"):
                self.script_sources.append(values["src"])
            else:
                self._in_script = True
                self.inline_scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.inline_scripts[-1] += data
        else:
            self.text.append(data)

    def inputs(self) -> list[dict]:
        return [values for tag, values in self.elements if tag == "input"]


def _parse(response) -> _Page:
    assert response.status_code == 200, response.text[:400]
    page = _Page()
    page.feed(response.text)
    return page


def _static_script(source: str) -> str:
    """The text of a same-origin script the page loads, from the package."""
    name = source.split("?", 1)[0].rsplit("/", 1)[-1]
    candidates = [STATIC / name]
    if name == "client.js":  # the supplier portal serves its client under this name
        candidates.append(STATIC / "lightwork-third-party-portal.js")
    for path in candidates:
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise AssertionError(f"script {source} is not a packaged static file")


def _assert_paste_and_autofill_friendly(page: _Page) -> None:
    for tag, values in page.elements:
        blocked = _BLOCKING_ATTRIBUTES & set(values)
        assert not blocked, f"<{tag}> carries {sorted(blocked)}"
        for attribute in ("name", "id", "class"):
            assert not _PUZZLE.search(values.get(attribute, "")), f"<{tag}> looks like a puzzle: {values}"
    assert not _ARITHMETIC.search(" ".join(page.text)), "the page asks an arithmetic question"
    scripts = list(page.inline_scripts)
    scripts += [_static_script(source) for source in page.script_sources
                if not source.startswith(("http:", "https:", "//"))]
    for script in scripts:
        match = _BLOCKING_SCRIPT.search(script)
        assert match is None, f"a sign-in script handles clipboard or drop events: {match.group(0)}"
    for field in page.inputs():
        if field.get("type") == "password":
            assert "readonly" not in field and "disabled" not in field, field
            maximum = field.get("maxlength")
            # Password managers generate long passphrases; never truncate them.
            assert maximum is None or int(maximum) >= 64, field


def _field(page: _Page, **match) -> dict:
    found = [field for field in page.inputs()
             if all(field.get(key) == value for key, value in match.items())]
    assert len(found) == 1, (match, page.inputs())
    return found[0]


def _local_passphrase_fields(page: _Page, *, new: bool) -> None:
    password = _field(page, name="password")
    assert password["type"] == "password"
    assert password["autocomplete"] == ("new-password" if new else "current-password")
    if new:
        confirm = _field(page, name="password2")
        assert confirm["type"] == "password" and confirm["autocomplete"] == "new-password"
    else:
        assert not [f for f in page.inputs() if f.get("name") == "password2"]
    # A Show control lets people check what they typed or pasted.
    assert any(tag == "button" and values.get("aria-controls") == "owner-password"
               for tag, values in page.elements)
    form = [values for tag, values in page.elements if tag == "form"]
    assert form and all(values.get("method") == "post" for values in form)
    assert all(values.get("autocomplete") != "off" for values in form)


@pytest.fixture
def home(monkeypatch, tmp_path):
    from maverick import client as client_binding
    from maverick import config, world_model

    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[client]\nid="sign-in-autofill"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client_binding.reset_client_cache()
    from maverick_dashboard import local_passphrases

    local_passphrases.reset_attempt_limit()
    yield tmp_path
    local_passphrases.reset_attempt_limit()
    config.reset_config_cache()
    client_binding.reset_client_cache()


def _owner_browser():
    from maverick_dashboard.app import app

    return TestClient(app, base_url=LOCAL, client=("127.0.0.1", 50011),
                      headers={"Origin": LOCAL}, follow_redirects=False)


def _remote_browser():
    from maverick_dashboard.app import app

    return TestClient(app, base_url=REMOTE, client=("192.0.2.50", 50012),
                      headers={"Origin": REMOTE}, follow_redirects=False)


def _claim(owner) -> None:
    claimed = owner.post("/auth/local-owner", data={
        "email": OWNER, "password": OWNER_PASS, "password2": OWNER_PASS, "confirm": "yes"})
    assert claimed.status_code == 303, claimed.text


def test_owner_setup_takes_a_saved_or_pasted_new_passphrase(home):
    page = _parse(_owner_browser().get("/auth/local-owner"))
    email = _field(page, name="email")
    assert email["type"] == "email" and email["autocomplete"] == "username"
    _local_passphrase_fields(page, new=True)
    _assert_paste_and_autofill_friendly(page)


def test_sign_in_page_lets_a_password_manager_fill_both_fields(home):
    owner = _owner_browser()
    _claim(owner)
    owner.cookies.clear()
    for browser in (owner, _remote_browser()):
        page = _parse(browser.get("/auth/local-login"))
        email = _field(page, name="email")
        assert email["type"] == "email" and email["autocomplete"] == "username"
        _local_passphrase_fields(page, new=False)
        _assert_paste_and_autofill_friendly(page)


def test_invitation_acceptance_names_the_account_for_the_password_manager(home):
    owner = _owner_browser()
    _claim(owner)
    made = owner.post("/users/invite", data={"email": COLLEAGUE, "role": "operator"})
    assert made.status_code == 200, made.text
    link = re.search(r"/auth/invite/inv_[A-Za-z0-9_-]+", made.text)[0]
    page = _parse(_remote_browser().get(link))
    # The account name sits beside the new passphrase so the manager saves both.
    account = _field(page, autocomplete="username")
    assert account["type"] == "email" and account["value"] == COLLEAGUE
    _local_passphrase_fields(page, new=True)
    _assert_paste_and_autofill_friendly(page)


def test_supplier_access_code_can_be_pasted_and_shown(home):
    from maverick_dashboard.app import app

    supplier = TestClient(app, base_url=REMOTE, follow_redirects=False)
    page = _parse(supplier.get(
        "/api/v1/external/third-party-collaboration/browser-supplier-portal-0001/portal"))
    code = _field(page, id="invitation-credential")
    assert code["type"] == "password"
    help_text = " ".join(page.text)
    assert "Paste the access code" in help_text
    assert _field(page, id="show-credential")["type"] == "checkbox"
    _assert_paste_and_autofill_friendly(page)


def test_the_paste_blocking_check_catches_a_blocking_form():
    """Guard the guard: the checks above really fail on a hostile form."""
    hostile = _Page()
    hostile.feed('<form method="post"><input type="password" name="password" onpaste="return false">'
                 '</form><script>document.forms[0].addEventListener("paste", e => e.preventDefault())'
                 '</script>')
    with pytest.raises(AssertionError):
        _assert_paste_and_autofill_friendly(hostile)
    scripted = _Page()
    scripted.feed('<input type="password" name="password"><script>'
                  'field.addEventListener( "paste" ,stop)</script>')
    with pytest.raises(AssertionError):
        _assert_paste_and_autofill_friendly(scripted)
    puzzle = _Page()
    puzzle.feed('<p>What is 3 + 4?</p><input name="challenge_answer">')
    with pytest.raises(AssertionError):
        _assert_paste_and_autofill_friendly(puzzle)
    short = _Page()
    short.feed('<input type="password" name="password" maxlength="20">')
    with pytest.raises(AssertionError):
        _assert_paste_and_autofill_friendly(short)
