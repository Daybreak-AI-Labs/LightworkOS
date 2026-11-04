"""Tests for the per-action approval gate (computer + browser tools)."""
from __future__ import annotations

import copy
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.safety import action_gate
from maverick.safety import consent as consent_module
from maverick.safety.consent import ConsentDecision


@pytest.fixture(autouse=True)
def _clean_mode(tmp_path, monkeypatch):
    # Keep any audit/ledger side effects inside tmp and start from the default
    # (unset) consent mode unless a test overrides it.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)


def _capture(monkeypatch):
    """Replace the primitive decision with a recorder that always grants."""
    calls: list[dict] = []

    def fake(
        name,
        *,
        risk,
        scope,
        detail,
        provenance,
        raise_on_deny=False,
        allow_auto_approve=True,
        consult_ledger=True,
        approval_card=None,
    ):
        calls.append(
            {"name": name, "risk": risk, "scope": scope,
             "detail": detail, "provenance": provenance,
             "allow_auto_approve": allow_auto_approve,
             "consult_ledger": consult_ledger,
             "approval_card": approval_card},
        )
        return ConsentDecision(True, "auto", risk, 0.0)

    monkeypatch.setattr(consent_module, "require_consent", fake)
    return calls


def _mutable_authority(monkeypatch):
    state = {
        "authority": {
            "actor": "user:alice",
            "workspace": "workspace-one",
            "role": "operator",
            "versions": {
                "principal_sha256": "a" * 64,
                "role_permissions_sha256": "b" * 64,
                "budget_authority_sha256": "c" * 64,
            },
        },
        "budget": {
            "currency": "USD",
            "external_effect_cost": "unmeasured",
            "authority_sha256": "c" * 64,
        },
    }

    def current(*, actor_hint=None):
        del actor_hint
        return (
            copy.deepcopy(state["authority"]),
            copy.deepcopy(state["budget"]),
            True,
        )

    monkeypatch.setattr(consent_module, "_runtime_approval_authority", current)
    return state


# --- non-mutating actions are never gated -----------------------------------

@pytest.mark.parametrize(
    "action",
    ["screenshot", "cursor_position", "wait", "bogus"],
)
def test_computer_nonmutating_never_gated(action, monkeypatch):
    calls = _capture(monkeypatch)
    assert action_gate.gate_computer_action(action, {}) is None
    assert calls == []


@pytest.mark.parametrize(
    "action",
    ["current_url", "screenshot", "extract_text", "extract_html", "find_text",
     "wait_for", "list_links", "bogus"],
)
def test_browser_nonmutating_never_gated(action, monkeypatch):
    calls = _capture(monkeypatch)
    assert action_gate.gate_browser_action(action, {}) is None
    assert calls == []


# --- exact mutations never inherit silent or standing approval ----------------

def test_default_auto_mode_does_not_silently_approve_mutation():
    computer = action_gate.gate_computer_action(
        "left_click", {"coordinate": [10, 20]},
    )
    browser = action_gate.gate_browser_action("click", {"selector": "#ok"})
    assert computer and computer.startswith("ERROR:")
    assert browser and browser.startswith("ERROR:")


def test_auto_deny_blocks_with_error(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    out = action_gate.gate_computer_action("left_click", {"coordinate": [1, 2]})
    assert out is not None and out.startswith("ERROR:")
    assert "was not approved" in out
    assert "left_click at [1, 2]" in out
    assert "no action was sent" in out

    out2 = action_gate.gate_browser_action("click", {"selector": "#x"})
    assert out2 is not None and out2.startswith("ERROR:")


# --- risk classification -----------------------------------------------------

def test_browser_click_pay_is_high(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_browser_action("click", {"selector": "text=Pay now"})
    assert calls[0]["risk"] == "high"
    assert calls[0]["name"] == "browser.click"
    assert calls[0]["provenance"] == "browser.click"
    assert calls[0]["allow_auto_approve"] is False
    assert calls[0]["consult_ledger"] is False
    card = calls[0]["approval_card"]
    assert card["authorization"]["prediction_grants_authority"] is False
    assert card["consequences"]["known_effects"]
    assert card["consequences"]["unresolved_assumptions"]


def test_browser_click_ordinary_is_medium(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_browser_action("click", {"selector": "#search-box"})
    assert calls[0]["risk"] == "medium"


def test_computer_key_return_is_high(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_computer_action("key", {"text": "Return"})
    assert calls[0]["risk"] == "high"


def test_computer_ordinary_click_is_medium(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_computer_action("left_click", {"coordinate": [5, 5]})
    assert calls[0]["risk"] == "medium"


def test_fill_form_values_scanned_for_risk(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_browser_action("fill_form", {"fields": {"#note": "wire transfer"}})
    assert calls[0]["risk"] == "high"


# --- privacy: typed values never appear in the audit scope/detail ------------

def test_browser_navigate_url_strips_query_fragment_and_userinfo(monkeypatch):
    calls = _capture(monkeypatch)
    raw = (
        "https://alice:secret@example.com/reset/path"
        "?email=alice%40example.com&reset_token=not-redacted#access_token=frag"
    )
    action_gate.gate_browser_action("navigate", {"url": raw})
    assert calls[0]["scope"] == "https://example.com/reset/path"
    assert calls[0]["detail"] == "https://example.com/reset/path"
    blob = f"{calls[0]['detail']} {calls[0]['scope']}"
    assert "alice:secret" not in blob
    assert "reset_token" not in blob
    assert "not-redacted" not in blob
    assert "access_token" not in blob
    assert "alice%40example.com" not in blob


def test_browser_navigate_relative_url_strips_query_fragment(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_browser_action("navigate", {"url": "/reset?token=abc#frag"})
    assert calls[0]["scope"] == "/reset"
    assert calls[0]["detail"] == "/reset"


def test_browser_typed_value_not_in_detail(monkeypatch):
    calls = _capture(monkeypatch)
    secret = "hunter2-SECRET"  # pragma: allowlist secret
    action_gate.gate_browser_action("type", {"selector": "#pw", "text": secret})
    blob = f"{calls[0]['detail']} {calls[0]['scope']}"
    assert secret not in blob
    assert str(len(secret)) in calls[0]["detail"]  # length is logged instead


def test_computer_typed_value_not_in_detail(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_computer_action("type", {"text": "topsecret"})
    assert "topsecret" not in f"{calls[0]['detail']} {calls[0]['scope']}"


def test_fill_form_values_not_in_detail(monkeypatch):
    calls = _capture(monkeypatch)
    action_gate.gate_browser_action(
        "fill_form", {"fields": {"#iban": "DE89370400440532013000"}},
    )
    assert "DE89370400440532013000" not in f"{calls[0]['detail']} {calls[0]['scope']}"
    assert "#iban" in calls[0]["detail"]  # selector is shown, value is not
    assert "DE89370400440532013000" not in str(calls[0]["approval_card"])


def test_browser_context_change_after_decision_requires_fresh_review(monkeypatch):
    calls = _capture(monkeypatch)
    contexts = iter([
        {"page_url": "https://example.test/one", "credential_version_sha256": "a" * 64},
        {"page_url": "https://example.test/two", "credential_version_sha256": "a" * 64},
    ])

    result = action_gate.gate_browser_action(
        "click",
        {"selector": "#approve"},
        context_provider=lambda: next(contexts),
    )

    assert result and "changed while approval was pending" in result
    assert len(calls) == 1


def test_credential_revision_change_after_decision_requires_fresh_review(monkeypatch):
    _capture(monkeypatch)
    revisions = iter(["a" * 64, "b" * 64])

    result = action_gate.gate_computer_action(
        "key",
        {"text": "Return"},
        context_provider=lambda: {
            "seat_sha256": "c" * 64,
            "credential_version_sha256": next(revisions),
        },
    )

    assert result and "changed while approval was pending" in result


def test_unavailable_target_context_blocks_before_human_decision(monkeypatch):
    calls = _capture(monkeypatch)

    result = action_gate.gate_browser_action(
        "click",
        {"selector": "#approve"},
        context_provider=lambda: (_ for _ in ()).throw(RuntimeError("page closed")),
    )

    assert result and "target context is unavailable" in result
    assert calls == []


@pytest.mark.parametrize("action", ["mouse_move", "scroll"])
def test_computer_pointer_and_scroll_mutations_require_fresh_human(
    action, monkeypatch,
):
    calls = _capture(monkeypatch)
    permit = action_gate.gate_computer_action(action, {})
    assert isinstance(permit, action_gate.ActionPermit)
    assert calls[0]["allow_auto_approve"] is False
    assert calls[0]["consult_ledger"] is False


@pytest.mark.parametrize(
    "action",
    ["go_back", "go_forward", "scroll", "save_session", "close"],
)
def test_browser_navigation_and_session_mutations_require_fresh_human(
    action, monkeypatch,
):
    calls = _capture(monkeypatch)
    permit = action_gate.gate_browser_action(action, {})
    assert isinstance(permit, action_gate.ActionPermit)
    assert calls[0]["allow_auto_approve"] is False
    assert calls[0]["consult_ledger"] is False


def test_browser_context_commits_the_current_dom_target():
    from maverick.tools.browser import _BrowserSession

    target = {"text": "Approve"}

    class _Locator:
        first = None

        def __init__(self):
            self.first = self

        def count(self):
            return 1

        def evaluate(self, _script):
            return {
                "tag": "BUTTON", "text": target["text"], "disabled": False,
                "readOnly": False, "visible": True, "inViewport": True,
                "rect": [1, 1, 100, 30],
            }

    class _Page:
        url = (
            "https://alice:secret@example.test/review"
            "?token=eyJ" + "A" * 32 + "." + "b" * 64
        )

        def locator(self, _selector):
            return _Locator()

    class _Context:
        @staticmethod
        def storage_state():
            return {"cookies": []}

    session = _BrowserSession()
    session._page = _Page()
    session._context = _Context()
    before = session.approval_context("click", {"selector": "#decision"})
    target["text"] = "Delete"
    after = session.approval_context("click", {"selector": "#decision"})

    assert before["target_state_sha256"] != after["target_state_sha256"]
    assert before["target_summary"] == "Approve at https://example.test/review"


def test_browser_context_detects_an_identical_page_instance_swap():
    from maverick.tools.browser import _BrowserSession

    class _Locator:
        first = None

        def __init__(self):
            self.first = self

        @staticmethod
        def count():
            return 1

        @staticmethod
        def evaluate(_script):
            return {
                "tag": "BUTTON", "text": "Approve", "disabled": False,
                "readOnly": False, "visible": True, "inViewport": True,
                "rect": [1, 1, 100, 30],
            }

    class _Page:
        url = "https://example.test/review"

        @staticmethod
        def locator(_selector):
            return _Locator()

    class _Context:
        @staticmethod
        def storage_state():
            return {"cookies": []}

    session = _BrowserSession()
    session._page = _Page()
    session._context = _Context()
    before = session.approval_context("click", {"selector": "#decision"})
    session._page = _Page()
    after = session.approval_context("click", {"selector": "#decision"})

    assert before["target_state_sha256"] == after["target_state_sha256"]
    assert before["page_instance_sha256"] != after["page_instance_sha256"]


def test_browser_dispatch_rejects_changed_parent_form_activation_target():
    """An unchanged button cannot inherit approval for a revised form target."""
    from copy import deepcopy

    from maverick.tools.browser import _BrowserSession

    snapshot = {
        "tag": "BUTTON",
        "id": "save",
        "name": "",
        "role": "",
        "type": "submit",
        "ariaLabel": "",
        "text": "Save",
        "disabled": False,
        "readOnly": False,
        "visible": True,
        "inViewport": True,
        "href": None,
        "resolvedHref": None,
        "formAttribute": None,
        "owningForm": {
            "id": "review",
            "name": "",
            "actionAttribute": "/original",
            "resolvedAction": "https://example.test/original",
            "method": "post",
            "enctype": "application/x-www-form-urlencoded",
            "target": "",
            "noValidate": False,
        },
        "submitterOverrides": {
            "actionAttribute": None,
            "resolvedAction": "https://example.test/original",
            "methodAttribute": None,
            "resolvedMethod": "",
            "enctypeAttribute": None,
            "resolvedEnctype": "",
            "targetAttribute": None,
            "resolvedTarget": "",
            "noValidateAttribute": False,
            "noValidate": False,
        },
        "inlineHandler": "",
        "rect": [1, 1, 100, 30],
        "activationContextWithinLimit": True,
    }

    class _Handle:
        def evaluate(self, script):
            for commitment in (
                "resolvedHref", "owningForm", "submitterOverrides",
                "resolvedAction", "resolvedMethod", "resolvedEnctype",
                "resolvedTarget", "noValidate",
            ):
                assert commitment in script
            return deepcopy(snapshot)

    handle = _Handle()

    class _Locator:
        first = None

        def __init__(self):
            self.first = self

        @staticmethod
        def count():
            return 1

        @staticmethod
        def element_handle():
            return handle

    class _Page:
        url = "https://example.test/review"
        effects = 0

        @staticmethod
        def locator(_selector):
            return _Locator()

        @staticmethod
        def evaluate(script, payload):
            assert "owningForm" in script
            current = handle.evaluate(script)
            if current != payload["expected"][0]:
                return "stale"
            _Page.effects += 1
            return "dispatched"

    class _Context:
        @staticmethod
        def storage_state():
            return {"cookies": []}

    session = _BrowserSession()
    session._page = _Page()
    session._context = _Context()
    session.approval_context("click", {"selector": "#save"})
    snapshot["owningForm"]["actionAttribute"] = "/revised"
    snapshot["owningForm"]["resolvedAction"] = "https://example.test/revised"
    snapshot["submitterOverrides"]["resolvedAction"] = (
        "https://example.test/revised"
    )

    result = session.dispatch_approved(
        "click", {"selector": "#save"}, 30_000, set(),
    )

    assert "target changed at dispatch" in result
    assert _Page.effects == 0


def test_browser_context_rejects_oversized_activation_values():
    """Truncated same-prefix destinations must never become approvable."""
    from maverick.tools.browser import _BrowserSession

    class _Locator:
        first = None

        def __init__(self):
            self.first = self

        @staticmethod
        def count():
            return 1

        @staticmethod
        def evaluate(script):
            assert "text.length > 4096" in script
            assert "activationContextWithinLimit" in script
            return {
                "tag": "A",
                "text": "Continue",
                "disabled": False,
                "readOnly": False,
                "visible": True,
                "inViewport": True,
                "rect": [1, 1, 100, 30],
                "activationContextWithinLimit": False,
            }

    class _Page:
        url = "https://example.test/review"

        @staticmethod
        def locator(_selector):
            return _Locator()

    class _Context:
        @staticmethod
        def storage_state():
            return {"cookies": []}

    session = _BrowserSession()
    session._page = _Page()
    session._context = _Context()

    with pytest.raises(RuntimeError, match="unavailable or ambiguous"):
        session.approval_context("click", {"selector": "#continue"})


@pytest.mark.parametrize(
    "count,disabled,visible,in_viewport",
    [
        (0, False, True, True),
        (2, False, True, True),
        (1, True, True, True),
        (1, False, False, True),
        (1, False, True, False),
    ],
)
def test_browser_context_rejects_unavailable_or_nonvisible_target(
    count, disabled, visible, in_viewport,
):
    from maverick.tools.browser import _BrowserSession

    class _Locator:
        first = None

        def __init__(self):
            self.first = self

        def count(self):
            return count

        def evaluate(self, _script):
            return {
                "tag": "BUTTON", "text": "Delete", "disabled": disabled,
                "readOnly": False, "visible": visible,
                "inViewport": in_viewport,
                "rect": [1, 1, 100, 30],
            }

    class _Page:
        url = "https://example.test/review"

        def locator(self, _selector):
            return _Locator()

    class _Context:
        @staticmethod
        def storage_state():
            return {"cookies": []}

    session = _BrowserSession()
    session._page = _Page()
    session._context = _Context()

    with pytest.raises(RuntimeError, match="unavailable or ambiguous"):
        session.approval_context("click", {"selector": "#decision"})


def test_dispatch_consumption_rechecks_target_after_gate_returns(monkeypatch):
    _capture(monkeypatch)
    contexts = iter([
        {"page_url": "https://example.test/review", "target": "Save"},
        {"page_url": "https://example.test/review", "target": "Save"},
        {"page_url": "https://example.test/review", "target": "Delete"},
    ])
    parameters = {"selector": "#decision"}
    permit = action_gate.gate_browser_action(
        "click", parameters, context_provider=lambda: next(contexts),
    )

    assert isinstance(permit, action_gate.ActionPermit)
    dispatched = []
    denied = action_gate.consume_action_permit(
        permit, effect=lambda: dispatched.append(True) or "clicked",
    )
    assert denied and "changed after approval" in denied
    assert dispatched == []
    assert action_gate.consume_action_permit(
        permit, effect=lambda: "clicked",
    ).startswith("ERROR: action approval was already consumed")


def test_expired_action_permit_has_plain_targeted_message(monkeypatch):
    from maverick import approval_cards

    _capture(monkeypatch)
    _mutable_authority(monkeypatch)

    def context():
        return {
            "window": "settings",
            "target_summary": "Save settings",
            "credential_version_sha256": "d" * 64,
        }

    permit = action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=context,
    )
    assert isinstance(permit, action_gate.ActionPermit)
    original = approval_cards.require_current_approval_card
    monkeypatch.setattr(
        approval_cards,
        "require_current_approval_card",
        lambda card: original(card, now=float(card["expires_at"]) + 1.0),
    )
    dispatched = []

    result = action_gate.consume_action_permit(
        permit, effect=lambda: dispatched.append(True) or "clicked",
    )

    assert "approval expired" in result
    assert "Save settings" in result
    assert dispatched == []


def test_configured_auth_refuses_rbac_lookup_failure(monkeypatch):
    from maverick import connections
    from maverick_dashboard import auth

    calls = _capture(monkeypatch)
    monkeypatch.setattr(connections, "current_principal", lambda: "user:alice")
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: False)
    monkeypatch.setattr(
        auth, "role_for_principal",
        lambda principal: (_ for _ in ()).throw(RuntimeError("RBAC unavailable")),
    )

    result = action_gate.gate_browser_action(
        "click", {"selector": "#save"},
        context_provider=lambda: {"target_state_sha256": "a" * 64},
    )

    assert result and "approval authority is unavailable" in result
    assert calls == []


def test_workspace_authority_failure_denies_before_and_after_approval(monkeypatch):
    calls = _capture(monkeypatch)
    def context():
        return {"target_state_sha256": "a" * 64}
    permit = action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=context,
    )
    assert isinstance(permit, action_gate.ActionPermit)

    monkeypatch.setattr(
        consent_module,
        "current_tenant_id_strict",
        lambda: (_ for _ in ()).throw(RuntimeError("tenant registry unavailable")),
    )
    denied = action_gate.consume_action_permit(
        permit,
        effect=lambda: "clicked",
    )

    assert denied and "changed after approval" in denied
    assert len(calls) == 1

    fresh = action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=context,
    )
    assert fresh and "approval authority is unavailable" in fresh
    assert len(calls) == 1


def test_budget_authority_failure_denies_before_and_after_approval(monkeypatch):
    from maverick import config

    calls = _capture(monkeypatch)
    def context():
        return {"target_state_sha256": "a" * 64}
    permit = action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=context,
    )
    assert isinstance(permit, action_gate.ActionPermit)

    monkeypatch.setattr(
        config,
        "get_budget_overrides",
        lambda: (_ for _ in ()).throw(RuntimeError("budget store unavailable")),
    )
    denied = action_gate.consume_action_permit(
        permit,
        effect=lambda: "clicked",
    )

    assert denied and "changed after approval" in denied
    assert len(calls) == 1

    fresh = action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=context,
    )
    assert fresh and "approval authority is unavailable" in fresh
    assert len(calls) == 1


def test_browser_dispatch_does_not_click_after_post_gate_target_swap(monkeypatch):
    from maverick.tools import browser

    _capture(monkeypatch)
    contexts = iter([
        {"page_url": "https://example.test/review", "target": "Save"},
        {"page_url": "https://example.test/review", "target": "Save"},
        {"page_url": "https://example.test/review", "target": "Delete"},
    ])

    class _Page:
        url = "https://example.test/review"
        clicks = 0

        def click(self, selector, timeout):
            del selector, timeout
            self.clicks += 1

    class _Session:
        page = _Page()

        @staticmethod
        def approval_context(action, args):
            del action, args
            return next(contexts)

    session = _Session()
    monkeypatch.setattr(browser, "_get_session", lambda: session)
    monkeypatch.setattr(browser, "_deny_and_close_current_page", lambda *args: None)

    result = browser._run_browser_action({"action": "click", "selector": "#save"})

    assert result and "changed after approval" in result
    assert session.page.clicks == 0


def test_computer_dispatch_does_not_click_after_post_gate_window_swap(monkeypatch):
    from maverick.tools import computer

    _capture(monkeypatch)
    contexts = iter([
        {"foreground_window_sha256": "a" * 64},
        {"foreground_window_sha256": "a" * 64},
        {"foreground_window_sha256": "b" * 64},
    ])
    monkeypatch.setattr(
        computer, "_computer_approval_context", lambda args=None: next(contexts),
    )
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)

    class _PyAutoGui:
        FAILSAFE = True
        clicks = 0

        @staticmethod
        def size():
            return (1280, 800)

        def click(self, x=None, y=None):
            del x, y
            self.clicks += 1

    driver = _PyAutoGui()
    monkeypatch.setattr(computer, "_ensure_pyautogui", lambda: driver)

    result = computer._run_computer_action(
        {"action": "left_click", "coordinate": [10, 20]},
    )

    assert result and "changed after approval" in result
    assert driver.clicks == 0


def test_browser_raw_selector_driver_is_refused_after_final_observation(monkeypatch):
    from maverick.tools import browser

    _capture(monkeypatch)

    class _Page:
        url = "https://example.test/review"
        clicks = 0

        def click(self, selector, timeout):
            del selector, timeout
            self.clicks += 1

    class _Session:
        page = _Page()

        @staticmethod
        def approval_context(action, args):
            del action, args
            return {"page_url": _Page.url, "target_state_sha256": "a" * 64}

    session = _Session()
    monkeypatch.setattr(browser, "_get_session", lambda: session)
    monkeypatch.setattr(browser, "_deny_and_close_current_page", lambda *args: None)

    result = browser._run_browser_action({"action": "click", "selector": "#save"})

    assert "cannot be bound atomically" in result
    assert session.page.clicks == 0


def test_computer_raw_global_driver_is_refused_after_final_observation(monkeypatch):
    from maverick.tools import computer

    _capture(monkeypatch)
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)
    monkeypatch.setattr(
        computer,
        "_computer_approval_context",
        lambda args=None: {
            "foreground_window_sha256": "a" * 64,
            "coordinate_sha256": "b" * 64,
        },
    )

    class _PyAutoGui:
        FAILSAFE = True
        clicks = 0

        @staticmethod
        def size():
            return (1280, 800)

        def click(self, x=None, y=None):
            del x, y
            self.clicks += 1

    driver = _PyAutoGui()
    monkeypatch.setattr(computer, "_ensure_pyautogui", lambda: driver)

    result = computer._run_computer_action(
        {"action": "left_click", "coordinate": [10, 20]},
    )

    assert "cannot be bound atomically" in result
    assert driver.clicks == 0


def test_browser_dispatch_uses_the_exact_frozen_reviewed_parameters(monkeypatch):
    from maverick.tools import browser

    _capture(monkeypatch)
    request = {"action": "click", "selector": "#save"}

    class _Page:
        url = "https://example.test/review"
        selectors = []

        def click(self, selector, timeout):
            del timeout
            self.selectors.append(selector)

    class _Session:
        page = _Page()
        observations = 0

        def approval_context(self, action, args):
            del action, args
            self.observations += 1
            if self.observations == 4:
                request["selector"] = "#delete-account"
            return {
                "page_url": self.page.url,
                "target_state_sha256": "a" * 64,
            }

        def dispatch_approved(self, action, args, timeout, allow_hosts):
            del action, allow_hosts
            self.page.click(args["selector"], timeout)
            return f"clicked {args['selector']}"

    session = _Session()
    monkeypatch.setattr(browser, "_get_session", lambda: session)
    monkeypatch.setattr(browser, "_deny_and_close_current_page", lambda *args: None)

    result = browser._run_browser_action(request)

    assert result.startswith("clicked")
    assert session.observations >= 4
    assert request["selector"] == "#delete-account"
    assert session.page.selectors == ["#save"]


def test_computer_dispatch_uses_the_exact_frozen_reviewed_parameters(monkeypatch):
    from maverick.tools import computer

    _capture(monkeypatch)
    request = {"action": "left_click", "coordinate": [10, 20]}
    observations = 0

    def context(args=None):
        nonlocal observations
        del args
        observations += 1
        if observations == 4:
            request["coordinate"][:] = [900, 700]
        return {
            "foreground_window_sha256": "a" * 64,
            "coordinate_sha256": "b" * 64,
        }

    class _PyAutoGui:
        FAILSAFE = True
        clicks = []

        @staticmethod
        def size():
            return (1280, 800)

        def click(self, x=None, y=None):
            self.clicks.append((x, y))

        def dispatch_bound(self, action, coord, args):
            del action, args
            self.click(*coord)
            return f"clicked at {coord}"

    driver = _PyAutoGui()
    monkeypatch.setattr(computer, "_computer_approval_context", context)
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)
    monkeypatch.setattr(computer, "_ensure_pyautogui", lambda: driver)

    result = computer._run_computer_action(request)

    assert result.startswith("clicked")
    assert observations >= 4
    assert request["coordinate"] == [900, 700]
    assert driver.clicks == [(10, 20)]


def test_concurrent_role_mutation_winning_before_browser_fence_blocks_click(
    monkeypatch,
):
    from maverick.authority_effects import authority_effect_fence
    from maverick.tools import browser

    _capture(monkeypatch)
    authority = _mutable_authority(monkeypatch)

    class _Page:
        url = "https://example.test/review"
        clicks = 0

        def click(self, selector, timeout):
            del selector, timeout
            self.clicks += 1

    class _Session:
        page = _Page()

        @staticmethod
        def approval_context(action, args):
            del action, args
            return {
                "page_url": "https://example.test/review",
                "target": "Save",
                "credential_version_sha256": "d" * 64,
            }

        def dispatch_approved(self, action, args, timeout, allow_hosts):
            del action, allow_hosts
            self.page.click(args["selector"], timeout)
            return f"clicked {args['selector']}"

    real_gate = browser.gate_browser_action

    def mutate_role_then_return(*args, **kwargs):
        permit = real_gate(*args, **kwargs)

        def mutate():
            with authority_effect_fence():
                authority["authority"]["role"] = "viewer"

        thread = threading.Thread(target=mutate)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive(), "role mutation did not win before dispatch"
        return permit

    session = _Session()
    monkeypatch.setattr(browser, "_get_session", lambda: session)
    monkeypatch.setattr(browser, "_deny_and_close_current_page", lambda *args: None)
    monkeypatch.setattr(browser, "gate_browser_action", mutate_role_then_return)

    result = browser._run_browser_action({"action": "click", "selector": "#save"})

    assert result and "changed after approval" in result
    assert session.page.clicks == 0


def test_concurrent_credential_mutation_before_computer_fence_blocks_click(
    monkeypatch,
):
    from maverick.authority_effects import authority_effect_fence
    from maverick.tools import computer

    _capture(monkeypatch)
    _mutable_authority(monkeypatch)
    credential = {"digest": "d" * 64}
    monkeypatch.setattr(
        computer,
        "_computer_approval_context",
        lambda args=None: {
            "foreground_window_sha256": "e" * 64,
            "credential_version_sha256": credential["digest"],
        },
    )
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)

    class _PyAutoGui:
        FAILSAFE = True
        clicks = 0

        @staticmethod
        def size():
            return (1280, 800)

        def click(self, x=None, y=None):
            del x, y
            self.clicks += 1

    driver = _PyAutoGui()
    monkeypatch.setattr(computer, "_ensure_pyautogui", lambda: driver)
    real_gate = computer.gate_computer_action

    def rotate_credential_then_return(*args, **kwargs):
        permit = real_gate(*args, **kwargs)

        def mutate():
            with authority_effect_fence():
                credential["digest"] = "f" * 64

        thread = threading.Thread(target=mutate)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive(), "credential rotation did not win before dispatch"
        return permit

    monkeypatch.setattr(
        computer, "gate_computer_action", rotate_credential_then_return,
    )

    result = computer._run_computer_action(
        {"action": "left_click", "coordinate": [10, 20]},
    )

    assert result and "changed after approval" in result
    assert driver.clicks == 0


def test_browser_physical_dispatch_holds_authority_fence_until_return(
    monkeypatch,
):
    from maverick.authority_effects import authority_effect_fence
    from maverick.tools import browser

    _capture(monkeypatch)
    _mutable_authority(monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    mutation_done = threading.Event()

    class _Page:
        url = "https://example.test/review"

        def click(self, selector, timeout):
            del selector, timeout
            entered.set()
            assert release.wait(10), "test did not release browser action"

    class _Session:
        page = _Page()

        @staticmethod
        def approval_context(action, args):
            del action, args
            return {
                "page_url": "https://example.test/review",
                "target": "Save",
                "credential_version_sha256": "d" * 64,
            }

        def dispatch_approved(self, action, args, timeout, allow_hosts):
            del action, allow_hosts
            self.page.click(args["selector"], timeout)
            return f"clicked {args['selector']}"

    session = _Session()
    monkeypatch.setattr(browser, "_get_session", lambda: session)
    monkeypatch.setattr(browser, "_deny_and_close_current_page", lambda *args: None)

    def mutate_authority():
        try:
            with authority_effect_fence():
                pass
        finally:
            mutation_done.set()

    executor = ThreadPoolExecutor(max_workers=2)
    try:
        effect = executor.submit(
            browser._run_browser_action,
            {"action": "click", "selector": "#save"},
        )
        assert entered.wait(5), "browser action did not reach physical dispatch"
        mutation = executor.submit(mutate_authority)
        assert not mutation_done.wait(0.25), (
            "authority mutation crossed the live browser effect fence"
        )
        release.set()
        assert effect.result(timeout=10).startswith("clicked")
        mutation.result(timeout=10)
    finally:
        release.set()
        executor.shutdown(wait=True)

    assert mutation_done.is_set()


def test_computer_physical_dispatch_holds_authority_fence_until_return(
    monkeypatch,
):
    from maverick.authority_effects import authority_effect_fence
    from maverick.tools import computer

    _capture(monkeypatch)
    _mutable_authority(monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    mutation_done = threading.Event()
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)
    monkeypatch.setattr(
        computer,
        "_computer_approval_context",
        lambda args=None: {
            "foreground_window_sha256": "e" * 64,
            "credential_version_sha256": "f" * 64,
        },
    )

    class _PyAutoGui:
        FAILSAFE = True

        @staticmethod
        def size():
            return (1280, 800)

        @staticmethod
        def click(x=None, y=None):
            del x, y
            entered.set()
            assert release.wait(10), "test did not release computer action"

        @staticmethod
        def dispatch_bound(action, coord, args):
            del action, args
            _PyAutoGui.click(*coord)
            return f"clicked at {coord}"

    monkeypatch.setattr(computer, "_ensure_pyautogui", _PyAutoGui)

    def mutate_authority():
        try:
            with authority_effect_fence():
                pass
        finally:
            mutation_done.set()

    executor = ThreadPoolExecutor(max_workers=2)
    try:
        effect = executor.submit(
            computer._run_computer_action,
            {"action": "left_click", "coordinate": [10, 20]},
        )
        assert entered.wait(5), "computer action did not reach physical dispatch"
        mutation = executor.submit(mutate_authority)
        assert not mutation_done.wait(0.25), (
            "authority mutation crossed the live computer effect fence"
        )
        release.set()
        assert effect.result(timeout=10).startswith("clicked")
        mutation.result(timeout=10)
    finally:
        release.set()
        executor.shutdown(wait=True)

    assert mutation_done.is_set()


def test_computer_context_commits_the_foreground_window(monkeypatch):
    from maverick.tools import computer

    target = {"title": "Review"}
    monkeypatch.setattr(
        computer,
        "_foreground_window_identity",
        lambda: {"window": 1, "title": target["title"]},
    )
    before = computer._computer_approval_context({"coordinate": [10, 20]})
    target["title"] = "Different application"
    after = computer._computer_approval_context({"coordinate": [10, 20]})

    assert before["foreground_window_sha256"] != after["foreground_window_sha256"]


def test_dispatch_recheck_blocks_target_swap_after_permit_validation(monkeypatch):
    _capture(monkeypatch)
    safe = {"page_url": "https://example.test", "target": "Save"}
    swapped = {"page_url": "https://example.test", "target": "Delete"}
    contexts = iter([safe, safe, safe, swapped])
    permit = action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=lambda: next(contexts),
    )
    assert isinstance(permit, action_gate.ActionPermit)
    dispatched = []

    result = action_gate.consume_action_permit(
        permit, effect=lambda: dispatched.append(True) or "clicked",
    )

    assert "target changed at dispatch" in result
    assert dispatched == []


def test_lightwork_token_in_selector_is_redacted_from_approval(monkeypatch):
    calls = _capture(monkeypatch)
    token = "lw-rest-" + "A" * 43
    selector = f'input[value="{token}"]'

    action_gate.gate_browser_action("click", {"selector": selector})

    visible = (
        calls[0]["scope"]
        + calls[0]["detail"]
        + repr(calls[0]["approval_card"])
    )
    assert token not in visible
    assert "REDACTED:lightwork_agent_token" in visible


def test_browser_selector_and_exception_token_are_redacted_at_runtime(
    monkeypatch, caplog,
):
    from maverick.tools import browser

    _capture(monkeypatch)
    token = "lw-rest-" + "A" * 43
    selector = f'input[value="{token}"]'

    class _Page:
        url = "https://example.test/review"

        @staticmethod
        def click(received, timeout):
            del timeout
            assert received == selector
            raise RuntimeError(f"Playwright rejected selector {received}")

    class _Session:
        page = _Page()

        @staticmethod
        def approval_context(action, args):
            del action, args
            return {
                "page_url": "https://example.test/review",
                "target_state_sha256": "a" * 64,
            }

        def dispatch_approved(self, action, args, timeout, allow_hosts):
            del action, allow_hosts
            self.page.click(args["selector"], timeout)

    monkeypatch.setattr(browser, "_get_session", _Session)
    monkeypatch.setattr(browser, "_deny_and_close_current_page", lambda *args: None)
    caplog.set_level("INFO", logger="maverick.tools.browser")

    result = browser._run_browser_action(
        {"action": "click", "selector": selector},
    )

    visible = result + caplog.text
    assert token not in visible
    assert "REDACTED:lightwork_agent_token" in visible
    assert "observe current state before retrying" in result


def test_computer_driver_exception_token_is_redacted_at_runtime(monkeypatch):
    from maverick.tools import computer

    _capture(monkeypatch)
    token = "lw-mcp-" + "B" * 43
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)
    monkeypatch.setattr(
        computer,
        "_computer_approval_context",
        lambda args=None: {
            "foreground_window_sha256": "c" * 64,
            "coordinate_sha256": "d" * 64,
        },
    )

    class _PyAutoGui:
        FAILSAFE = True

        @staticmethod
        def size():
            return (1280, 800)

        @staticmethod
        def typewrite(text, interval):
            del interval
            assert text == token
            raise RuntimeError(f"driver rejected input {text}")

        @staticmethod
        def dispatch_bound(action, coord, args):
            del action, coord
            _PyAutoGui.typewrite(args["text"], interval=0.01)

    monkeypatch.setattr(computer, "_ensure_pyautogui", _PyAutoGui)

    result = computer._run_computer_action({"action": "type", "text": token})

    assert token not in result
    assert "REDACTED:lightwork_agent_token" in result
    assert "observe current state before retrying" in result


def test_redacted_live_target_summary_is_visible_to_approver(monkeypatch):
    calls = _capture(monkeypatch)
    context = {
        "target_state_sha256": "a" * 64,
        "target_summary": "Save customer 42",
    }

    action_gate.gate_browser_action(
        "click", {"selector": "#save"}, context_provider=lambda: context,
    )

    assert "Save customer 42" in calls[0]["scope"]
    assert "Save customer 42" in calls[0]["detail"]
