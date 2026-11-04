"""Per-action approval gate for the computer-use and browser tools.

The computer and browser tools actuate real input -- clicks, keystrokes, form
fills -- that can submit a payment, send a message, or delete data. Tool-level
risk (``safety/tool_risk.py`` marks both ``high``) only decides whether the
tool is *registered*; it does not gate an individual click. This module gates
the *action*: a mutating actuation is routed through the exact-operation
consent boundary used by the other effecting tools, so the existing approval
queue, dashboard ``/approvals`` page, TTY prompt, and signed audit events all
apply with no new machinery.

Only the explicit mutating actions are gated; observation actions (screenshot,
extract_text, cursor_position, wait, ...) and unknown/typo actions are
no-ops. A mutating action defaults to ``medium`` risk; one whose target,
typed text, or key chord matches a high-impact verb (pay, submit, transfer,
delete, ...) escalates to ``high`` so the operator console and the audit trail
record *why* it was flagged.

Privacy: the high-risk classifier inspects typed *values* in memory, but the
audit ``detail`` records selectors/coordinates and value *lengths* only -- a
typed password or PII value must never land in the (potentially exported)
audit log. Navigation URLs are recorded without userinfo, query strings,
or fragments so reset tokens, OAuth codes, pre-signed signatures, and email
addresses in URL parameters are not persisted. Click/key targets are
secret-redacted before they become operator-visible labels; the exact value
remains bound only by its digest.

Every mutating browser or computer action needs an exact human decision. Silent
auto approval and standing action/scope grants are intentionally ineligible;
``ask`` and ``dashboard`` provide the interactive decision paths. Observation
actions remain ungated.
"""
from __future__ import annotations

import copy
import hmac
import re
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..approval_cards import ApprovalCardError, digest
from .consent import (
    ConsentDenied,
    ConsentPermit,
    consume_operation_consent,
    require_operation_consent,
)

# Explicit allowlists of actuating (state-mutating) actions. Everything else --
# observation actions and any unknown/typo action -- is a no-op, so
# the gate can never accidentally block a read or an unrecognised verb.
_COMPUTER_MUTATING = frozenset({
    "left_click", "right_click", "middle_click", "double_click",
    "left_click_drag", "type", "key", "mouse_move", "scroll",
})
_BROWSER_MUTATING = frozenset({
    "navigate", "go_back", "go_forward", "click", "type", "fill_form",
    "press", "scroll", "save_session", "close",
})

# High-impact verbs/nouns. A mutating action whose visible target text matches
# escalates medium -> high. Word boundaries so "approve" hits but "approximate"
# does not. Over-flagging here is the safe direction: a false ``high`` only adds
# a label, while a missed ``high`` understates a real risk.
_HIGH_RISK = re.compile(
    r"\b(pay|payment|purchase|buy|checkout|order|submit|send|transfer|wire|"
    r"remit|withdraw|approve|confirm|authori[sz]e|sign|delete|destroy|remove|"
    r"drop|wipe|erase|deactivate|disable|terminate|publish|deploy|merge|"
    r"execute)\b",
    re.IGNORECASE,
)
# Key chords that typically commit a form / fire the default action.
_SUBMIT_KEYS = ("enter", "return")

_MAX_DETAIL = 200
_APPROVAL_TTL_SECONDS = 300.0


@dataclass(frozen=True)
class ActionPermit:
    """Exact one-use consent carried to the physical dispatch boundary."""

    operation: ConsentPermit = field(repr=False)
    boundary: _ActionBoundary = field(repr=False)
    target_label: str = field(repr=False)

    @property
    def card(self) -> dict[str, Any]:
        return self.operation.card


def _short(text: str | None) -> str | None:
    """Collapse whitespace and bound length for an audit label."""
    if not text:
        return None
    out = " ".join(str(text).split())
    try:
        from .secret_detector import redact

        out, _matches = redact(out)
    except Exception:
        return "[approval label unavailable]"
    out = out[:_MAX_DETAIL]
    return out or None


def _safe_url_label(url: str | None) -> str | None:
    """Return a consent/audit-safe URL label without secret-bearing parts."""
    if not url:
        return None
    text = str(url)
    try:
        parts = urlsplit(text)
    except ValueError:
        return "[invalid URL]"
    if not parts.scheme and not parts.netloc:
        return _short(text.split("?", 1)[0].split("#", 1)[0]) or "[URL]"
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None:
        host = f"{host}:{port}"
    netloc = host
    if parts.scheme and not netloc:
        return _short(urlunsplit((parts.scheme, "", parts.path, "", ""))) or "[URL]"
    return _short(urlunsplit((parts.scheme, netloc, parts.path, "", ""))) or "[URL]"


def _matches_high_risk(*texts: str | None, key: str | None = None) -> bool:
    if key and any(k in key.lower() for k in _SUBMIT_KEYS):
        return True
    return any(t and _HIGH_RISK.search(t) for t in texts)


def _capture_context(
    provider: Callable[[], Mapping[str, Any]] | None,
) -> dict[str, Any]:
    if provider is None:
        return {"state": "not_supplied"}
    try:
        value = provider()
        if not isinstance(value, Mapping):
            raise TypeError("context provider did not return an object")
        captured = dict(value)
        digest(captured)
        return captured
    except Exception:
        # The unavailable state is explicit on the approval card.  A transition
        # to or from it still changes the exact operation binding.
        return {"state": "unavailable"}


def _effect_description(surface: str, action: str, risk: str) -> tuple[list[str], list[str], str, str, bool]:
    if surface == "browser":
        effects = {
            "navigate": ["Loads the reviewed destination in the active browser session."],
            "go_back": ["Navigates the active browser session to its previous history entry."],
            "go_forward": ["Navigates the active browser session to its next history entry."],
            "click": ["Activates the reviewed page target once."],
            "type": ["Changes the reviewed field in the active page."],
            "fill_form": ["Changes the reviewed set of form fields in the active page."],
            "press": ["Sends the reviewed key press to the active page target."],
            "scroll": ["Changes the active page viewport by the reviewed distance."],
            "save_session": [
                "Persists active browser cookies and local storage to the configured profile."
            ],
            "close": [
                "Saves configured browser state and closes the active browser session."
            ],
        }[action]
        assumptions = [
            "The current page and selector still identify the intended customer-visible target.",
            "Page scripts may cause effects that Lightwork cannot predict from the selector alone.",
        ]
        before = "The active page has not received this reviewed browser action."
        after = "The active page has received this action once; downstream site behavior may persist."
        irreversible = risk == "high" and action in {
            "click", "press", "navigate", "go_back", "go_forward",
        }
    else:
        effects = ["Sends one reviewed mouse or keyboard action to the active computer session."]
        assumptions = [
            "The foreground application and coordinate still identify the intended target.",
            "The application may interpret the input as a submit, send, purchase, or deletion.",
        ]
        before = "The foreground application has not received this reviewed input."
        after = "The foreground application has received this input once; application effects may persist."
        irreversible = risk == "high"
    return effects, assumptions, before, after, irreversible


class _ActionBoundary:
    """Keep target and credential commitments on one live context snapshot."""

    def __init__(
        self,
        *,
        scope: str | None,
        parameters: Mapping[str, Any],
        context_provider: Callable[[], Mapping[str, Any]] | None,
        initial_context: Mapping[str, Any],
        surface: str,
    ) -> None:
        self._scope = scope
        self._parameters = parameters
        self._context_provider = context_provider
        self._initial_context: dict[str, Any] | None = copy.deepcopy(
            dict(initial_context)
        )
        self._latest_context = copy.deepcopy(dict(initial_context))
        self._surface = surface

    def target(self) -> dict[str, Any]:
        # ``require_operation_consent`` first verifies the declared snapshot,
        # then calls again after the decision and at consumption. Reuse the
        # already captured snapshot exactly once so each later validation is a
        # genuinely fresh read from the physical target.
        if self._initial_context is not None:
            current = self._initial_context
            self._initial_context = None
        else:
            current = _capture_context(self._context_provider)
        self._latest_context = copy.deepcopy(current)
        return {"scope": self._scope, "context": copy.deepcopy(current)}

    def parameters(self) -> dict[str, Any]:
        # Keep the live mapping rather than freezing it: changing an argument
        # after review must invalidate the permit before dispatch.
        return copy.deepcopy(dict(self._parameters))

    def credentials(self) -> dict[str, Any]:
        # The generic boundary always resolves target before credentials. Use
        # that same snapshot so a page/window and its credential generation
        # cannot be assembled from two different observations.
        return {
            "surface": self._surface,
            "version_sha256": self._latest_context.get(
                "credential_version_sha256", "not_available"
            ),
        }

    def assert_dispatch_current(self) -> None:
        """Refuse when the physical target changes after permit validation."""

        current = _capture_context(self._context_provider)
        if current.get("state") == "unavailable" or not hmac.compare_digest(
            digest(current), digest(self._latest_context)
        ):
            raise ApprovalCardError("the physical target changed after approval")
        self._latest_context = copy.deepcopy(current)


def _require(
    name: str,
    risk: str,
    scope: str | None,
    detail: str | None,
    *,
    parameters: Mapping[str, Any],
    context_provider: Callable[[], Mapping[str, Any]] | None = None,
) -> str | ActionPermit:
    """Route through exact consent and return a one-use dispatch permit.

    ``name`` is built from the validated action enum (never free model text), so
    it is safe to reuse as ``provenance`` for the operator console label.
    """
    surface, _, action = name.partition(".")
    before_context = _capture_context(context_provider)
    if context_provider is not None and before_context.get("state") == "unavailable":
        return f"ERROR: {name} target context is unavailable; observe it and review again"
    context_label = _short(str(before_context.get("target_summary") or ""))
    display_scope = _short(scope) or name
    if context_label and context_label not in display_scope:
        display_scope = _short(f"{display_scope}; current target: {context_label}")
    display_detail = _short(detail) or name
    if context_label and context_label not in display_detail:
        display_detail = _short(f"{display_detail}; current target: {context_label}")
    effects, assumptions, before, after, irreversible = _effect_description(
        surface, action, risk,
    )
    boundary = _ActionBoundary(
        scope=scope,
        parameters=parameters,
        context_provider=context_provider,
        initial_context=before_context,
        surface=surface,
    )
    try:
        operation = require_operation_consent(
            action=name,
            risk=risk,
            scope=display_scope,
            detail=display_detail,
            provenance=name,
            target={"scope": scope, "context": before_context},
            parameters=dict(parameters),
            parameter_summary=[display_detail],
            known_effects=effects,
            unresolved_assumptions=assumptions,
            before=before,
            after=after,
            irreversible=irreversible,
            target_provider=boundary.target,
            parameters_provider=boundary.parameters,
            credential_versions_provider=boundary.credentials,
            # An exact browser/computer decision cannot be inherited from a
            # standing (action, scope) grant or a silent auto-approval.
            allow_auto_approve=False,
            consult_ledger=False,
            ttl_seconds=_APPROVAL_TTL_SECONDS,
        )
    except ConsentDenied:
        return (
            f"ERROR: {name} was not approved for {display_scope!r}; "
            "no action was sent"
        )
    except ApprovalCardError as exc:
        lowered = str(exc).lower()
        if "expired" in lowered:
            return (
                f"ERROR: {name} approval expired for {display_scope!r}; "
                "review it again"
            )
        if "actor is unavailable" in lowered:
            return (
                "ERROR: the current signed-in actor is unavailable for "
                f"{name} on {display_scope!r}; sign in and review it again"
            )
        if "changed after approval" in lowered:
            return (
                f"ERROR: {name} changed while approval was pending for "
                f"{display_scope!r}; review it again"
            )
        return (
            f"ERROR: {name} approval authority is unavailable for "
            f"{display_scope!r}; review it again"
        )
    return ActionPermit(
        operation=operation,
        boundary=boundary,
        target_label=display_scope,
    )


def consume_action_permit(
    permit: ActionPermit,
    *,
    effect: Callable[[], str],
) -> str:
    """Revalidate and run one physical effect inside the authority fence."""

    if not isinstance(permit, ActionPermit):
        return "ERROR: an exact action approval is required; review it again"
    if not callable(effect):
        return "ERROR: action dispatch is unavailable; no physical effect occurred"
    stack = ExitStack()
    try:
        stack.enter_context(consume_operation_consent(permit.operation))
    except ApprovalCardError as exc:
        stack.close()
        lowered = str(exc).lower()
        if "already consumed" in lowered:
            return (
                "ERROR: action approval was already consumed for "
                f"{permit.target_label!r}; review it again"
            )
        if "expired" in lowered:
            return (
                "ERROR: action approval expired for "
                f"{permit.target_label!r}; review it again"
            )
        if "actor is unavailable" in lowered:
            return (
                "ERROR: the current signed-in actor is unavailable for "
                f"{permit.target_label!r}; sign in and review it again"
            )
        return (
            f"ERROR: action changed after approval for {permit.target_label!r}; "
            "review the current operation"
        )
    with stack:
        try:
            permit.boundary.assert_dispatch_current()
        except ApprovalCardError:
            return (
                "ERROR: action target changed at dispatch for "
                f"{permit.target_label!r}; observe and review it again"
            )
        return effect()


def computer_action_risk(action: str, args: dict[str, Any]) -> str | None:
    """Risk of a computer action: ``'high'``/``'medium'`` for a mutating
    actuation, ``None`` for a read/observe action (which is never gated)."""
    if action not in _COMPUTER_MUTATING:
        return None
    text = args.get("text")
    high = _matches_high_risk(text, key=text if action == "key" else None)
    return "high" if high else "medium"


def gate_computer_action(
    action: str,
    args: dict[str, Any],
    *,
    context_provider: Callable[[], Mapping[str, Any]] | None = None,
) -> str | ActionPermit | None:
    """Gate one computer-use action.

    Returns an ``ERROR:`` string if the action is denied (for the tool to
    return verbatim), or ``None`` to proceed. A no-op for non-mutating actions.
    """
    risk = computer_action_risk(action, args)
    if risk is None:
        return None
    text = args.get("text")
    coord = args.get("coordinate")
    scope = f"{action} at {coord}" if coord else action
    # Value-bearing actions log a length, not the value (could be a secret).
    if action == "type":
        detail = f"type {len(str(text or ''))} chars"
    elif action == "key":
        detail = f"key {_short(str(text or '')) or '[key]'}"
    elif action == "scroll":
        direction = _short(str(args.get("scroll_direction") or "down")) or "down"
        amount = int(args.get("scroll_amount") or 3)
        detail = f"scroll {direction} {amount} notch(es)"
    elif action == "mouse_move":
        detail = f"move pointer to {coord}" if coord else "move pointer"
    else:
        detail = f"at {coord}" if coord else action
    return _require(
        f"computer.{action}", risk, scope, detail,
        parameters=args, context_provider=context_provider,
    )


def browser_action_risk(action: str, args: dict[str, Any]) -> str | None:
    """Risk of a browser action: ``'high'``/``'medium'`` for a mutating action,
    ``None`` for a read action (which is never gated). Scans selectors *and*
    field values for the high-risk signal."""
    if action not in _BROWSER_MUTATING:
        return None
    text = args.get("text")
    raw_fields = args.get("fields")
    fields = raw_fields if isinstance(raw_fields, dict) else {}
    field_parts = [str(k) for k in fields] + [str(v) for v in fields.values()]
    key = text if action == "press" else None
    high = _matches_high_risk(args.get("selector"), args.get("url"), *field_parts, key=key)
    return "high" if high else "medium"


def gate_browser_action(
    action: str,
    args: dict[str, Any],
    *,
    context_provider: Callable[[], Mapping[str, Any]] | None = None,
) -> str | ActionPermit | None:
    """Gate one browser action.

    Returns an ``ERROR:`` string if the action is denied, or ``None`` to
    proceed. A no-op for non-mutating actions.
    """
    risk = browser_action_risk(action, args)
    if risk is None:
        return None
    selector = args.get("selector")
    text = args.get("text")
    url = args.get("url")
    raw_fields = args.get("fields")
    fields = raw_fields if isinstance(raw_fields, dict) else None
    field_keys = list(fields.keys()) if fields else []
    safe_selector = _short(str(selector or ""))
    if action == "navigate":
        scope = detail = _safe_url_label(url) or action
    elif action in {"go_back", "go_forward"}:
        scope = "active browser history"
        detail = "go to previous history entry" if action == "go_back" else "go to next history entry"
    elif action == "scroll":
        delta = int(args.get("delta_y") or 500)
        scope = "active page viewport"
        detail = f"scroll active page by {delta} pixels"
    elif action == "save_session":
        scope = "configured browser profile"
        detail = "save active cookies and local storage"
    elif action == "close":
        scope = "active browser session"
        detail = "save configured state and close the active session"
    elif action == "fill_form":
        scope = "fill_form"
        shown = ", ".join(
            _short(str(key)) or "[field]" for key in field_keys[:5]
        )
        detail = f"fill {len(field_keys)} field(s): {shown}" if field_keys else "fill_form"
    elif action == "type":
        scope = safe_selector or action
        detail = f"type {len(str(text or ''))} chars into {safe_selector or '[field]'}"
    elif action == "press":
        scope = safe_selector or "page"
        detail = f"press {_short(str(text or '')) or '[key]'} on {safe_selector or 'page'}"
    else:
        scope = safe_selector or action
        detail = f"click {safe_selector}" if safe_selector else action
    return _require(
        f"browser.{action}", risk, scope, detail,
        parameters=args, context_provider=context_provider,
    )


__all__ = [
    "ActionPermit",
    "consume_action_permit",
    "gate_computer_action",
    "gate_browser_action",
    "computer_action_risk",
    "browser_action_risk",
]
