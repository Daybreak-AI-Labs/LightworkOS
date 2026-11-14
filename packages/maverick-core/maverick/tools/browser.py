"""Browser tool. Playwright-driven web browsing as discrete actions.

Lets the agent navigate URLs, click links, fill forms, extract text,
and screenshot pages — discretely, action by action, with each action
visible in the trajectory.

Different from the ``computer`` tool: this is HIGH-LEVEL web automation
(navigate, find element by selector or text, click, fill). The computer
tool is low-level (click at pixel coords). Use browser for web tasks
that can be described semantically ("click the Login button"), and
computer for tasks where the UI isn't a normal DOM (desktop apps,
canvas-based interfaces, anti-bot challenges).

Browser context persists across actions in one goal. Separate goals, users,
and workspaces never share a page or cookies; goal cleanup closes the context.

Session persistence: cookies + localStorage are saved to disk only when
``MAVERICK_BROWSER_STATE`` explicitly points at a per-task profile file.
When enabled, the state file is mode 0600, checkpointed after navigation,
on the ``save_session`` action, and at interpreter exit, then reloaded
when the next standalone context starts. Goal-scoped contexts never use the
shared file. Disable with ``MAVERICK_BROWSER_NO_PERSIST=1``.

Safety:
  - All navigations are allow-listed by default to ``http(s)://`` URLs.
  - ``MAVERICK_BROWSER_DISABLE=1`` env var disables the tool entirely.
  - Each call is logged with action + URL for audit trail.
"""
from __future__ import annotations

import asyncio
import atexit
import base64
import contextvars
import copy
import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..file_lock import (
    atomic_write_text,
    ensure_private_directory,
    ensure_private_file,
    require_private_directory,
)
from ..paths import data_dir
from ..safety.action_evidence import seal_bracketed
from ..safety.action_gate import (
    ActionPermit,
    browser_action_risk,
    consume_action_permit,
    gate_browser_action,
)
from . import Tool
from .http_fetch import _scan_fetched

log = logging.getLogger(__name__)


# Upper bound for a caller's ``timeout_ms``: a wait blocks the scope's single
# browser worker, and the wall-clock budget is only checked between tool calls.
_DEFAULT_TIMEOUT_MS = 30_000
_MAX_TIMEOUT_MS = 120_000
_MAX_FILL_FORM_FIELDS = 25
_MAX_FILL_FORM_SELECTOR_LENGTH = 500
_MAX_FILL_FORM_VALUE_LENGTH = 10_000
_MAX_FILL_FORM_FIELD_TIMEOUT_MS = 1_000
_MAX_FILL_FORM_TOTAL_TIMEOUT_MS = 5_000
# Bound at import: tests drive the fill_form batch deadline through this
# module-local clock; patching time.monotonic itself is process-global, and
# the consent-gate audit path consumes ticks before the batch loop runs.
_monotonic = time.monotonic

# Bounds for the read-only ``observe`` snapshot so it never floods the context.
_MAX_OBSERVE_ELEMENTS = 100
_MAX_OBSERVE_NAME_LENGTH = 120
_MAX_OBSERVE_AXTREE_CHARS = 20_000


def _redact_browser_text(value: Any) -> str:
    """Return model/log-visible browser text with capability tokens removed."""
    try:
        from ..safety.secret_detector import redact

        safe, _matches = redact(str(value or ""))
        return safe
    except Exception:
        # Browser targets and provider exceptions are untrusted. If the
        # detector is unavailable, withhold the label instead of reflecting a
        # selector, URL, DOM fragment, or exception that may contain a token.
        return "[browser detail withheld: redaction unavailable]"


# ---------- session persistence (cookies + localStorage survive restarts) ----------

_DEFAULT_STATE_PATH = data_dir("browser", "state.json")


def _persist_enabled() -> bool:
    """Only standalone use may load an explicitly configured state file.

    An environment-wide path cannot safely identify a user's goal or workspace.
    Goal sessions start fresh; browser_auth_vault is the explicit credential
    path for customer work.
    """
    from ..connections import current_principal
    from ..logging_config import current_goal_id
    from ..paths import current_tenant_id_strict

    return (
        os.environ.get("MAVERICK_BROWSER_NO_PERSIST") != "1"
        and bool(os.environ.get("MAVERICK_BROWSER_STATE"))
        and current_goal_id() is None
        and current_principal() is None
        and current_tenant_id_strict() is None
    )


def _state_path() -> Path:
    override = os.environ.get("MAVERICK_BROWSER_STATE")
    return Path(os.path.expanduser(override)) if override else _DEFAULT_STATE_PATH


def _restore_state_arg() -> str | None:
    """storage_state path to seed a new context with, or None for a fresh one."""
    if not _persist_enabled():
        return None
    p = _state_path()
    if not p.exists():
        return None
    require_private_directory(p.parent)
    # Protect state created by older releases before Playwright opens it.
    ensure_private_file(p)
    return str(p)


_BROWSER_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": [
                "navigate", "click", "type", "fill_form", "press", "scroll",
                "screenshot", "observe", "extract_text", "extract_html",
                "find_text", "wait_for", "go_back", "go_forward",
                "current_url", "list_links", "save_session", "close",
            ],
            "description": "Action to perform.",
        },
        "url": {
            "type": "string",
            "description": "URL for 'navigate' (http/https only).",
        },
        "selector": {
            "type": "string",
            "description": "CSS selector or Playwright text= locator for click/type/find_text/wait_for.",
        },
        "text": {
            "type": "string",
            "description": "Text to type, key to press, or text to find.",
        },
        "fields": {
            "type": "object",
            "description": "For 'fill_form': a {css_selector: value} map; fills many inputs in one call, in order.",
            "maxProperties": _MAX_FILL_FORM_FIELDS,
            "propertyNames": {"maxLength": _MAX_FILL_FORM_SELECTOR_LENGTH},
            "additionalProperties": {
                "type": "string",
                "maxLength": _MAX_FILL_FORM_VALUE_LENGTH,
            },
        },
        "delta_y": {
            "type": "integer",
            "description": "Pixels to scroll vertically (positive = down).",
        },
        "timeout_ms": {
            "type": "integer",
            "minimum": 1,
            "maximum": _MAX_TIMEOUT_MS,
            "description": "Override the default 30s action timeout (at most 120s).",
        },
    },
    "required": ["action"],
}


def _proxy_host_policy(tenant: str | None, host: str, port: int) -> bool:
    """Apply the originating session's hostname policy in the proxy thread."""
    from ..config import single_read
    from ..enterprise import egress_permitted
    from ..tenant.egress import egress_allowed

    # Enterprise policy parses a URL; bracket IPv6 so its host remains intact.
    authority = f"[{host}]" if ":" in host else host
    scheme = "https" if port == 443 else "http"
    # Do not retain a request's cached configuration past that request.
    with single_read(fresh=True):
        return egress_permitted(f"{scheme}://{authority}:{port}/") and egress_allowed(
            "browser", host, tenant=tenant,
        )


class _BrowserSession:
    """One persistent chromium instance, lazily started, thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        # Freeze this at creation: atexit/goal cleanup runs after the caller's
        # context may have been reset and must not turn persistence back on.
        self._allow_persist = _persist_enabled()
        self._playwright = None
        self._egress_proxy = None
        self._browser = None
        self._context = None
        self._page = None
        self._approval_dispatch = None

    @staticmethod
    def _target_snapshot(handle):
        return handle.evaluate("""element => {
            let activationContextWithinLimit = true;
            const bounded = value => {
              const text = String(value == null ? '' : value);
              if (text.length > 4096) activationContextWithinLimit = false;
              return text.slice(0, 4096);
            };
            const attribute = (node, name) => node.hasAttribute(name)
              ? bounded(node.getAttribute(name)) : null;
            const rect = element.getBoundingClientRect();
            const style = window.getComputedStyle(element);
            const cssVisible = style.display !== 'none' &&
              style.visibility !== 'hidden' &&
              style.visibility !== 'collapse' &&
              Number.parseFloat(style.opacity || '1') > 0;
            const checkVisible = typeof element.checkVisibility !== 'function' ||
              element.checkVisibility({
                checkOpacity: true,
                checkVisibilityCSS: true,
                contentVisibilityAuto: true
              });
            const inViewport = rect.bottom > 0 && rect.right > 0 &&
              rect.top < window.innerHeight && rect.left < window.innerWidth;
            const form = element.form || null;
            const submitter = form && /^(BUTTON|INPUT)$/.test(element.tagName);
            return {
              tag: element.tagName,
              id: element.id || '',
              name: element.getAttribute('name') || '',
              role: element.getAttribute('role') || '',
              type: element.getAttribute('type') || '',
              ariaLabel: element.getAttribute('aria-label') || '',
              text: String(element.innerText || element.value || '').slice(0, 1000),
              disabled: Boolean(element.disabled || element.getAttribute('aria-disabled') === 'true'),
              readOnly: Boolean(element.readOnly || element.getAttribute('aria-readonly') === 'true'),
              visible: Boolean(cssVisible && checkVisible),
              inViewport: Boolean(inViewport),
              href: attribute(element, 'href'),
              resolvedHref: element.hasAttribute('href')
                ? bounded(element.href) : null,
              formAttribute: attribute(element, 'form'),
              owningForm: form ? {
                id: bounded(form.id),
                name: bounded(form.getAttribute('name')),
                actionAttribute: attribute(form, 'action'),
                resolvedAction: bounded(form.action),
                method: bounded(form.method),
                enctype: bounded(form.enctype),
                target: bounded(form.target),
                noValidate: Boolean(form.noValidate)
              } : null,
              submitterOverrides: submitter ? {
                actionAttribute: attribute(element, 'formaction'),
                resolvedAction: bounded(element.formAction),
                methodAttribute: attribute(element, 'formmethod'),
                resolvedMethod: bounded(element.formMethod),
                enctypeAttribute: attribute(element, 'formenctype'),
                resolvedEnctype: bounded(element.formEnctype),
                targetAttribute: attribute(element, 'formtarget'),
                resolvedTarget: bounded(element.formTarget),
                noValidateAttribute: element.hasAttribute('formnovalidate'),
                noValidate: Boolean(element.formNoValidate)
              } : null,
              inlineHandler: String(element.onclick || '').slice(0, 4000),
              rect: [rect.x, rect.y, rect.width, rect.height].map(Math.round),
              activationContextWithinLimit
            };
        }""")

    def _ensure_started(self):
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise ImportError(
                "playwright not installed. Run: python -m pip install -e './packages/maverick-core[browser]' "
                "&& playwright install chromium"
            ) from e
        from ..consent_scanner import PlaywrightPageCollector, _PinnedSocksProxy
        from ..paths import current_tenant_id_strict, set_tenant

        tenant = current_tenant_id_strict()
        # Propagate only tenant identity, not an in-flight request's cached
        # configuration or other mutable context into proxy worker threads.
        session_context = contextvars.Context()
        session_context.run(set_tenant, tenant)
        # Keep the validated DNS answer tied to the actual socket connection,
        # including background and WebSocket traffic outside route callbacks.
        # A proxy failure must never fall back to an unguarded browser.
        try:
            self._egress_proxy = _PinnedSocksProxy(
                # Proxy workers are separate threads. Copy the pinned context
                # per call so tenant-specific configuration is resolved there.
                authorize_host=lambda host, port: session_context.copy().run(
                    _proxy_host_policy, tenant, host, port,
                ),
            )
            self._egress_proxy.__enter__()
            self._playwright = sync_playwright().start()
            from ..env_setting import env_or_config

            headless = env_or_config("MAVERICK_BROWSER_HEADED", "tools", "browser_headed", "0") != "1"
            launch = PlaywrightPageCollector._browser_launch_options(self._egress_proxy.server_url)
            launch["headless"] = headless
            self._browser = self._playwright.chromium.launch(**launch)
            self._context = self._browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
                storage_state=_restore_state_arg() if self._allow_persist else None,
            )
            # Apply destination policy to routed HTTP requests across pages and
            # popups. Chromium does not route every service-worker or WebSocket
            # request here; the pinned proxy is the IP-level network backstop.
            self._context.route("**/*", _route_guard)
            self._page = self._context.new_page()

        except BaseException:
            self.close()
            raise

    @property
    def page(self):
        self._ensure_started()
        return self._page

    def approval_context(
        self,
        action: str = "",
        args: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """Commit the live page, DOM target, and credentials without exposing them."""
        from ..approval_cards import digest

        self._ensure_started()
        state = self._context.storage_state()
        supplied = dict(args or {})
        selectors: list[str] = []
        if action in {"click", "type"} and supplied.get("selector"):
            selectors.append(str(supplied["selector"]))
        elif action == "fill_form" and isinstance(supplied.get("fields"), dict):
            selectors.extend(str(selector) for selector in supplied["fields"])
        elif action == "press":
            selectors.append(str(supplied.get("selector") or ":focus"))
        targets = []
        dispatch_targets = []
        for selector in selectors:
            try:
                locator = self._page.locator(selector)
                count = locator.count()
                if count != 1:
                    raise RuntimeError("approval target must resolve to exactly one element")
                handle_getter = getattr(locator.first, "element_handle", None)
                handle = handle_getter() if callable(handle_getter) else None
                first = self._target_snapshot(handle or locator.first)
                if not isinstance(first, dict) or first.get("disabled") is not False:
                    raise RuntimeError("approval target is not enabled")
                if first.get("activationContextWithinLimit", True) is not True:
                    raise RuntimeError(
                        "approval activation context exceeds the supported length"
                    )
                rectangle = first.get("rect")
                if (
                    not isinstance(rectangle, list)
                    or len(rectangle) != 4
                    or rectangle[2] <= 0
                    or rectangle[3] <= 0
                    or first.get("visible") is not True
                    or first.get("inViewport") is not True
                ):
                    raise RuntimeError("approval target is not currently visible")
                if action in {"type", "fill_form"} and first.get("readOnly") is True:
                    raise RuntimeError("approval target is read-only")
                targets.append({
                    "selector_sha256": digest(selector),
                    "count": count,
                    "first": first,
                })
                if handle is not None:
                    dispatch_targets.append({
                        "handle": handle,
                        "snapshot": copy.deepcopy(first),
                    })
            except Exception as exc:
                raise RuntimeError(
                    "browser approval target is unavailable or ambiguous"
                ) from exc
        page_url = str(self._page.url or "")
        try:
            parsed = urlparse(page_url)
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            port = parsed.port
            netloc = f"{host}:{port}" if port is not None else host
            safe_page = parsed._replace(
                netloc=netloc, params="", query="", fragment="",
            ).geturl()
        except ValueError:
            safe_page = "[invalid URL]"
        label = ""
        if targets:
            first_target = targets[0].get("first") or {}
            if isinstance(first_target, dict):
                label = str(
                    first_target.get("ariaLabel")
                    or first_target.get("text")
                    or first_target.get("name")
                    or first_target.get("id")
                    or first_target.get("role")
                    or first_target.get("tag")
                    or ""
                )
        if not label:
            try:
                label = str(self._page.title() or "")
            except Exception:
                label = ""
        try:
            from ..safety.secret_detector import redact

            target_summary, _matches = redact(
                " ".join(f"{label[:160]} at {safe_page[:240]}".split())
            )
        except Exception:
            target_summary = "current browser target (details unavailable)"
        context = {
            # This value is consumed only as input to the card's target digest;
            # it is never rendered or persisted in clear text.
            "page_url": page_url,
            "page_instance_sha256": digest(id(self._page)),
            "browser_context_instance_sha256": digest(id(self._context)),
            "credential_version_sha256": digest(state),
            "target_state_sha256": digest(targets),
            "target_summary": target_summary[:400],
        }
        self._approval_dispatch = {
            "action": action,
            "parameters_sha256": digest(supplied),
            "page_instance_sha256": digest(id(self._page)),
            "context_instance_sha256": digest(id(self._context)),
            "targets": dispatch_targets,
        }
        return context

    def dispatch_approved(self, action, args, timeout, allow_hosts) -> str:
        """Validate pinned DOM handles and actuate in one page task.

        A same-selector replacement cannot inherit approval: the final context
        capture pins the exact ElementHandle, and the page task validates every
        pinned element before applying any mutation.
        """
        from ..approval_cards import digest

        ticket = self._approval_dispatch
        self._approval_dispatch = None
        supplied = dict(args or {})
        if (
            not isinstance(ticket, dict)
            or ticket.get("action") != action
            or ticket.get("parameters_sha256") != digest(supplied)
            or ticket.get("page_instance_sha256") != digest(id(self._page))
            or ticket.get("context_instance_sha256") != digest(id(self._context))
        ):
            return "ERROR: browser target dispatch ticket is stale; no action was sent"
        targets = ticket.get("targets") or []
        if action not in {"click", "type", "fill_form", "press"}:
            return _dispatch_browser_action(
                action, self, self._page, supplied, timeout, allow_hosts,
            )
        expected_count = 1 if action in {"click", "type", "press"} else len(
            supplied.get("fields") or {}
        )
        if len(targets) != expected_count or not targets:
            return "ERROR: browser target could not be pinned; no action was sent"
        values = []
        if action == "type":
            values = [str(supplied.get("text") or "")]
        elif action == "fill_form":
            values = [str(value) for value in (supplied.get("fields") or {}).values()]
        payload = {
            "action": action,
            "elements": [target["handle"] for target in targets],
            "expected": [target["snapshot"] for target in targets],
            "values": values,
            "key": str(supplied.get("text") or ""),
        }
        result = self._page.evaluate("""payload => {
          function snapshot(element) {
            let activationContextWithinLimit = true;
            const bounded = value => {
              const text = String(value == null ? '' : value);
              if (text.length > 4096) activationContextWithinLimit = false;
              return text.slice(0, 4096);
            };
            const attribute = (node, name) => node.hasAttribute(name)
              ? bounded(node.getAttribute(name)) : null;
            const rect = element.getBoundingClientRect();
            const style = window.getComputedStyle(element);
            const cssVisible = style.display !== 'none' &&
              style.visibility !== 'hidden' && style.visibility !== 'collapse' &&
              Number.parseFloat(style.opacity || '1') > 0;
            const checkVisible = typeof element.checkVisibility !== 'function' ||
              element.checkVisibility({checkOpacity: true, checkVisibilityCSS: true,
                contentVisibilityAuto: true});
            const inViewport = rect.bottom > 0 && rect.right > 0 &&
              rect.top < window.innerHeight && rect.left < window.innerWidth;
            const form = element.form || null;
            const submitter = form && /^(BUTTON|INPUT)$/.test(element.tagName);
            return {tag: element.tagName, id: element.id || '',
              name: element.getAttribute('name') || '',
              role: element.getAttribute('role') || '',
              type: element.getAttribute('type') || '',
              ariaLabel: element.getAttribute('aria-label') || '',
              text: String(element.innerText || element.value || '').slice(0, 1000),
              disabled: Boolean(element.disabled || element.getAttribute('aria-disabled') === 'true'),
              readOnly: Boolean(element.readOnly || element.getAttribute('aria-readonly') === 'true'),
              visible: Boolean(cssVisible && checkVisible), inViewport: Boolean(inViewport),
              href: attribute(element, 'href'),
              resolvedHref: element.hasAttribute('href')
                ? bounded(element.href) : null,
              formAttribute: attribute(element, 'form'),
              owningForm: form ? {id: bounded(form.id),
                name: bounded(form.getAttribute('name')),
                actionAttribute: attribute(form, 'action'),
                resolvedAction: bounded(form.action), method: bounded(form.method),
                enctype: bounded(form.enctype), target: bounded(form.target),
                noValidate: Boolean(form.noValidate)} : null,
              submitterOverrides: submitter ? {
                actionAttribute: attribute(element, 'formaction'),
                resolvedAction: bounded(element.formAction),
                methodAttribute: attribute(element, 'formmethod'),
                resolvedMethod: bounded(element.formMethod),
                enctypeAttribute: attribute(element, 'formenctype'),
                resolvedEnctype: bounded(element.formEnctype),
                targetAttribute: attribute(element, 'formtarget'),
                resolvedTarget: bounded(element.formTarget),
                noValidateAttribute: element.hasAttribute('formnovalidate'),
                noValidate: Boolean(element.formNoValidate)} : null,
              inlineHandler: String(element.onclick || '').slice(0, 4000),
              rect: [rect.x, rect.y, rect.width, rect.height].map(Math.round),
              activationContextWithinLimit};
          }
          const elements = payload.elements || [];
          if (!elements.length || elements.length !== payload.expected.length)
            return 'stale';
          for (let index = 0; index < elements.length; index += 1) {
            const element = elements[index];
            if (!element || !element.isConnected ||
                JSON.stringify(snapshot(element)) !== JSON.stringify(payload.expected[index]))
              return 'stale';
          }
          function fill(element, value) {
            element.focus();
            const prototype = element instanceof HTMLTextAreaElement
              ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
            const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
            if (!descriptor || typeof descriptor.set !== 'function') return false;
            descriptor.set.call(element, value);
            element.dispatchEvent(new InputEvent('input', {bubbles: true,
              inputType: 'insertText', data: value}));
            element.dispatchEvent(new Event('change', {bubbles: true}));
            return true;
          }
          if (payload.action === 'click') elements[0].click();
          else if (payload.action === 'type') {
            if (!fill(elements[0], payload.values[0])) return 'unsupported';
          } else if (payload.action === 'fill_form') {
            for (let index = 0; index < elements.length; index += 1)
              if (!fill(elements[index], payload.values[index])) return 'unsupported';
          } else if (payload.action === 'press') {
            const target = elements[0]; const key = payload.key;
            target.focus();
            const down = new KeyboardEvent('keydown', {key, bubbles: true, cancelable: true});
            const allowed = target.dispatchEvent(down);
            target.dispatchEvent(new KeyboardEvent('keyup', {key, bubbles: true}));
            if (allowed && /^(Enter|Return|Space| )$/i.test(key)) {
              if (/^(BUTTON|A)$/.test(target.tagName)) target.click();
              else if (/^(Enter|Return)$/i.test(key) && target.form)
                target.form.requestSubmit();
            }
          }
          return 'dispatched';
        }""", payload)
        if result == "stale":
            return "ERROR: browser target changed at dispatch; observe and review it again"
        if result != "dispatched":
            return "ERROR: browser target does not support atomic dispatch; no action was sent"
        denial = _deny_and_close_current_page(self._page, allow_hosts)
        if denial is not None:
            return denial
        if action == "click":
            return f"clicked {_redact_browser_text(supplied['selector'])!r} on {_redact_browser_text(self._page.url)}"
        if action == "type":
            return f"typed {len(values[0])} chars into {_redact_browser_text(supplied['selector'])!r}"
        if action == "fill_form":
            return f"filled {len(values)}/{len(values)} field(s)"
        return f"pressed {_redact_browser_text(supplied.get('text') or '')}"

    def save_state(self) -> bool:
        """Persist cookies + localStorage to disk. Returns True if written."""
        with self._lock:
            if self._context is None or not self._allow_persist:
                return False
            p = _state_path()
            try:
                if p.parent.exists():
                    require_private_directory(p.parent)
                else:
                    ensure_private_directory(p.parent)
                # Ask Playwright for the in-memory representation and publish
                # it ourselves.  Passing a pathname to Playwright would create
                # cookies/localStorage with inherited ACLs before we could
                # protect the file (and chmod is not a DACL boundary on Windows).
                state = self._context.storage_state()
                atomic_write_text(
                    p,
                    json.dumps(state, separators=(",", ":")),
                    encoding="utf-8",
                )
                return True
            except Exception as e:
                log.warning("browser save_state: %s", _redact_browser_text(e))
                return False

    def close(self):
        with self._lock:
            for closer in (self._context, self._browser, self._playwright, self._egress_proxy):
                if closer is None:
                    continue
                try:
                    if closer is self._playwright:
                        closer.stop()
                    else:
                        closer.close()
                except Exception as e:
                    log.warning(
                        "browser close: %s: %s",
                        type(closer).__name__,
                        _redact_browser_text(e),
                    )
            self._page = self._context = self._browser = self._playwright = None
            self._egress_proxy = None


_BrowserScope = tuple[str | None, str | None, int | None]
_sessions: dict[_BrowserScope, _BrowserSession] = {}
_workers: dict[_BrowserScope, ThreadPoolExecutor] = {}
_closing: set[_BrowserScope] = set()
_session_lock = threading.Lock()


def _session_scope() -> _BrowserScope:
    from ..connections import current_principal
    from ..logging_config import current_goal_id
    from ..paths import current_tenant_id_strict

    return current_tenant_id_strict(), current_principal(), current_goal_id()


def _get_session() -> _BrowserSession:
    scope = _session_scope()
    with _session_lock:
        if scope in _closing:
            raise RuntimeError("browser session is closing")
        if scope not in _sessions:
            _sessions[scope] = _BrowserSession()
        return _sessions[scope]


def _close_scope(scope: _BrowserScope) -> None:
    with _session_lock:
        session = _sessions.pop(scope, None)
    try:
        if session is not None:
            try:
                session.save_state()
            finally:
                session.close()
    finally:
        from .aria_navigate import _clear_scope

        _clear_scope(scope)


def close_browser() -> None:
    """Tear down only the caller's browser session. Idempotent."""
    _close_scope(_session_scope())


async def run_on_browser_worker(fn: Callable[[dict[str, Any]], str], args: dict[str, Any]) -> str:
    """Keep sync Playwright and its page on one thread for this customer goal."""
    scope = _session_scope()
    with _session_lock:
        if scope in _closing:
            return "ERROR: browser session is closing; no action was sent"
        worker = _workers.get(scope)
        if worker is None:
            worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="lightwork-browser")
            _workers[scope] = worker
    context = contextvars.copy_context()
    return await asyncio.get_running_loop().run_in_executor(worker, context.run, fn, args)


async def close_goal_browsers(goal_id: int) -> None:
    """Close each principal's browser on its Playwright worker at goal end."""
    tenant = _session_scope()[0]
    with _session_lock:
        scopes = [scope for scope in _sessions.keys() | _workers.keys()
                  if scope[0] == tenant and scope[2] == goal_id]
        _closing.update(scopes)
    try:
        for scope in scopes:
            with _session_lock:
                worker = _workers.get(scope)
            if worker is None:
                _close_scope(scope)
            else:
                await asyncio.get_running_loop().run_in_executor(worker, _close_scope, scope)
                with _session_lock:
                    _workers.pop(scope, None)
                worker.shutdown(wait=False)
    finally:
        with _session_lock:
            _closing.difference_update(scopes)


def _save_on_exit() -> None:
    with _session_lock:
        sessions = tuple(_sessions.values())
        _sessions.clear()
    for session in sessions:
        try:
            session.save_state()
            session.close()
        except Exception:
            pass


atexit.register(_save_on_exit)


_SAFE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _capability_denied(host: str) -> str:
    return (
        "⚠ DENIED by capability policy: browser is not granted "
        f"host {host!r}. The browser session was closed."
    )


def _browser_host_denial(url: str, allow_hosts: tuple[str, ...]) -> str | None:
    """Return a denial string if ``url`` has a host outside ``allow_hosts``."""
    if not allow_hosts:
        return None
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except ValueError:
        return None
    if not host or any(fnmatch(host, pat) for pat in allow_hosts):
        return None
    return _capability_denied(host)


def _egress_denial(url: str) -> str | None:
    """Enterprise-mode + per-tenant egress checks for a browser destination.

    Mirrors http_fetch._preflight_fetch's enterprise/tenant checks: before
    this, the browser tool was reachable from enterprise mode / a restrictive
    [egress] or [tenancy.egress.<t>] plane with no check at all -- every other
    outbound-request tool (http_fetch, websocket, connectors) gates on these
    two, but a prompt-injected page could still make the *browser* reach
    anything the process itself could.
    """
    from ..enterprise import enterprise_egress_denial
    deny = enterprise_egress_denial(url, tool="browser")
    if deny:
        return deny
    try:
        from ..tenant.egress import egress_allowed
        host = (urlparse(url).hostname or "").strip().lower()
        if host and not egress_allowed("browser", host):
            return (f"egress policy blocks browser from reaching {host!r} "
                    "(see [egress] / [sandbox.tool.browser]).")
    except Exception:  # pragma: no cover -- policy never breaks a navigation
        pass
    return None


def _deny_and_close_current_page(page: Any, allow_hosts: tuple[str, ...]) -> str | None:
    url = getattr(page, "url", "") or ""
    # SSRF re-check on the URL we ACTUALLY landed on. page.goto / click / back
    # follow 3xx redirects transparently, so the front-door _is_safe_browser_url
    # check on the *requested* URL isn't enough -- a redirect to
    # http://169.254.169.254/ or another internal host would otherwise be
    # readable via screenshot / extract_*. If the current page is an http(s) URL
    # on a non-public host, close the session so nothing can read it.
    if url and _SAFE_URL_RE.match(url) and not _is_safe_browser_url(url):
        close_browser()
        host = (urlparse(url).hostname or "").strip().lower()
        return (
            f"⚠ DENIED: navigation landed on a private/internal host {host!r} "
            "(redirect to a non-public address); the browser session was closed."
        )
    if url and _SAFE_URL_RE.match(url):
        denial = _egress_denial(url)
        if denial is not None:
            close_browser()
            return f"⚠ DENIED: {denial} The browser session was closed."
    denial = _browser_host_denial(url, allow_hosts)
    if denial is None:
        return None
    close_browser()
    return denial

def _is_safe_browser_url(url: str) -> bool:
    if not _SAFE_URL_RE.match(url):
        return False

    host = (urlparse(url).hostname or "").strip().lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return False

    # Resolve the host (via is_blocked_host -> getaddrinfo) rather than
    # only testing a literal ipaddress.ip_address(host). The literal-only
    # check let decimal (2130706433) and hex (0x7f000001) encodings of
    # 127.0.0.1 -- which raise ValueError but resolve to loopback -- fall
    # through as "allowed", an SSRF bypass that the sibling http_fetch
    # guard already closes. Reuse it so both guards (and the
    # MAVERICK_FETCH_ALLOW_PRIVATE escape hatch) stay consistent.
    from .http_fetch import is_blocked_host

    return not is_blocked_host(host)


def _route_guard(route: Any, request: Any) -> None:
    """Playwright request interceptor: abort any http(s) request -- main
    frame OR routed subresource (image, script, XHR/fetch, iframe, popup) --
    whose host fails the SSRF/enterprise/tenant checks. Service workers and
    WebSockets may bypass this callback; the connection proxy independently
    enforces public IP addresses for their TCP traffic.

    Non-http(s) schemes (data:, blob:, about:, chrome-error:, ...) are not
    egress and are waved through -- these are same-document resource loads
    a page uses constantly (inline images, blob downloads) that have no
    host to check.
    """
    try:
        parsed = urlparse(request.url)
    except ValueError:
        route.abort()
        return
    if parsed.scheme not in ("http", "https"):
        route.continue_()
        return
    host = (parsed.hostname or "").strip().lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        route.abort()
        return
    from .http_fetch import is_blocked_host
    if is_blocked_host(host):
        route.abort()
        return
    try:
        from ..enterprise import egress_permitted
        if not egress_permitted(request.url):
            route.abort()
            return
    except Exception:  # pragma: no cover -- policy never breaks a request
        pass
    try:
        from ..tenant.egress import egress_allowed
        if not egress_allowed("browser", host):
            route.abort()
            return
    except Exception:  # pragma: no cover -- policy never breaks a request
        pass
    route.continue_()


def _browser_navigate(session, page, args, timeout, allow_hosts) -> str:
    url = args.get("url") or ""
    if not _is_safe_browser_url(url):
        return (
            "ERROR: URL must be http(s) and must not target localhost or "
            f"non-public IP ranges; got {_redact_browser_text(url)!r}"
        )
    # Enterprise/tenant egress checks on the REQUESTED url, before any
    # request is made -- so a denied destination can't leak via DNS, TLS
    # SNI, or redirects before the denial is returned (same rationale as
    # http_fetch._preflight_fetch). _deny_and_close_current_page below
    # re-runs this on the url actually landed on, in case of a redirect.
    denial = _egress_denial(url)
    if denial is not None:
        return f"ERROR: {denial}"
    log.info("browser.navigate %s", _redact_browser_text(url))
    page.goto(url, timeout=timeout, wait_until="domcontentloaded")
    denial = _deny_and_close_current_page(page, allow_hosts)
    if denial is not None:
        return denial
    session.save_state()  # checkpoint cookies after each navigation
    return f"navigated to {_redact_browser_text(page.url)} (status: loaded)"


def _browser_go_back(page, args, timeout, allow_hosts) -> str:
    page.go_back(timeout=timeout)
    denial = _deny_and_close_current_page(page, allow_hosts)
    if denial is not None:
        return denial
    return f"back -> {_redact_browser_text(page.url)}"


def _browser_go_forward(page, args, timeout, allow_hosts) -> str:
    page.go_forward(timeout=timeout)
    denial = _deny_and_close_current_page(page, allow_hosts)
    if denial is not None:
        return denial
    return f"forward -> {_redact_browser_text(page.url)}"


def _browser_click(page, args, timeout, allow_hosts) -> str:
    selector = args.get("selector")
    if not selector:
        return "ERROR: click requires selector"
    safe_selector = _redact_browser_text(selector)
    log.info("browser.click %s", safe_selector)
    page.click(selector, timeout=timeout)
    denial = _deny_and_close_current_page(page, allow_hosts)
    if denial is not None:
        return denial
    return (
        f"clicked {safe_selector!r} on {_redact_browser_text(page.url)}"
    )


def _browser_type(page, args, timeout) -> str:
    selector = args.get("selector")
    text = args.get("text") or ""
    if not selector:
        return "ERROR: type requires selector"
    safe_selector = _redact_browser_text(selector)
    log.info("browser.type len=%d into %s", len(text), safe_selector)
    page.fill(selector, text, timeout=timeout)
    return f"typed {len(text)} chars into {safe_selector!r}"


def _fill_form_input_error(args: dict[str, Any]) -> str | None:
    """Size bounds for fill_form, checked before approval and dispatch.

    The approved path fills every field in one page task, so these bounds must
    hold there too, not only in the per-field ``_browser_fill_form`` loop.
    """
    fields = args.get("fields")
    if not isinstance(fields, dict) or not fields:
        return "ERROR: fill_form requires a non-empty 'fields' object {selector: value}"
    if len(fields) > _MAX_FILL_FORM_FIELDS:
        return f"ERROR: fill_form supports at most {_MAX_FILL_FORM_FIELDS} fields"
    for selector, value in fields.items():
        if len(str(selector)) > _MAX_FILL_FORM_SELECTOR_LENGTH:
            return (f"ERROR: fill_form selectors are limited to "
                    f"{_MAX_FILL_FORM_SELECTOR_LENGTH} characters")
        if len(str(value)) > _MAX_FILL_FORM_VALUE_LENGTH:
            return (f"ERROR: fill_form values are limited to "
                    f"{_MAX_FILL_FORM_VALUE_LENGTH} characters")
    return None


def _browser_fill_form(page, args, timeout) -> str:
    fields = args.get("fields")
    if not isinstance(fields, dict) or not fields:
        return "ERROR: fill_form requires a non-empty 'fields' object {selector: value}"
    if len(fields) > _MAX_FILL_FORM_FIELDS:
        return f"ERROR: fill_form supports at most {_MAX_FILL_FORM_FIELDS} fields"

    filled: list[str] = []
    errors: list[str] = []
    field_timeout = min(timeout, _MAX_FILL_FORM_FIELD_TIMEOUT_MS)
    total_timeout = min(timeout, _MAX_FILL_FORM_TOTAL_TIMEOUT_MS)
    deadline = _monotonic() + (total_timeout / 1000)

    for selector, value in fields.items():
        selector = str(selector)
        value = str(value)
        safe_selector = _redact_browser_text(selector)
        if len(selector) > _MAX_FILL_FORM_SELECTOR_LENGTH:
            errors.append(
                f"{_redact_browser_text(selector[:80])}: selector too long"
            )
            continue
        if len(value) > _MAX_FILL_FORM_VALUE_LENGTH:
            errors.append(f"{safe_selector}: value too long")
            continue

        remaining_ms = int((deadline - _monotonic()) * 1000)
        if remaining_ms <= 0:
            errors.append("batch timeout")
            break
        try:
            page.fill(selector, value, timeout=min(field_timeout, remaining_ms))
            filled.append(safe_selector)
        except Exception as e:
            errors.append(f"{safe_selector}: {type(e).__name__}")
    log.info("browser.fill_form filled=%d errors=%d", len(filled), len(errors))
    summary = f"filled {len(filled)}/{len(fields)} field(s)"
    if errors:
        summary += "; failed: " + ", ".join(errors[:10])
    return summary


def _browser_press(page, args, timeout, allow_hosts) -> str:
    text = args.get("text") or ""
    selector = args.get("selector")
    if not text:
        return "ERROR: press requires text (key name, e.g. 'Enter')"
    if selector:
        page.press(selector, text, timeout=timeout)
    else:
        page.keyboard.press(text)
    denial = _deny_and_close_current_page(page, allow_hosts)
    if denial is not None:
        return denial
    return f"pressed {_redact_browser_text(text)!r}"


def _browser_scroll(page, args) -> str:
    dy = int(args.get("delta_y") or 400)
    page.evaluate(f"window.scrollBy(0, {dy})")
    return f"scrolled by {dy}"


def _browser_screenshot(page) -> str:
    png_bytes = page.screenshot(full_page=False)
    b64 = base64.b64encode(png_bytes).decode("ascii")
    log.info(
        "browser.screenshot len=%d url=%s",
        len(b64),
        _redact_browser_text(page.url),
    )
    return f"<screenshot mime=image/png base64>{b64}</screenshot>"


def _browser_extract_text(page, args) -> str:
    selector = args.get("selector")
    if selector:
        els = page.query_selector_all(selector)
        text = "\n".join((el.inner_text() or "").strip() for el in els)[:50_000]
    else:
        # Whole-page text fallback.
        body = page.query_selector("body")
        text = (body.inner_text() or "").strip()[:50_000] if body else ""
    return _scanned_page_text(text)


def _scanned_page_text(text: str) -> str:
    """Page-derived text, annotated by the injection scan, then redacted."""
    cleaned, warning = _scan_fetched(text)
    return _redact_browser_text(warning + cleaned)


def _browser_extract_html(page, args) -> str:
    selector = args.get("selector")
    if selector:
        el = page.query_selector(selector)
        return _scanned_page_text((el.inner_html() if el else "")[:100_000])
    return _scanned_page_text(page.content()[:100_000])


def _browser_find_text(page, args) -> str:
    text = args.get("text") or ""
    if not text:
        return "ERROR: find_text requires text"
    loc = page.get_by_text(text, exact=False)
    count = loc.count()
    if count == 0:
        return (
            f"text {_redact_browser_text(text)!r} not found on "
            f"{_redact_browser_text(page.url)}"
        )
    # Return location summary for the first match.
    try:
        box = loc.first.bounding_box()
        if box:
            return (
                f"found {count} match(es); first at "
                f"({box['x']:.0f}, {box['y']:.0f}, "
                f"{box['width']:.0f}x{box['height']:.0f})"
            )
    except Exception:
        pass
    return f"found {count} match(es) for {_redact_browser_text(text)!r}"


def _browser_wait_for(page, args, timeout) -> str:
    selector = args.get("selector")
    if not selector:
        return "ERROR: wait_for requires selector"
    page.wait_for_selector(selector, timeout=timeout)
    return f"selector {_redact_browser_text(selector)!r} appeared"


def _browser_list_links(page) -> str:
    anchors = page.query_selector_all("a[href]")
    links = []
    for a in anchors[:100]:
        href = a.get_attribute("href") or ""
        text = (a.inner_text() or "").strip()[:80]
        links.append(f"{text!r} -> {href}")
    return (
        _scanned_page_text("\n".join(links))
        if links
        else "no links on page"
    )


def _observe_selector_hint(el: Any) -> str | None:
    """A best-effort, human-usable selector for an interactive element.

    Prefers a stable handle (id, name, data-testid) and falls back to a tag +
    accessible-attribute hint. Returns ``None`` if nothing useful is found.
    Never raises -- a bad element just contributes no hint.
    """
    try:
        for attr in ("id", "data-testid", "name"):
            val = el.get_attribute(attr)
            if val:
                if attr == "id":
                    return f"#{val}"
                return f"[{attr}={val!r}]"
        tag = (el.evaluate("e => e.tagName") or "").lower()
        for attr in ("aria-label", "placeholder", "type", "href"):
            val = el.get_attribute(attr)
            if val:
                return f"{tag or '*'}[{attr}={val!r}]"
        return tag or None
    except Exception:
        return None


def _browser_observe(page) -> str:
    """READ-ONLY semantic snapshot of the current page.

    Returns title + url, Playwright's accessibility tree, and a BOUNDED list of
    interactive elements (role, accessible name, selector hint) so the agent can
    act on meaning rather than pixels. Output is capped so it never floods the
    context. Read-only: never mutates the page and is never gated.
    """
    try:
        title = page.title()
    except Exception:
        title = ""
    url = getattr(page, "url", "") or ""

    # Accessibility tree (semantic structure). Bound its serialized size.
    try:
        ax = page.accessibility.snapshot()
    except Exception as e:
        ax = None
        log.debug(
            "browser.observe accessibility snapshot failed: %s",
            _redact_browser_text(e),
        )
    try:
        ax_json = json.dumps(ax, ensure_ascii=False, default=str) if ax else ""
    except (TypeError, ValueError):
        ax_json = ""
    ax_truncated = len(ax_json) > _MAX_OBSERVE_AXTREE_CHARS
    if ax_truncated:
        ax_json = ax_json[:_MAX_OBSERVE_AXTREE_CHARS]

    # Bounded list of interactive elements with role + accessible name + hint.
    elements: list[dict[str, Any]] = []
    try:
        handles = page.query_selector_all(
            "a[href], button, input, select, textarea, "
            "[role=button], [role=link], [role=textbox], [contenteditable=true]",
        )
    except Exception as e:
        handles = []
        log.debug(
            "browser.observe element query failed: %s",
            _redact_browser_text(e),
        )
    for el in handles:
        if len(elements) >= _MAX_OBSERVE_ELEMENTS:
            break
        try:
            role = el.get_attribute("role") or (el.evaluate("e => e.tagName") or "").lower()
            name = (
                el.get_attribute("aria-label")
                or el.get_attribute("placeholder")
                or (el.inner_text() or "").strip()
                or el.get_attribute("value")
                or el.get_attribute("name")
                or ""
            )
        except Exception:
            continue
        name = " ".join(str(name).split())[:_MAX_OBSERVE_NAME_LENGTH]
        entry: dict[str, Any] = {"role": role or "?", "name": name}
        hint = _observe_selector_hint(el)
        if hint:
            entry["selector"] = hint
        elements.append(entry)

    log.info(
        "browser.observe url=%s elements=%d",
        _redact_browser_text(url),
        len(elements),
    )
    snapshot = {
        "title": title,
        "url": url,
        "interactive_elements": elements,
        "interactive_truncated": len(handles) > len(elements),
        "accessibility_tree": ax_json,
        "accessibility_truncated": ax_truncated,
    }
    return _scanned_page_text(json.dumps(snapshot, ensure_ascii=False, default=str))


def _browser_save_session(session) -> str:
    ok = session.save_state()
    return "session saved" if ok else "session not saved (persistence disabled or no active context)"


def _parse_allow_hosts(args: dict[str, Any]) -> tuple[str, ...]:
    raw_allow_hosts = args.get("_capability_allow_hosts")
    return (
        tuple(str(pat).lower() for pat in raw_allow_hosts)
        if isinstance(raw_allow_hosts, (list, tuple, set, frozenset))
        else ()
    )


def _dispatch_browser_action(
    action: str, session, page, args, timeout, allow_hosts,
) -> str:
    """Run a single browser action against the live page. Behavior identical
    to the prior inline if/elif chain (same order, same returns)."""
    if action == "navigate":
        return _browser_navigate(session, page, args, timeout, allow_hosts)
    if action == "current_url":
        return _redact_browser_text(page.url)
    if action == "go_back":
        return _browser_go_back(page, args, timeout, allow_hosts)
    if action == "go_forward":
        return _browser_go_forward(page, args, timeout, allow_hosts)
    if action == "click":
        return _browser_click(page, args, timeout, allow_hosts)
    if action == "type":
        return _browser_type(page, args, timeout)
    if action == "fill_form":
        return _browser_fill_form(page, args, timeout)
    if action == "press":
        return _browser_press(page, args, timeout, allow_hosts)
    if action == "scroll":
        return _browser_scroll(page, args)
    if action == "screenshot":
        return _browser_screenshot(page)
    if action == "observe":
        return _browser_observe(page)
    if action == "extract_text":
        return _browser_extract_text(page, args)
    if action == "extract_html":
        return _browser_extract_html(page, args)
    if action == "find_text":
        return _browser_find_text(page, args)
    if action == "wait_for":
        return _browser_wait_for(page, args, timeout)
    if action == "list_links":
        return _browser_list_links(page)
    if action == "save_session":
        return _browser_save_session(session)
    if action == "close":
        close_browser()
        return "browser closed"
    return f"ERROR: unknown action {action!r}"


def _dispatch_approved_browser_action(
    action: str, session, page, args, timeout, allow_hosts,
) -> str:
    """Use the session's target-bound driver for DOM mutations.

    A selector lookup followed by a separate Playwright action has an
    unavoidable replacement window. Refuse that raw path when an exact action
    permit was required.
    """
    if action in {"click", "type", "fill_form", "press"}:
        dispatcher = getattr(session, "dispatch_approved", None)
        if not callable(dispatcher):
            return (
                "ERROR: browser target cannot be bound atomically; no action "
                "was sent; observe it and review again"
            )
        return dispatcher(action, args, timeout, allow_hosts)
    return _dispatch_browser_action(
        action, session, page, args, timeout, allow_hosts,
    )


def _browser_approval_context(session, page, action, args) -> dict[str, Any]:
    """Capture approval context while preserving legacy test-driver support.

    Selector-bound input must come from a session that can pin the exact DOM
    handles it will later dispatch to.  Navigation, history, viewport, and
    session-lifecycle actions have no DOM target, so a minimal page-instance
    context is sufficient for older or embedded drivers that do not expose the
    richer ``approval_context`` hook.
    """
    provider = getattr(session, "approval_context", None)
    if callable(provider):
        return provider(action, copy.deepcopy(args))
    if action in {"click", "type", "fill_form", "press"}:
        raise RuntimeError("target-bound browser driver is unavailable")

    from ..approval_cards import digest

    page_url = str(getattr(page, "url", "") or "")
    try:
        parsed = urlparse(page_url)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parsed.port
        netloc = f"{host}:{port}" if port is not None else host
        safe_page = parsed._replace(
            netloc=netloc, params="", query="", fragment="",
        ).geturl()
    except ValueError:
        safe_page = "[invalid URL]"
    return {
        "page_instance_sha256": digest(id(page)),
        "browser_session_instance_sha256": digest(id(session)),
        "credential_version_sha256": "not_available",
        "target_state_sha256": digest({
            "action": action,
            "page_url": page_url,
        }),
        "target_summary": _redact_browser_text(safe_page)[:400],
    }


def _run_browser_action(args: dict[str, Any]) -> str:
    # A tool invocation owns an immutable logical input.  Keep one private
    # snapshot for approval and dispatch so a caller or a context callback
    # cannot change the selector, URL, or typed value between validation and
    # the physical effect.
    try:
        args = copy.deepcopy(dict(args))
    except Exception:
        return "ERROR: browser action input could not be frozen; no action was sent"
    if os.environ.get("MAVERICK_BROWSER_DISABLE") == "1":
        return "ERROR: browser tool disabled by MAVERICK_BROWSER_DISABLE=1"
    action = args.get("action")
    if not action:
        return "ERROR: action is required"

    try:
        session = _get_session()
        page = session.page
    except ImportError as e:
        return f"ERROR: {e}"

    try:
        timeout = int(args.get("timeout_ms") or _DEFAULT_TIMEOUT_MS)
    except (TypeError, ValueError):
        return "ERROR: timeout_ms must be an integer number of milliseconds"
    timeout = max(1, min(timeout, _MAX_TIMEOUT_MS))
    allow_hosts = _parse_allow_hosts(args)
    if action == "fill_form" and (error := _fill_form_input_error(args)):
        return error

    if action != "navigate":
        denial = _deny_and_close_current_page(page, allow_hosts)
        if denial is not None:
            return denial

    # Per-action approval gate. Every navigation/session/actuation mutation
    # needs an exact human decision; silent auto approval and standing grants
    # are ineligible. Read actions (extract_*/screenshot/find_text/...) are not
    # gated.
    authorization = gate_browser_action(
        action,
        args,
        context_provider=lambda: _browser_approval_context(
            session, page, action, args,
        ),
    )
    if isinstance(authorization, str):
        return authorization

    def dispatch() -> str:
        try:
            if isinstance(authorization, ActionPermit):
                return consume_action_permit(
                    authorization,
                    effect=lambda: _dispatch_approved_browser_action(
                        action, session, page, args, timeout, allow_hosts,
                    ),
                )
            return _dispatch_browser_action(
                action, session, page, args, timeout, allow_hosts,
            )
        except Exception as exc:
            # Playwright often includes the selector or URL in its exception.
            # The action may already have reached the page, so tell the caller
            # to observe current state instead of presenting it as replay-safe.
            detail = _redact_browser_text(exc)
            return (
                f"ERROR: browser {action} could not be confirmed "
                f"({type(exc).__name__}: {detail}); observe current state "
                "before retrying"
            )

    if browser_action_risk(action, args) == "high":
        # Bracket a high-risk action with sealed before/after captures
        # (no-op unless screenshot sealing is configured).
        return seal_bracketed(
            lambda: base64.b64encode(page.screenshot(full_page=False)).decode("ascii"),
            dispatch,
            action=f"browser.{action}",
        )
    return dispatch()


def browser(*, managed: bool = False) -> Tool:
    """Factory: builds the browser tool."""
    async def managed_action(args: dict[str, Any]) -> str:
        return await run_on_browser_worker(_run_browser_action, args)

    return Tool(
        name="browser",
        description=(
            "Browse the web. navigate to a URL, then observe to get a compact "
            "semantic snapshot (title, url, accessibility tree, and interactive "
            "elements with roles/names/selectors) so you can act on meaning, not "
            "pixels -- prefer observe before clicking. find_text or use CSS "
            "selectors to interact (click, type, fill_form to batch-fill many "
            "inputs), extract_text or extract_html to read, screenshot to see, "
            "list_links to discover navigation. Use this for normal web tasks; "
            "use the 'computer' tool for non-DOM UIs."
        ),
        input_schema=_BROWSER_INPUT_SCHEMA,
        fn=managed_action if managed else _run_browser_action,
    )
