"""The egress lock, enforced where requests actually leave.

``enterprise.py`` provides an application-layer egress control. An earlier
version documented the mechanism as ``enterprise_egress_denial`` applied *"at
each tool's request"*. That parenthetical was the load-bearing false clause.
The check existed at **11** call sites; a census of production code found
**194 direct outbound HTTP call sites across 96 modules**, of which **87 had no
egress gate of any kind** -- including ``gmail_tool``,
``salesforce_tool``, ``slack_bot``, ``replicate_tool`` (a second third-party
inference API), and ``maverick_knowledge/embed.py``, which ships document text
to an embedding vendor.

The per-tool design could not have worked. It required every author of every
connector, forever, to remember an unenforced convention, and nothing failed
when they did not -- the test suite validated the policy *function* and a
handful of hand-picked wrappers, so it was structurally incapable of noticing a
bypass. Sixty connectors under ``tools/`` drifted out of coverage exactly that
way.

So the check moves to where requests are actually issued. Most direct callers
use ``httpx`` and one uses ``requests``; provider SDKs can use the compatible
``httpx2`` family internally. All three funnel every call -- module-level
``httpx.get``, a hand-built ``Client``, an SDK client, or a pooled ``Session``
-- through a one-request network seam. Wrapping those methods covers existing
connectors and provider SDK traffic, covers connectors not yet written, and
re-checks every followed redirect hop.

**This does not weaken SSRF pinning.** ``tools/_ssrf`` installs a custom
*transport*, which sits below the one-hop client method; the guard runs first
and the pinned transport still runs after. They compose.

**Default posture is unchanged.** ``egress_permitted`` returns True whenever
enterprise mode is off, so on a default install this is one predicate per
request and nothing else. It is not a general firewall: it is defense in depth
for supported Python HTTP paths. A hard no-egress boundary additionally
requires sandbox network isolation and host/OS/VPC firewall policy.

**What it still does not cover**, stated because an overclaim here is the
original defect: a tool that shells out to ``curl``, opens a raw socket, or
uses an HTTP library the guard does not wrap. ``sandbox/network_policy`` says
the same about itself -- there is no packet-level backend. The
``egress_contract`` CI gate enumerates every module that makes direct outbound
HTTP and fails when one uses a library outside the wrapped set, so that gap is
a recorded number rather than a discovery.
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Any

log = logging.getLogger(__name__)

#: HTTP client libraries this guard wraps. The egress_contract gate refuses a
#: production module that reaches the network through anything else.
COVERED_LIBRARIES = ("httpx", "httpx2", "requests", "urllib")

#: The two independently distributed HTTPX-compatible client families. Keep
#: this list aligned with ``_TARGETS`` and the egress-contract census.
_HTTPX_FAMILIES = ("httpx", "httpx2")

_installed = False
# A target can be reloaded while the guard is active.  Keep every class/module
# generation by direct object reference so teardown restores both the current
# methods and any older classes retained by callers across that reload.
_originals: dict[str, list[tuple[Any, str, Any, Any]]] = {}
_compatibility: dict[str, dict[str, Any]] = {}
_lifecycle_lock = threading.RLock()

_WRAPPER_TARGET = "__maverick_egress_guard_target__"
_WRAPPER_ORIGINAL = "__maverick_egress_guard_original__"
# A module reload creates a new ``_PatchOnImport`` class and resets ``_hook``,
# while the prior-generation finder remains in ``sys.meta_path``.  Mark finder
# instances with a stable string attribute so the reloaded module can discover
# and remove every generation instead of retaining only the newest reference.
_HOOK_MARKER = "__maverick_egress_guard_import_hook__"

#: Distinguishes "caller omitted timeout" from "caller passed None", which
#: urllib treats differently (None means no timeout; omitted means the global
#: default socket timeout).
_SENTINEL = object()


def _is_guard_wrapper(value: Any, target: str) -> bool:
    return getattr(value, _WRAPPER_TARGET, None) == target


def _recorded(owner: Any, attribute: str, wrapper: Any) -> bool:
    return any(
        saved_owner is owner
        and saved_attribute == attribute
        and saved_wrapper is wrapper
        for records in _originals.values()
        for saved_owner, saved_attribute, _, saved_wrapper in records
    )


def _replace_with_guard(
    target: str,
    owner: Any,
    attribute: str,
    wrapper: Any,
) -> None:
    """Replace one method and retain enough identity to undo every generation."""
    current = getattr(owner, attribute)
    if _is_guard_wrapper(current, target):
        # This can happen when a package reload re-exports a class from an
        # already-loaded submodule, or after egress_guard itself was reloaded.
        # Adopt the wrapper rather than stacking another policy check.
        if not _recorded(owner, attribute, current):
            original = getattr(current, _WRAPPER_ORIGINAL, current)
            _originals.setdefault(target, []).append(
                (owner, attribute, original, current)
            )
        return

    setattr(wrapper, _WRAPPER_TARGET, target)
    setattr(wrapper, _WRAPPER_ORIGINAL, current)
    records = _originals.setdefault(target, [])
    record = (owner, attribute, current, wrapper)
    records.append(record)
    try:
        setattr(owner, attribute, wrapper)
    except Exception:  # failure-policy: fail_closed -- roll back and re-raise
        # A metaclass can reject one half of a sync/async pair.  Remove this
        # record immediately; the caller's transaction restores earlier ones.
        try:
            if getattr(owner, attribute) is wrapper:
                setattr(owner, attribute, current)
        except Exception:  # failure-policy: fail_soft_with_audit -- restore logged
            log.exception(
                "egress guard: failed to restore rejected patch %r.%s",
                owner,
                attribute,
            )
        records.pop()
        if not records:
            _originals.pop(target, None)
        raise


def _restore_record(record: tuple[Any, str, Any, Any]) -> None:
    owner, attribute, original, wrapper = record
    try:
        current = getattr(owner, attribute)
    except Exception:  # failure-policy: best_effort -- owner already unavailable
        return
    if current is wrapper or _is_guard_wrapper(
        current,
        getattr(wrapper, _WRAPPER_TARGET, ""),
    ):
        try:
            setattr(owner, attribute, original)
        except Exception:  # failure-policy: fail_soft_with_audit -- restore logged
            log.exception(
                "egress guard: could not restore %r.%s",
                owner,
                attribute,
            )


def _record_lengths() -> dict[str, int]:
    return {target: len(records) for target, records in _originals.items()}


def _restore_since(snapshot: dict[str, int]) -> None:
    """Undo records added after ``snapshot``, newest assignment first."""
    for target in reversed(list(_originals)):
        records = _originals[target]
        keep = snapshot.get(target, 0)
        for record in reversed(records[keep:]):
            _restore_record(record)
        del records[keep:]
        if not records:
            _originals.pop(target, None)


def _denied(url: str) -> str | None:
    """Denial reason for an outbound URL, or None to allow.

    Resolved at request time rather than at install time: enterprise mode, the
    compliance floor, the allow-list, and the tenant egress plane are all live
    config, and a deployment that turns the boundary on must not have to
    restart to get it.

    Composes the per-tenant egress plane (:mod:`maverick.tenant.egress` --
    independent of enterprise mode, since a tenant boundary matters whether or
    not enterprise mode is on) with the enterprise allow-list: a request is
    admitted only when BOTH permit it. Before this, the tenant plane was
    consulted directly by exactly one tool (``http_fetch``) despite its own
    docstring claiming it applies to every tool -- hooking it in here, at the
    seam every httpx/requests/urllib call already funnels through, is what
    actually makes that claim true.
    """
    host = ""
    try:
        from .enterprise import _host_of
        host = _host_of(url)
    except Exception:  # failure-policy: fail_closed -- host policy is unavailable
        log.exception("egress guard: hostname parsing unavailable; refusing egress")
        return "egress policy could not be evaluated, so the boundary stays closed"
    tenant_denied = False
    try:
        from .enterprise import egress_permitted
        enterprise_ok = egress_permitted(url)
        from .tenant.egress import host_allowed
        tenant_denied = bool(host) and not host_allowed(host)
        if enterprise_ok and not tenant_denied:
            return None
    # failure-policy: fail_closed
    except Exception:
        log.exception("egress guard: policy unavailable; refusing egress to %r", url)
        return ("egress policy could not be evaluated, so the boundary stays "
                "closed")
    # Deliberate, narrow exception to the audit-refusal contract.
    #
    # That contract exists so "we could not record this action" never becomes
    # "we did it anyway". Here the action is being REFUSED either way -- the
    # caller gets EgressBlocked whether or not this write lands -- so the
    # concern the contract protects against cannot arise. Letting AuditRefused
    # propagate would only replace an accurate egress reason with a confusing
    # one: under enterprise mode with no off-host signing key, every blocked
    # request would surface as OffHostSigningRequiredError, and an operator
    # would go hunting for a signing problem instead of reading the allow-list.
    #
    # The refusal is logged at error level rather than dropped, because a
    # deployment that cannot record blocked exfiltration attempts has a real
    # problem -- just not one worth mistranslating this exception for.
    from .audit import EventKind
    from .audit.errors import AuditRefused
    from .audit.writer import audit_event
    try:
        audit_event(EventKind.EGRESS_BLOCKED, provider="http-client",
                    host=host or (url or "?"))
    except AuditRefused:
        log.error(
            "egress guard: blocked egress to %r but the audit subsystem "
            "refused to record it; the request is still refused",
            host or url)
    if tenant_denied:
        return (
            f"egress policy blocks this request to {host or url!r} "
            "(see [egress] / [tenancy.egress.<tenant>])."
        )
    return (
        f"enterprise mode: refusing egress to {host or url!r} -- not a local "
        "endpoint and not in [enterprise] allowed_hosts. The application "
        "egress boundary blocks this request."
    )


def _check(url: str) -> None:
    reason = _denied(url)
    if reason is None:
        return
    from .enterprise import EgressBlocked
    blocked = EgressBlocked(reason)
    # The constructor words its message for a model-provider refusal ("route
    # this role to a self-hosted model"); a blocked request says why instead.
    blocked.args = (reason,)
    raise blocked


def _is_network_transport(transport: Any) -> bool:
    """Whether a transport must pass the outbound policy check.

    An ASGI/WSGI/Mock transport hands the request to an in-process object: no
    socket opens, nothing crosses the host boundary, and there is nothing for
    an egress lock to prevent. Blocking those is a false positive with teeth --
    it refuses in-process ASGI calls under enterprise mode, which is how this
    was found (every TestClient request in the suite blocked on "testserver").

    The exemption is deliberately an exact-type allowlist. A custom
    ``BaseTransport`` can open a socket, shell out, or delegate elsewhere, so
    unknown transports -- including subclasses and wrappers around a mock --
    are treated as network-capable. Starlette's in-process TestClient transport
    is admitted only when its exact class object is available from the already
    imported module; a matching class name is not enough.

    A mock handler that itself makes a real request is checked when that request
    goes back through a guarded library.
    """
    transport_type = type(transport)
    for family in _HTTPX_FAMILIES:
        # Do not import either optional family here. The guard deliberately
        # preserves Maverick's cold-start contract, and the transport can only
        # have come from a family that is already loaded.
        module = sys.modules.get(family)
        if module is None:
            continue
        if any(
            transport_type is known_type
            for known_type in (
                getattr(module, "ASGITransport", None),
                getattr(module, "WSGITransport", None),
                getattr(module, "MockTransport", None),
            )
        ):
            return False

    starlette_testclient = sys.modules.get("starlette.testclient")
    if starlette_testclient is not None:
        test_transport = getattr(
            starlette_testclient,
            "_TestClientTransport",
            None,
        )
        if transport_type is test_transport:
            return False

    return True


def _reaches_the_network(client: Any, request: Any) -> bool:
    """Whether this request will actually leave the process."""
    try:
        transport = client._transport_for_url(request.url)
    except Exception:  # failure-policy: fail_closed -- assume it reaches network
        return True
    return _is_network_transport(transport)


def _httpx_degraded_check(request: Any, *, client_name: str) -> None:
    """Deny every HTTPX-family send when its per-hop guard cannot be installed.

    A public ``send`` wrapper cannot observe a redirect chain's later hops.
    Therefore, when HTTPX no longer exposes the one-hop seam, enterprise and
    compliance deployments must refuse the whole request rather than apply an
    incomplete first-URL check. Default deployments retain their existing
    behavior so an unsupported optional client version does not become a
    platform-wide outage outside the asserted data boundary.
    """
    try:
        from .enterprise import enterprise_enabled

        boundary_required = enterprise_enabled()
    except Exception:  # failure-policy: fail_closed -- require boundary
        boundary_required = True
    if not boundary_required:
        return

    url = str(getattr(request, "url", "") or "")
    host = url
    try:
        from .enterprise import _host_of

        host = _host_of(url) or url
    except Exception:  # failure-policy: best_effort -- diagnostic label only
        pass

    # Record the compatibility refusal when possible. Failure to write this
    # event never opens the data boundary; the request is refused below.
    try:
        from .audit import EventKind
        from .audit.writer import audit_event

        audit_event(
            EventKind.EGRESS_BLOCKED,
            provider=f"{client_name}-compatibility-fallback",
            host=host or "?",
        )
    except Exception:  # failure-policy: best_effort
        log.exception(
            "egress guard: could not audit degraded %s refusal for %r",
            client_name,
            host or url,
        )

    from .enterprise import EgressBlocked

    raise EgressBlocked(
        f"enterprise/compliance mode: installed {client_name} cannot be "
        "guarded at every redirect hop, so all sends through that client are "
        "refused until a compatible version is installed."
    )


def _patch_httpx_fail_closed(
    mod: Any,
    reason: str,
    *,
    client_name: str,
) -> bool:
    """Install the degraded public-send boundary; return whether it succeeded."""
    sync_owner = getattr(mod, "Client", None)
    async_owner = getattr(mod, "AsyncClient", None)
    sync_method = getattr(sync_owner, "send", None)
    async_method = getattr(async_owner, "send", None)
    if not callable(sync_method) or not callable(async_method):
        _compatibility[client_name] = {
            "compatible": False,
            "reason": f"{reason}; public send fallback is unavailable",
            "seam": "_send_single_request",
            "fail_closed_fallback": False,
        }
        return False

    sync_key = f"{client_name}.Client.send"
    async_key = f"{client_name}.AsyncClient.send"

    def _sync_send(self, request, *args, **kwargs):
        _httpx_degraded_check(request, client_name=client_name)
        return sync_method(self, request, *args, **kwargs)

    async def _async_send(self, request, *args, **kwargs):
        _httpx_degraded_check(request, client_name=client_name)
        return await async_method(self, request, *args, **kwargs)

    _replace_with_guard(sync_key, sync_owner, "send", _sync_send)
    _replace_with_guard(async_key, async_owner, "send", _async_send)
    _compatibility[client_name] = {
        "compatible": False,
        "reason": reason,
        "seam": "_send_single_request",
        "fallback_seam": "send",
        "fail_closed_fallback": True,
    }
    return True


def _patch_httpx_family(mod: Any, *, client_name: str) -> None:
    """Wrap an HTTPX-compatible family at the one-network-request seam.

    ``Client.send`` owns a complete redirect chain, so wrapping it checks only
    the first URL. ``_send_single_request`` is entered once for every actual
    network hop, after HTTPX has built the next redirect request and selected
    its stream type. Wrapping the sync and async implementations independently
    preserves their respective byte-stream contracts while re-evaluating live
    policy (including the new URL's host) on every hop.

    In-process ASGI/WSGI/TestClient and mock transports are still exempt through
    :func:`_reaches_the_network`; a request that opens no socket is not egress.
    """
    sync_owner = getattr(mod, "Client", None)
    async_owner = getattr(mod, "AsyncClient", None)
    sync_method = getattr(sync_owner, "_send_single_request", None)
    async_method = getattr(async_owner, "_send_single_request", None)
    if not callable(sync_method) or not callable(async_method):
        reason = (
            f"installed {client_name} does not expose compatible sync and async "
            "_send_single_request seams"
        )
        if _patch_httpx_fail_closed(
            mod,
            reason,
            client_name=client_name,
        ):
            return
        raise RuntimeError(_compatibility[client_name]["reason"])

    async_key = f"{client_name}.AsyncClient._send_single_request"
    sync_key = f"{client_name}.Client._send_single_request"
    def _sync_send_single_request(self, request, *args, **kwargs):
        if _reaches_the_network(self, request):
            _check(str(request.url))
        return sync_method(self, request, *args, **kwargs)

    async def _async_send_single_request(self, request, *args, **kwargs):
        if _reaches_the_network(self, request):
            _check(str(request.url))
        return await async_method(self, request, *args, **kwargs)

    _replace_with_guard(
        sync_key,
        sync_owner,
        "_send_single_request",
        _sync_send_single_request,
    )
    _replace_with_guard(
        async_key,
        async_owner,
        "_send_single_request",
        _async_send_single_request,
    )
    _compatibility[client_name] = {
        "compatible": True,
        "reason": "",
        "seam": "_send_single_request",
    }


def _patch_httpx(mod: Any) -> None:
    """Wrap the original ``httpx`` distribution."""
    _patch_httpx_family(mod, client_name="httpx")


def _patch_httpx2(mod: Any) -> None:
    """Wrap the provider-SDK ``httpx2`` distribution."""
    _patch_httpx_family(mod, client_name="httpx2")


def _patch_requests(mod: Any) -> None:
    original_send = mod.Session.send
    target = "requests.Session.send"

    def _send(self, request, **kwargs):
        _check(str(getattr(request, "url", "")))
        return original_send(self, request, **kwargs)

    _replace_with_guard(target, mod.Session, "send", _send)


def _patch_urllib(mod: Any) -> None:
    """Nine production modules reach the network through urllib.

    ``urlopen`` and ``build_opener().open()`` both funnel through
    ``OpenerDirector.open``, so one wrapper covers every form.
    """
    original_open = mod.OpenerDirector.open
    target = "urllib.OpenerDirector.open"

    def _open(self, fullurl, data=None, timeout=_SENTINEL):
        # `fullurl` is a str or a Request; Request.full_url holds the target.
        # A str is parsed the way `open` itself will (it unwraps `URL:...`
        # and `<...>`), so the guard checks the host the request reaches.
        url = getattr(fullurl, "full_url", None)
        if url is None and isinstance(fullurl, str):
            try:
                url = mod.Request(fullurl).full_url
            except ValueError:
                url = fullurl
        _check(str(url or ""))
        if timeout is _SENTINEL:
            return original_open(self, fullurl, data)
        return original_open(self, fullurl, data, timeout)

    _replace_with_guard(target, mod.OpenerDirector, "open", _open)


def _unpatch(name: str, mod: Any = None) -> None:
    """Restore every recorded generation for one import target."""
    del mod  # records retain the exact owners; sys.modules may be a new generation
    prefixes = (
        (f"{name}.",)
        if name in _HTTPX_FAMILIES or name == "requests"
        else ("urllib.",)
    )
    for target in reversed(list(_originals)):
        if not target.startswith(prefixes):
            continue
        records = _originals.pop(target)
        for record in reversed(records):
            _restore_record(record)


#: Module name -> patcher. Keyed on the importable name so the hook below can
#: match it exactly.
_TARGETS = {
    "httpx": _patch_httpx,
    "httpx2": _patch_httpx2,
    "requests": _patch_requests,
    "urllib.request": _patch_urllib,
}

_patched: set[str] = set()


class _PatchOnImport:
    """Patch a client library the moment it is first imported.

    Importing an HTTPX family eagerly from ``import maverick`` costs real time and breaks
    the CLI cold-start guarantee -- ``maverick --help`` is pinned not to load
    httpx/httpx2, the provider SDKs, numpy, or fastapi, and a stray module-level
    import taxes every invocation. So the guard arms itself instead: it patches
    what is already loaded, and registers this finder to catch the rest.

    ``find_spec`` delegates to the remaining finders for the real spec, then
    wraps that spec's ``exec_module`` so the patch lands immediately after the
    module body runs. The loader instance is created per-spec, so setting the
    attribute here does not leak into unrelated imports.
    """

    __maverick_egress_guard_import_hook__ = True

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in _TARGETS:
            return None
        spec = None
        for finder in sys.meta_path:
            if finder is self:
                continue
            found = getattr(finder, "find_spec", None)
            if found is None:
                continue
            try:
                spec = found(fullname, path, target)
            except Exception:  # failure-policy: best_effort -- try other finders
                spec = None
            if spec is not None:
                break
        if spec is None or spec.loader is None:
            return None
        real_exec = spec.loader.exec_module

        def exec_module(module, _real=real_exec, _name=fullname):
            # Reload executes into the existing module object. Mark readiness
            # unavailable before that object can expose freshly defined,
            # unwrapped classes to another thread.
            with _lifecycle_lock:
                participating = _installed and _hook is self
                if participating:
                    _patched.discard(_name)
                    _compatibility[_name] = {
                        "compatible": False,
                        "reason": "client import or reload is in progress",
                        "fail_closed_fallback": False,
                    }
            _real(module)
            if not participating:
                return
            try:
                with _lifecycle_lock:
                    # The guard may have been uninstalled while the real loader
                    # executed. Never leave an untracked wrapper behind.
                    if not _installed or _hook is not self:
                        return
                    _patch_target(_name, module)
                    _patched.add(_name)
                    if _name not in _HTTPX_FAMILIES:
                        _compatibility.pop(_name, None)
            # failure-policy: fail_closed
            except Exception as exc:
                # An imported-but-unwrapped client would remain usable if
                # enterprise mode were enabled later at runtime. Readiness
                # metadata alone cannot close that socket path, so refuse the
                # import when no enforceable wrapper could be installed.
                _compatibility.setdefault(
                    _name,
                    {
                        "compatible": False,
                        "reason": "egress guard installation failed",
                        "fail_closed_fallback": False,
                    },
                )
                log.exception("egress guard: could not wrap %s", _name)
                raise RuntimeError(
                    f"refusing to import {_name}: the process-wide egress "
                    "boundary could not be installed"
                ) from exc

        try:
            spec.loader.exec_module = exec_module
        except (AttributeError, TypeError):  # pragma: no cover - exotic loader
            return None
        return spec


_hook: _PatchOnImport | None = None


def _patch_target(name: str, module: Any) -> None:
    """Patch one loaded target atomically across all of its network seams."""
    snapshot = _record_lengths()
    try:
        _TARGETS[name](module)
    except Exception:  # failure-policy: fail_closed -- undo and re-raise
        _restore_since(snapshot)
        raise


def _remove_hook() -> None:
    global _hook
    # Do not rely only on ``_hook``. ``importlib.reload(egress_guard)`` resets
    # that module global but cannot remove the prior finder from meta_path.
    # Multiple retained finders wrap the same loader recursively and can make a
    # later target import fail with RecursionError.
    for finder in tuple(sys.meta_path):
        if finder is not _hook and not getattr(finder, _HOOK_MARKER, False):
            continue
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
    _hook = None


def _teardown(*, clear_compatibility: bool = True) -> None:
    """Restore all recorded seams, including incomplete install state."""
    global _installed
    for name in reversed(tuple(_TARGETS)):
        _unpatch(name)
    _originals.clear()
    _patched.clear()
    _remove_hook()
    if clear_compatibility:
        _compatibility.clear()
    _installed = False


def _patch_loaded_target(name: str) -> None:
    """Guard a target that has already been imported, if present."""
    module = sys.modules.get(name)
    if module is None:
        return
    _patch_target(name, module)
    _patched.add(name)
    if name not in _HTTPX_FAMILIES:
        _compatibility.pop(name, None)


def install() -> bool:
    """Arm the guard. Idempotent; returns whether it is active.

    Patches every target already imported, and hooks the rest so they are
    wrapped on first import. Deliberately does NOT import httpx or httpx2: see
    :class:`_PatchOnImport`.
    """
    global _installed, _hook
    with _lifecycle_lock:
        # A prior failed install can leave records even though `_installed`
        # never became true. Start from a known, fully restored baseline.
        if not _installed:
            _teardown()

        failed_name = "unknown"
        try:
            # First cover everything already loaded.
            for name in _TARGETS:
                failed_name = name
                _patch_loaded_target(name)

            # Then arm lazy imports. A second scan closes the interval between
            # the first scan and hook insertion for another importing thread.
            if _hook is None:
                _hook = _PatchOnImport()
                sys.meta_path.insert(0, _hook)
            for name in _TARGETS:
                failed_name = name
                _patch_loaded_target(name)
        except Exception:  # failure-policy: fail_closed -- tear down and re-raise
            failure = dict(
                _compatibility.get(
                    failed_name,
                    {
                        "compatible": False,
                        "reason": "egress guard installation failed",
                        "fail_closed_fallback": False,
                    },
                )
            )
            failure["compatible"] = False
            if not failure.get("reason"):
                failure["reason"] = "egress guard installation failed"
            _teardown()
            _compatibility[failed_name] = failure
            raise

        _installed = True
        return True


def uninstall() -> None:
    """Restore the unwrapped network paths. For tests and controlled teardown."""
    with _lifecycle_lock:
        # Do not trust `_installed`: an exception can occur after the first
        # family or method was wrapped but before that flag is committed.
        _teardown()


def _target_is_guarded(name: str, module: Any) -> bool:
    if name in _HTTPX_FAMILIES:
        status = _compatibility.get(name)
        if not status or status.get("compatible") is not True:
            return False
        attribute = "_send_single_request"
        owners = (getattr(module, "Client", None), getattr(module, "AsyncClient", None))
        targets = (
            f"{name}.Client.{attribute}",
            f"{name}.AsyncClient.{attribute}",
        )
        return all(
            owner is not None
            and _is_guard_wrapper(getattr(owner, attribute, None), target)
            for owner, target in zip(owners, targets, strict=True)
        )
    if name == "requests":
        owner = getattr(module, "Session", None)
        return owner is not None and _is_guard_wrapper(
            getattr(owner, "send", None),
            "requests.Session.send",
        )
    if name == "urllib.request":
        owner = getattr(module, "OpenerDirector", None)
        return owner is not None and _is_guard_wrapper(
            getattr(owner, "open", None),
            "urllib.OpenerDirector.open",
        )
    return False


def active() -> bool:
    with _lifecycle_lock:
        if not _installed or _hook is None or _hook not in sys.meta_path:
            return False
        if not all(
            status.get("compatible") is True
            for status in _compatibility.values()
        ):
            return False
        return all(
            _target_is_guarded(name, module)
            for name in _TARGETS
            if (module := sys.modules.get(name)) is not None
        )


def compatibility_status() -> dict[str, Any]:
    """Return an operator-readable snapshot of guarded-client compatibility.

    HTTPX's one-hop seam is intentionally checked at runtime rather than
    assumed from a package version. ``active`` becomes false when a loaded
    client cannot be wrapped, giving readiness/doctor integrations a
    fail-closed signal instead of silently claiming the boundary is installed.
    """
    with _lifecycle_lock:
        return {
            "installed": _installed,
            "active": active(),
            "clients": {
                name: dict(status)
                for name, status in sorted(_compatibility.items())
            },
        }


__all__ = [
    "COVERED_LIBRARIES",
    "active",
    "compatibility_status",
    "install",
    "uninstall",
]
