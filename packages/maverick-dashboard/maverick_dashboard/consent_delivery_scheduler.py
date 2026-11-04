"""Bounded rotating worker for explicitly reviewed native consent subscriptions."""
from __future__ import annotations

import logging
import threading
import time

from maverick import config
from maverick import consent_delivery as native
from maverick.consent_delivery_runtime import run_delivery_once
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.tenant.registry import assert_tenant_active, list_tenants

from . import auth, rbac, workspace_tenants
from . import consent_delivery_api as existing

log = logging.getLogger(__name__)
_lock = threading.Lock()
_stop = _thread = None
_cursor = ""
_states = {}


def subscription_authority(store, tenant, subscription):
    """Current saved owner, exact editions and native source at every boundary."""
    from .consent_delivery_managed_api import REFERENCE, _pins, worker_enabled
    try:
        if current_tenant_id_strict() != tenant or not worker_enabled():
            raise PermissionError
        assert_tenant_active(tenant)
        current = store.managed_record(tenant, "subscription", REFERENCE)
        if current != subscription or not current["material"]["active"]:
            raise PermissionError
        material = current["material"]
        owner = material["owner"]
        auth.stored_automation_identity(owner)
        if ("admin" not in rbac.permissions_for(auth.role_for_principal(owner)) or
                "admin" not in rbac.permissions_for(auth.global_role_for_principal(owner))):
            raise PermissionError
        mode = material["workspace_authority"]
        if mode == "principal_selection" and not workspace_tenants.principal_can_select(owner, tenant):
            raise PermissionError
        if mode not in {"principal_selection", "principal_isolation", "operator_floor"}:
            raise PermissionError
        if mode == "principal_isolation":
            from maverick.paths import canonical_tenant_id, tenant_by_user_enabled
            if not tenant_by_user_enabled() or canonical_tenant_id("api:"+owner) != tenant:
                raise PermissionError
        if mode == "operator_floor":
            from maverick.paths import implicit_tenant_id
            configured = config.load_config().get("dashboard", {}).get("active_tenant")
            if tenant not in {implicit_tenant_id(), configured}:
                raise PermissionError
        from . import ui_visibility
        if not ui_visibility.is_visible(ui_visibility.page_for("/consent/delivery"), auth.role_for_principal(owner)):
            raise PermissionError
        if _pins(store, tenant, [item["destination_id"] for item in material["destinations"]]) != material["destinations"]:
            raise PermissionError
        existing._ops()
    except Exception as exc:
        raise native.ConsentDeliveryRevoked("The automatic subscription’s current authority changed; review it again.") from exc


def workspace_cycle(tenant, *, transport=None):
    from .consent_delivery_managed_api import REFERENCE, worker_enabled
    if not worker_enabled():
        return
    ops = existing._ops()
    store = existing._delivery_store(ops, tenant)
    subscription = store.managed_record(tenant, "subscription", REFERENCE)
    if subscription is None or not subscription["material"]["active"]:
        return
    subscription_authority(store, tenant, subscription)
    material = subscription["material"]
    def guard(claim):
        subscription_authority(store, tenant, subscription)
        if claim is not None and not any((claim.destination_id, claim.destination_revision, claim.signing_key_id) ==
                (item["destination_id"], item["revision"], item["key_id"]) for item in material["destinations"]):
            raise native.ConsentDeliveryRevoked("This send is outside the reviewed destination editions.")
    result = run_delivery_once(tenant, [item["destination_id"] for item in material["destinations"]],
        worker_id="managed-consent-delivery", sync_limit=100, delivery_limit=10, lease_seconds=60,
        preference_store=existing._preference_store(tenant), delivery_store=store, transport=transport,
        after_sequence=material["watermark"], before_effect=guard, hold_unknown=True)
    _states[tenant] = {"checked_at": time.time(), "held": False, "dispatched": result["dispatched"]}
    return result


def cycle():
    global _cursor
    from .automation_queue import _configured_tenant_floor
    if config.config_source_errors():
        raise ValueError("Current delivery settings are unavailable.")
    floor = _configured_tenant_floor()
    tenants = {rec.id for rec in list_tenants() if rec.active}
    if floor:
        tenants.add(floor)
    ordered = sorted(tenants)
    batch = ([item for item in ordered if item > _cursor]+[item for item in ordered if item <= _cursor])[:16]
    for tenant in batch:
        _cursor = tenant
        try:
            with tenant_scope(tenant=tenant):
                workspace_cycle(tenant)
        except Exception as exc:
            _states[tenant] = {"checked_at": time.time(), "held": True}
            log.warning("Automatic consent delivery held (%s)", type(exc).__name__)
    # Status is a bounded process observation, never proof of delivery.
    for tenant in list(_states):
        if tenant not in tenants:
            _states.pop(tenant, None)
    if len(_states) > 128:
        for tenant in sorted(_states, key=lambda item: _states[item]["checked_at"])[:-128]:
            _states.pop(tenant, None)


def _loop(stop):
    while not stop.is_set():
        try:
            cycle()
        except Exception as exc:
            log.warning("Automatic consent delivery unavailable (%s)", type(exc).__name__)
        stop.wait(5)


def start_consent_delivery_scheduler():
    global _stop, _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _stop = threading.Event()
        _thread = threading.Thread(target=_loop, args=(_stop,), name="consent-delivery", daemon=True)
        _thread.start()
        return True


def stop_consent_delivery_scheduler(*, timeout=5, wait=True):
    global _stop, _thread
    with _lock:
        stop, worker = _stop, _thread
        if stop is not None:
            stop.set()
    if worker is None:
        return False
    if wait:
        worker.join(max(0, min(float(timeout),30)))
    if worker.is_alive():
        return False
    with _lock:
        if worker is _thread:
            _stop = _thread = None
    return True


def status(tenant):
    return {"running_here": _thread is not None and _thread.is_alive(), "last_check": _states.get(tenant),
            "batch_limit":16,"delivery_limit":10,"source_limit":100,
            "note":"Automatic delivery runs only for a reviewed active subscription. A running worker does not prove a delivery arrived."}
