"""Per-user department (suite) access grants — dashboard-facing shim.

The store and enforcement moved into the kernel (:mod:`maverick.suite_grants`)
so the deploy/dispatch chokepoints in ``maverick.departments`` /
``maverick.fleet`` gate EVERY caller, not just the dashboard. This module
re-exports that single source of truth so existing dashboard imports and tests
keep working unchanged.

Dashboard-only layering (SCIM-group-derived grants) lives in
``maverick_dashboard.scim_groups`` and is applied by ``auth.caller_suites`` on
top of the kernel resolution — explicit grant wins, then group-derived, then
the configured default.
"""
from __future__ import annotations

from maverick.suite_grants import (  # noqa: F401
    DepartmentAccessError,
    SuiteGrantStoreError,
    admin_principals,
    default_suites,
    ensure_suite_allowed,
    get_grant,
    granted_suites,
    is_admin_principal,
    known_suites,
    list_grants,
    register_grant_resolver,
    remove_grant,
    set_suites,
    store_path,
    suite_allowed_for,
)

__all__ = [
    "DepartmentAccessError", "SuiteGrantStoreError", "store_path", "known_suites",
    "default_suites",
    "admin_principals", "is_admin_principal", "register_grant_resolver",
    "list_grants", "get_grant", "granted_suites", "set_suites", "remove_grant",
    "suite_allowed_for", "ensure_suite_allowed",
]
