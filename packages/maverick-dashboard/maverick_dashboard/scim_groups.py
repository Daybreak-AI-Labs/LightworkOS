"""IdP group -> dashboard access mapping (SCIM Groups to roles/departments).

SCIM (``scim.py``) stores the groups an IdP pushes; this module turns that
membership into access, so joining the "Finance Team" in Okta/Entra is what
grants the finance department — no per-user hand assignment:

    [dashboard.group_roles]
    "Finance Team" = "operator"

    [dashboard.group_suites]
    "Finance Team" = ["finance", "tax"]

Group names and role values are matched case-insensitively (an IdP may rename a
group's case, or an operator may capitalize a role). A ``group_suites`` value
may be a single string or a list; unknown suite keys are dropped, so a typo
never silently widens access.

Resolution order (explicit always wins over derived):
  * role:   stored assignment -> group-derived -> ``default_role``
    (wired in ``auth.global_role_for_principal``);
  * suites: explicit grant -> group-derived -> ``[dashboard] default_suites``
    (wired as a kernel grant resolver — see
    :func:`maverick.suite_grants.register_grant_resolver`).

Enforcement reach: the resolver is armed by importing this module, which the
dashboard does at startup (``auth`` imports it). Explicit grants and the
configured default therefore resolve identically in every process, but
group-*derived* grants are only visible where the dashboard resolver is armed.
A pure ``maverick-core`` process (e.g. a worker that never imports the
dashboard) falls back to explicit-grant + default; run department scoping in
**deny-by-default** mode (``[dashboard] default_suites``) if you need a
non-dashboard surface to fail closed for a group-only principal rather than
fall through to unrestricted.

Identity matching is deliberately strict. A dashboard principal is
``user:<sub>`` (the OIDC subject). We match it to a SCIM user only through a
*non-forgeable* binding: the IdP's own ``externalId`` (the usual Okta sub /
Entra immutable object id) or our internal record ``id``. For pairwise-``sub``
IdPs (Entra), where the login sub differs from ``externalId``, we bridge
through the subject directory — but ONLY on those same non-forgeable
identifiers. We never match (directly or via the directory) on
``userName``/``email``: those are contact/display attributes, and the directory
records login ``email``/``upn`` claims WITHOUT an ``email_verified`` check, so
keying a grant on them would let a forged email claim (or a second identity
source) resolve another user's SCIM record and inherit its group-mapped role
and departments. ``subs_for`` stays broad for *revocation* (over-revoking is
safe); *granting* must not. Deactivated (``active=false``) users confer
nothing. Derived access follows the IdP automatically: mappings are read at
resolution time, so removing a user from the group (or the group itself)
revokes on the next request.

Note on trust: with a ``group_roles``/``group_suites`` mapping configured, the
static ``MAVERICK_SCIM_TOKEN`` becomes an authorization-granting credential
(pushing a user into a mapped group confers that group's role/departments).
Treat it with the sensitivity of an admin credential and rotate/scope it
accordingly.
"""
from __future__ import annotations

from maverick.suite_grants import known_suites, register_grant_resolver

from .rbac import is_known_role, most_privileged


class GroupAccessPolicyError(RuntimeError):
    """Group-derived access policy cannot be read or validated."""


def _config_table(key: str) -> dict | None:
    """Return a configured mapping, preserving absent-vs-corrupt semantics."""
    try:
        from maverick.config import config_source_errors, load_config

        cfg = load_config()
        errors = config_source_errors()
    except Exception as e:
        raise GroupAccessPolicyError("group access config is unreadable") from e
    if errors:
        paths = ", ".join(sorted(errors))
        raise GroupAccessPolicyError(
            f"group access config source is unreadable: {paths}"
        )
    if not isinstance(cfg, dict):
        raise GroupAccessPolicyError("group access config root must be a table")
    dashboard = cfg.get("dashboard")
    if dashboard is None:
        return None
    if not isinstance(dashboard, dict):
        raise GroupAccessPolicyError("dashboard config must be a table")
    raw = dashboard.get(key)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise GroupAccessPolicyError(f"dashboard.{key} must be a table")
    return raw


def _ci_mapping(key: str) -> dict:
    """The ``[dashboard.<key>]`` table re-keyed by case-folded group name, so
    lookups survive an IdP renaming a group's case."""
    table = _config_table(key)
    if not table:
        return {}
    result: dict[str, object] = {}
    for raw_name, raw_value in table.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise GroupAccessPolicyError(f"dashboard.{key} has an invalid group name")
        name = raw_name.strip().casefold()
        if name in result:
            raise GroupAccessPolicyError(
                f"dashboard.{key} has duplicate case-insensitive group names"
            )
        if key == "group_roles":
            if not isinstance(raw_value, str) or not is_known_role(raw_value.strip().lower()):
                raise GroupAccessPolicyError(
                    f"dashboard.{key} has an invalid role for {raw_name!r}"
                )
            result[name] = raw_value.strip().lower()
        elif key == "group_suites":
            if isinstance(raw_value, str):
                values = [raw_value]
            elif isinstance(raw_value, (list, tuple)):
                values = list(raw_value)
            else:
                raise GroupAccessPolicyError(
                    f"dashboard.{key} has an invalid suite list for {raw_name!r}"
                )
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise GroupAccessPolicyError(
                    f"dashboard.{key} has an invalid suite for {raw_name!r}"
                )
            result[name] = [value.strip() for value in values]
        else:  # pragma: no cover - only the two policy tables are internal callers
            raise GroupAccessPolicyError(f"unsupported group access table {key!r}")
    return result


def _sub_of(principal: str) -> str:
    p = (principal or "").strip()
    return p.removeprefix("user:")


def _active(rec: dict) -> bool:
    """Whether a validated SCIM record carries the literal boolean ``true``.

    The store parser rejects non-booleans; this defensive identity check keeps
    a directly supplied or future record shape from treating a truthy string as
    active and conferring group access.
    """
    return rec.get("active") is True


def _matching_users(principal: str) -> dict[str, dict]:
    """Validated SCIM users authoritatively bound to ``principal``."""
    sub = _sub_of(principal)
    if not sub:
        return {}
    from . import subject_directory
    from .scim import _load

    if subject_directory.is_retired(sub):
        return {}
    users = _load()
    if not users:
        return {}
    directory = subject_directory.load_index()
    matched: dict[str, dict] = {}
    for uid, rec in users.items():
        ext_id = str(rec.get("externalId") or "")
        int_id = str(rec.get("id") or "")
        if sub in (ext_id, int_id) or sub in subject_directory.subs_in(
            directory, [ext_id, int_id]
        ):
            matched[uid] = rec
    return matched


def active_for_principal(principal: str) -> bool | None:
    """SCIM lifecycle status for an authenticated principal.

    ``None`` means the SCIM roster has no authoritative binding (no opinion),
    ``True`` means matched and active, and ``False`` means matched but
    deprovisioned. Store/directory corruption raises so authentication can deny
    rather than grant the deployment default role.
    """
    sub = _sub_of(principal)
    if not sub:
        return None
    from .subject_directory import is_retired

    # A hard DELETE removes the SCIM resource, but never its denial decision.
    # Check the hashed retirement ledger before interpreting an absent roster
    # match as "no opinion" and falling through to the deployment default role.
    if is_retired(sub):
        return False
    matched = _matching_users(principal)
    if not matched:
        return None
    return all(_active(rec) for rec in matched.values())


def active_check():
    """``check(principal)``: :func:`active_for_principal`'s answer for many
    principals (a list of people, not one sign-in). The SCIM users, subject
    directory and retired ledger are read and indexed once, so each check is
    a lookup. Corruption raises here, as it does there."""
    from . import subject_directory
    from .scim import _load

    directory = subject_directory.load_index()
    retired = subject_directory.retired_check(directory)
    by_sub: dict[str, dict[str, dict]] = {}
    for uid, rec in _load().items():
        ext_id = str(rec.get("externalId") or "")
        int_id = str(rec.get("id") or "")
        for key in {ext_id, int_id} | subject_directory.subs_in(directory, [ext_id, int_id]):
            by_sub.setdefault(key, {})[uid] = rec

    def check(principal: str) -> bool | None:
        sub = _sub_of(principal)
        if not sub:
            return None
        if retired(sub):
            return False
        matched = by_sub.get(sub)
        if not matched:
            return None
        return all(_active(rec) for rec in matched.values())
    return check


def group_names_for_principal(principal: str) -> frozenset[str]:
    """The displayNames of every SCIM group the (active) principal belongs to."""
    from .scim import _load_effective_groups

    users = _matching_users(principal)
    groups = _load_effective_groups()
    if not users or not groups:
        return frozenset()

    matched = {uid for uid, rec in users.items() if _active(rec)}
    if not matched:
        return frozenset()
    return frozenset(
        str(g.get("displayName") or "")
        for g in groups.values()
        if matched & set(g.get("members", []))
    ) - {""}


def role_for_principal(principal: str) -> str | None:
    """The most-privileged role mapped to any of the principal's groups, or
    ``None`` when no group carries a role mapping."""
    try:
        mapping = _ci_mapping("group_roles")
        if not mapping:
            return None
        names = group_names_for_principal(principal)
        mapped = {mapping[n.casefold()]
                  for n in names if n.casefold() in mapping}
        # Ranked by granted permission atoms -- the generalization of "ROLES
        # is ordered most-privileged first" that also covers custom roles.
        return most_privileged(mapped)
    except Exception:
        # auth.global_role_for_principal deliberately swallows resolver errors
        # and falls through to the deployment default (historically operator).
        # Return the least-privileged valid role instead, so corrupt SCIM state
        # or policy cannot silently broaden access through that fallback.
        from . import strict_reads

        if strict_reads.active():
            raise
        return "viewer"


def suites_for_principal(principal: str) -> frozenset[str] | None:
    """The union of department suites mapped to the principal's groups, or
    ``None`` when no group carries a suites mapping (no opinion).

    A matched group with an empty/typo'd value yields a (possibly empty) grant,
    NOT unrestricted: once any of the caller's groups matches a ``group_suites``
    row, the result is the intersection with the real suite catalog — deny is
    the safe direction for a misconfiguration, never a silent widening."""
    try:
        mapping = _ci_mapping("group_suites")
        if not mapping:
            return None
        names = group_names_for_principal(principal)
        hit = False
        out: set[str] = set()
        for n in names:
            key = n.casefold()
            if key not in mapping:
                continue
            hit = True
            out.update(mapping[key])
        if not hit:
            return None
        return frozenset(out) & known_suites()
    except Exception:
        # The kernel grant chain also swallows resolver errors and otherwise
        # falls through to an unrestricted default. An explicit empty result
        # is the only fail-closed answer at this integration seam.
        return frozenset()


# Plug group-derived grants into the KERNEL resolution chain, so the
# deploy/dispatch gates in maverick.departments / maverick.fleet honor group
# membership in any process that has imported the dashboard. Importing this
# module (auth.py does, at module import) is what arms the resolver.
register_grant_resolver(suites_for_principal)

__all__ = [
    "GroupAccessPolicyError", "active_check", "active_for_principal", "group_names_for_principal",
    "role_for_principal", "suites_for_principal",
]
