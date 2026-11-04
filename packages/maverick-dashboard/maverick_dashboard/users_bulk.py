"""Change many people's roles at once on the Users page, and undo it.

Filter the people list, select people (or every person matching the filter),
choose a role, confirm a count, and get a change report that can be undone.
Every change goes through :func:`rbac.set_role` / :func:`rbac.remove_user`,
the same calls the one-person controls use, so their audit records, their
recovery-administrator protection and their validation all apply per person.
Pending invitations can be cancelled in bulk the same way (that one cannot be
undone, and the confirmation says so).
"""
from __future__ import annotations

from maverick.audit import AuditRefused

_SEP = "\x1f"
MAX_PEOPLE = 500


def matches(principal: str, role: str, label: str, query: str, role_filter: str) -> bool:
    """Whether one row passes the People filter (text in the name, email or
    sign-in, and an exact role)."""
    if role_filter and role != role_filter:
        return False
    text = (query or "").strip().lower()
    return not text or text in principal.lower() or text in (label or "").lower()


def matching(role_map: dict[str, str], labels: dict[str, str], query: str, role_filter: str) -> list[str]:
    return [p for p, r in sorted(role_map.items()) if matches(p, r, labels.get(p, ""), query, role_filter)]


def targets(role_map: dict[str, str], labels: dict[str, str], *, scope: str, chosen: list[str],
            query: str, role_filter: str) -> list[str]:
    """The people a bulk change applies to: everyone matching the filter, or
    the selected people who still hold an explicit role."""
    if scope == "matching":
        found = matching(role_map, labels, query, role_filter)
    else:
        picked = {p.strip() for p in chosen if p and p.strip()}
        found = [p for p in sorted(role_map) if p in picked]
    return found[:MAX_PEOPLE + 1]


_MAY_HAVE_CHANGED = ("The activity log refused this change and the role list could not be put back, "
                     "so it may now hold the change. Check this person's role.")


def _may_have_changed(row: dict, principal: str, attempted: str) -> None:
    """The change was refused but not rolled back: report the role the list
    holds now (read back), so the change is never shown as not made."""
    from . import rbac

    try:
        now = rbac.list_users().get(principal, "")
    except Exception:  # noqa: BLE001 -- the list is the thing that failed
        now = attempted
    row.update(outcome="uncertain", after=now, reason=_MAY_HAVE_CHANGED)


def _store_reason(exc: Exception) -> str:
    if isinstance(exc, AuditRefused):
        return "The activity log refused this change, so it was not made."
    return str(exc) or "The role list could not be updated."


def apply(people: list[str], role: str, *, actor: str) -> list[dict]:
    """Give each person ``role``; one refusal never stops the others."""
    from . import rbac

    current = rbac.list_users()
    report = []
    for principal in people:
        before = current.get(principal, "")
        row = {"principal": principal, "before": before, "after": role, "outcome": "changed", "reason": ""}
        if before == role:
            row["outcome"] = "unchanged"
        else:
            try:
                rbac.set_role(principal, role, actor=actor)
            except rbac.RecoveryAuthorityError as exc:
                row.update(outcome="refused", after=before, reason=str(exc))
            except ValueError:
                row.update(outcome="refused", after=before, reason="That role or person is not valid.")
            except rbac.RosterRollbackError:
                _may_have_changed(row, principal, role)
            except (rbac.RbacStoreError, AuditRefused) as exc:
                # The activity log or the role list refused this one change. The
                # people already changed keep their report (and their undo).
                row.update(outcome="refused", after=before, reason=_store_reason(exc))
        report.append(row)
    return report


def undo_tokens(report: list[dict]) -> list[str]:
    """What the Undo button posts back: each changed person, the role they had
    before and the role this change gave them."""
    return [f"{row['principal']}{_SEP}{row['before']}{_SEP}{row['after']}"
            for row in report
            if row["outcome"] == "changed"
            or (row["outcome"] == "uncertain" and row["after"] != row["before"])]


def undo(tokens: list[str], *, actor: str) -> list[dict]:
    """Put each person back on the role they had before a bulk change. An
    empty earlier role clears the explicit role again (the standard role then
    applies), exactly as "Use standard role" does."""
    from . import rbac

    current = rbac.list_users()
    report = []
    for token in tokens[:MAX_PEOPLE]:
        principal, _, rest = str(token).partition(_SEP)
        principal = principal.strip()
        if not principal:
            continue
        before, has_given, given = rest.partition(_SEP)
        now = current.get(principal, "")
        row = {"principal": principal, "before": now, "after": before, "outcome": "changed", "reason": ""}
        try:
            if now == before:
                row["outcome"] = "unchanged"
            elif has_given and now != given:
                # Someone changed this person again after the bulk change; putting
                # the old role back would overwrite that newer decision.
                row.update(outcome="refused", after=now,
                           reason="Their role was changed again after this change, so it was left as it is.")
            elif before:
                rbac.set_role(principal, before, actor=actor)
            else:
                rbac.remove_user(principal, actor=actor)
        except rbac.RecoveryAuthorityError as exc:
            row.update(outcome="refused", after=now, reason=str(exc))
        except ValueError:
            row.update(outcome="refused", after=now, reason="That role or person is not valid.")
        except rbac.RosterRollbackError:
            _may_have_changed(row, principal, before)
        except (rbac.RbacStoreError, AuditRefused) as exc:
            row.update(outcome="refused", after=now, reason=_store_reason(exc))
        report.append(row)
    return report


__all__ = ["MAX_PEOPLE", "apply", "matches", "matching", "targets", "undo", "undo_tokens"]
