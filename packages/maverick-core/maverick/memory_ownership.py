"""Resolve content ownership independently of a task's execution capability."""
from __future__ import annotations


def current_owner(*, world=None, goal_id=None) -> str:
    from .logging_config import current_goal_id
    from .world_model import close_world_if_owned, open_world

    goal_id = current_goal_id() if goal_id is None else goal_id
    if not goal_id:
        return ""  # explicit local/unowned scope, never all named employees
    owned = world is None
    world = open_world() if owned else world
    try:
        goal = world.get_goal(goal_id)
        if goal is None or not isinstance(getattr(goal, "owner", None), str):
            raise ValueError("Current memory ownership is unavailable")
        return goal.owner
    finally:
        if owned:
            close_world_if_owned(world)


def source_allowed(goal_id, owner: str, *, world=None) -> bool:
    """A source must still exist, retain its owner and permit local learning."""
    from .pilot_learning import excluded
    if not goal_id:
        return owner == ""  # new explicitly local records only
    try:
        return not excluded(goal_id) and current_owner(world=world, goal_id=goal_id) == owner
    except Exception:
        return False


# Records in the Lightwork home folder that name people who can sign in. Each
# maps the parsed JSON to the people it names; a shape it does not expect
# raises, and the installation then does not count as single-person.
def _invited(data):
    # An invitation that expired unused can never be accepted; any other one
    # (still open, or used) names a person who can sign in.
    import time

    now = time.time()
    return [row["email"] for row in data.values()
            if row.get("used_at") or float(row.get("expires_at") or now + 1) > now]


def _accounts(data):
    return list(data["accounts"])


def _keys(data):
    return list(data)


def _workspace_roles(data):
    return [person for members in data.values() for person in members]


def _selections(data):
    return list(data.get("selections") or {})


def _scim_users(data):
    # Any provisioned user means company sign-in manages people here.
    return [str(row) for row in data["users"]]


_PEOPLE_FILES = (
    ("dashboard-invites.json", _invited),
    ("dashboard-passphrases.json", _accounts),
    ("dashboard-users.json", _keys),
    ("dashboard-tenant-roles.json", _workspace_roles),
    ("dashboard-workspace-tenants.json", _selections),
    ("scim_users.json", _scim_users),
)
_MAX_PEOPLE_FILE_BYTES = 4 * 1024 * 1024


def _person(value) -> str:
    text = str(value).strip().casefold()
    return text.removeprefix("user:")


def _others_can_sign_in() -> bool:
    """A sign-in method that admits people other than the local owner."""
    import os

    from .config import load_global_config
    from .oidc import oidc_enabled
    from .proxy_auth import proxy_auth_enabled

    if oidc_enabled() or proxy_auth_enabled() or os.environ.get("MAVERICK_DASHBOARD_TOKEN", "").strip():
        return True
    table = (load_global_config() or {}).get("dashboard") or {}
    if not isinstance(table, dict):
        return True
    token, admins = table.get("token"), table.get("admins")
    return bool(isinstance(token, str) and token.strip()) or bool(admins)


def sole_person() -> str:
    """The installation's only person, as ``user:<email>``, or ``""``.

    Learning keeps one person's task text out of what a workspace shares. On
    an installation only its owner can sign in to, "shared" can only mean
    shared with that owner, so learning may use their tasks. Any sign of a
    second person -- another local account, role, workspace role, invitation
    or provisioned user, a configured administrator list, or a sign-in method
    that admits other people (company sign-in, a sign-in proxy, the shared
    access token) -- answers ``""``, and so does anything unreadable. It is
    asked again every time, so what was learned stops being used the moment
    someone else can sign in."""
    import json

    from .cli._local_owner import goal_owner
    from .paths import maverick_home

    try:
        owner = goal_owner()
        if not owner or _others_can_sign_in():
            return ""
        me = _person(owner)
        home = maverick_home()
        for name, people in _PEOPLE_FILES:
            path = home / name
            if not path.exists():
                continue
            if path.stat().st_size > _MAX_PEOPLE_FILE_BYTES:
                return ""
            data = json.loads(path.read_text(encoding="utf-8"))
            if data in ({}, []):
                continue
            if any(_person(person) != me for person in people(data)):
                return ""
        return owner
    except Exception:  # noqa: BLE001 -- anything unreadable means "not provably alone"
        return ""


def learning_source_allowed(goal_id, *, world=None, sole: str | None = None) -> bool:
    """Whether skill learning may use this task: a shared (ownerless) task,
    or, on a single-person installation, one of its owner's tasks. Pass
    ``sole`` (from :func:`sole_person`) when checking many tasks at once."""
    if source_allowed(goal_id, "", world=world):
        return True
    sole = sole_person() if sole is None else sole
    return bool(sole) and source_allowed(goal_id, sole, world=world)
