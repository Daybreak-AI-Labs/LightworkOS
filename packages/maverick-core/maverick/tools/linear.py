"""Linear issue-tracker tool.

Read + write Linear issues via their GraphQL API.

Auth: LINEAR_API_KEY (personal API key from Linear → Settings → API).

ops:
  - search(query, limit)           — text search across issues
  - get(issue_id)                  — fetch one (use the team/key id like "ENG-123")
  - create(title, description, team) — open an issue
  - comment(issue_id, body)        — append a comment
  - update_status(issue_id, state) — move between states (Triage, Todo, ...)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_LINEAR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "get", "create", "comment", "update_status"],
        },
        "query": {"type": "string"},
        "issue_id": {"type": "string", "description": "Issue identifier (e.g. 'ENG-123')."},
        "title": {"type": "string"},
        "description": {"type": "string"},
        "team": {"type": "string", "description": "Team key (e.g. 'ENG'). Required for create."},
        "body": {"type": "string", "description": "Comment body."},
        "state": {"type": "string", "description": "State name (e.g. 'In Progress')."},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


_API_URL = "https://api.linear.app/graphql"


def _key() -> str:
    k = os.environ.get("LINEAR_API_KEY", "").strip()
    if not k:
        raise RuntimeError(
            "Linear requires LINEAR_API_KEY (personal API key from "
            "Linear → Settings → API)."
        )
    return k


def _post(query: str, variables: dict | None = None) -> dict:
    import httpx
    resp = _governed_sender(httpx.post)(
        _API_URL,
        json={"query": query, "variables": variables or {}},
        headers={
            "Authorization": _key(),
            "Content-Type": "application/json",
        },
        timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("errors"):
        raise RuntimeError(f"Linear API error: {data['errors']}")
    return data.get("data") or {}


def _search(query: str, limit: int) -> str:
    # Linear's issueSearch takes a top-level `query: String` term for
    # full-text search. The old `filter: {searchableContent: ...}` is not a
    # valid IssueFilter field, so the GraphQL document was rejected and every
    # search raised "Linear API error".
    # issueSearch caps `first` at 100 and paginates with a Relay-style
    # pageInfo cursor; follow `endCursor` until `limit` issues are collected,
    # bounded by a hard page cap.
    q = """
    query Search($q: String!, $n: Int!, $after: String) {
      issueSearch(query: $q, first: $n, after: $after) {
        nodes { identifier title state { name } url priority }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    nodes: list[dict] = []
    after: str | None = None
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        n = min(100, max(1, limit - len(nodes)))
        data = _post(q, {"q": query, "n": n, "after": after})
        search = data.get("issueSearch") or {}
        nodes.extend(search.get("nodes") or [])
        page = search.get("pageInfo") or {}
        if len(nodes) >= limit or not page.get("hasNextPage"):
            break
        after = page.get("endCursor")
        if not after:
            break
    nodes = nodes[:limit]
    if not nodes:
        return "no matches"
    return "\n".join(
        f"  {n['identifier']}  [{(n.get('state') or {}).get('name', '?'):>12}]  "
        f"{n.get('title', '')[:80]}  {n.get('url', '')}"
        for n in nodes
    )


def _get(issue_id: str) -> str:
    q = """
    query Get($id: String!) {
      issue(id: $id) {
        identifier title description state { name }
        priority url assignee { name } team { key }
        createdAt updatedAt
      }
    }
    """
    data = _post(q, {"id": issue_id})
    issue = data.get("issue")
    if not issue:
        return f"issue {issue_id!r} not found"
    return (
        f"{issue['identifier']}  {issue['title']}\n"
        f"  state:    {(issue.get('state') or {}).get('name', '?')}\n"
        f"  priority: {issue.get('priority')}\n"
        f"  assignee: {(issue.get('assignee') or {}).get('name', '(unassigned)')}\n"
        f"  team:     {(issue.get('team') or {}).get('key', '')}\n"
        f"  created:  {issue.get('createdAt')}\n"
        f"  updated:  {issue.get('updatedAt')}\n"
        f"  url:      {issue.get('url')}\n\n"
        f"{(issue.get('description') or '')[:5000]}"
    )


def _resolve_team_id(team_key: str) -> str:
    q = """
    query Teams { teams(first: 50) { nodes { id key } } }
    """
    data = _post(q)
    for t in (data.get("teams") or {}).get("nodes") or []:
        if t.get("key") == team_key:
            return t.get("id", "")
    raise RuntimeError(f"team {team_key!r} not found")


def _create(title: str, description: str, team_key: str) -> str:
    team_id = _resolve_team_id(team_key)
    q = """
    mutation Create($t: String!, $d: String!, $teamId: String!) {
      issueCreate(input: {title: $t, description: $d, teamId: $teamId}) {
        success
        issue { identifier url }
      }
    }
    """
    data = _post(q, {"t": title, "d": description, "teamId": team_id})
    payload = data.get("issueCreate") or {}
    if not payload.get("success"):
        return "ERROR: issueCreate returned success=false"
    issue = payload.get("issue") or {}
    return f"created {issue.get('identifier')}: {issue.get('url')}"


def _comment(issue_id: str, body: str) -> str:
    q = """
    mutation Comment($id: String!, $body: String!) {
      commentCreate(input: {issueId: $id, body: $body}) {
        success comment { url }
      }
    }
    """
    data = _post(q, {"id": issue_id, "body": body})
    payload = data.get("commentCreate") or {}
    if not payload.get("success"):
        return "ERROR: commentCreate returned success=false"
    return f"commented: {(payload.get('comment') or {}).get('url', '')}"


def _update_status(issue_id: str, state_name: str) -> str:
    # Resolve state id by name for the team that owns this issue.
    q1 = """
    query IssueState($id: String!) {
      issue(id: $id) { team { id states(first: 50) { nodes { id name } } } }
    }
    """
    data = _post(q1, {"id": issue_id})
    issue = data.get("issue") or {}
    states = ((issue.get("team") or {}).get("states") or {}).get("nodes") or []
    target = next(
        (s for s in states if s.get("name", "").lower() == state_name.lower()),
        None,
    )
    if not target:
        names = ", ".join(s.get("name", "?") for s in states)
        return f"ERROR: state {state_name!r} not found. Available: {names}"
    q2 = """
    mutation Update($id: String!, $sid: String!) {
      issueUpdate(id: $id, input: {stateId: $sid}) { success }
    }
    """
    out = _post(q2, {"id": issue_id, "sid": target["id"]})
    if not (out.get("issueUpdate") or {}).get("success"):
        return "ERROR: issueUpdate returned success=false"
    return f"updated {issue_id} -> {state_name}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[session]'"
    try:
        if op == "search":
            return _search(
                (args.get("query") or "").strip() or " ",
                max(1, min(int(args.get("limit") or 20), 100)),
            )
        if op == "get":
            iid = (args.get("issue_id") or "").strip()
            if not iid:
                return "ERROR: get requires issue_id"
            return _get(iid)
        if op == "create":
            title = (args.get("title") or "").strip()
            team = (args.get("team") or "").strip()
            if not title or not team:
                return "ERROR: create requires title and team"
            return _create(title, args.get("description") or "", team)
        if op == "comment":
            iid = (args.get("issue_id") or "").strip()
            body = args.get("body") or ""
            if not iid or not body:
                return "ERROR: comment requires issue_id and body"
            return _comment(iid, body)
        if op == "update_status":
            iid = (args.get("issue_id") or "").strip()
            state = (args.get("state") or "").strip()
            if not iid or not state:
                return "ERROR: update_status requires issue_id and state"
            return _update_status(iid, state)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Linear request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def linear() -> Tool:
    return Tool(
        name="linear",
        description=(
            "Read / write Linear issues via GraphQL. ops: search "
            "(text), get (by identifier like 'ENG-123'), create "
            "(title + team key, optional description), comment "
            "(issue_id + body), update_status (issue_id + state name "
            "like 'In Progress'). Auth via LINEAR_API_KEY."
        ),
        input_schema=_LINEAR_SCHEMA,
        fn=_run,
    )
