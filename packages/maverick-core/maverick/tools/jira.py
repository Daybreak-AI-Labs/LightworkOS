"""Jira issue-tracker tool.

Read + write Jira issues via the v3 REST API.

Auth: JIRA_URL (e.g. https://your-org.atlassian.net) + JIRA_USER +
JIRA_API_TOKEN (personal API token from id.atlassian.com).

ops:
  - search(jql, limit)             — JQL query
  - get(issue_key)                 — fetch one (e.g. 'PROJ-123')
  - create(project, summary, ...)  — open an issue
  - comment(issue_key, body)
  - transition(issue_key, status)  — move state by name
"""
from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any

from . import Tool

log = logging.getLogger(__name__)

# A literal Jira issue key: project key (letter then letters/digits/_) + number.
_ISSUE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]+-\d+$")


def _require_key(issue_key: str) -> str:
    """Return ``issue_key`` if it is a literal ``PROJ-123`` token, else raise.

    The key is interpolated straight into the REST path. Without this guard a
    model-supplied value such as ``../myself`` or ``DEMO-1?expand=changelog``
    lets httpx normalize ``..`` / append a query and reach other authenticated
    Jira endpoints, so we validate the strict key shape and refuse anything else.
    """
    if not _ISSUE_KEY_RE.match(issue_key):
        raise ValueError(f"invalid issue_key {issue_key!r} (expected like 'PROJ-123')")
    return issue_key


_JIRA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "get", "create", "comment", "transition"],
        },
        "jql": {"type": "string", "description": "JQL (search op)."},
        "issue_key": {"type": "string", "description": "e.g. 'PROJ-123'."},
        "project": {"type": "string", "description": "Project key (create)."},
        "summary": {"type": "string", "description": "Title (create)."},
        "description": {"type": "string"},
        "issue_type": {"type": "string", "description": "e.g. 'Task' (default)."},
        "body": {"type": "string", "description": "Comment body."},
        "status": {"type": "string", "description": "Target status (transition)."},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str, str]:
    url = os.environ.get("JIRA_URL", "").strip().rstrip("/")
    user = os.environ.get("JIRA_USER", "").strip()
    tok = os.environ.get("JIRA_API_TOKEN", "").strip()
    if not url or not user or not tok:
        raise RuntimeError(
            "Jira requires JIRA_URL + JIRA_USER + JIRA_API_TOKEN."
        )
    return url, user, tok


def _auth_header(user: str, tok: str) -> dict:
    raw = f"{user}:{tok}".encode()
    return {
        "Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _client():
    import httpx

    from ..governed_http import GuardedClient
    url, user, tok = _config()
    # follow_redirects=False: the Basic-auth header is a client default, which
    # httpx does NOT strip on a cross-host redirect (only auth= is stripped),
    # so a 30x off JIRA_URL would replay the API token to another host.
    return url, GuardedClient(httpx.Client(
        headers=_auth_header(user, tok), timeout=30.0, follow_redirects=False,
    ))


def _search(jql: str, limit: int) -> str:
    url, client = _client()
    # Atlassian removed the old POST /rest/api/3/search (May 2025) in favour of
    # /search/jql, which paginates with an opaque nextPageToken instead of
    # startAt/maxResults totals. Follow the token until `limit` issues are
    # collected, bounded by a hard page cap.
    issues: list[dict] = []
    token: str | None = None
    max_pages = max(1, (limit // 100) + 2)
    with client:
        for _ in range(max_pages):
            body: dict = {
                "jql": jql,
                "maxResults": min(100, max(1, limit - len(issues))),
                "fields": ["summary", "status", "assignee", "priority"],
            }
            if token:
                body["nextPageToken"] = token
            resp = client.post(f"{url}/rest/api/3/search/jql", json=body)
            resp.raise_for_status()
            data = resp.json()
            issues.extend(data.get("issues") or [])
            token = data.get("nextPageToken")
            if len(issues) >= limit or not token:
                break
    issues = issues[:limit]
    if not issues:
        return "no matches"
    rows = []
    for i in issues:
        f = i.get("fields") or {}
        rows.append(
            f"  {i['key']}  [{(f.get('status') or {}).get('name', '?'):>12}]  "
            f"{(f.get('summary') or '')[:80]}"
        )
    return "\n".join(rows)


def _get(issue_key: str) -> str:
    _require_key(issue_key)
    url, client = _client()
    with client:
        resp = client.get(f"{url}/rest/api/3/issue/{issue_key}")
        if resp.status_code == 404:
            return f"issue {issue_key!r} not found"
        resp.raise_for_status()
        data = resp.json()
    f = data.get("fields") or {}
    desc = f.get("description")
    desc_text = ""
    if isinstance(desc, dict):
        # ADF (Atlassian Doc Format) — flatten paragraphs.
        for block in desc.get("content") or []:
            for run in block.get("content") or []:
                if run.get("type") == "text":
                    desc_text += run.get("text", "")
            desc_text += "\n"
    elif isinstance(desc, str):
        desc_text = desc
    return (
        f"{data.get('key')}  {f.get('summary', '')}\n"
        f"  status:   {(f.get('status') or {}).get('name', '?')}\n"
        f"  priority: {(f.get('priority') or {}).get('name', '?')}\n"
        f"  assignee: {(f.get('assignee') or {}).get('displayName', '(unassigned)')}\n"
        f"  type:     {(f.get('issuetype') or {}).get('name', '?')}\n"
        f"  url:      {url}/browse/{data.get('key')}\n\n"
        f"{desc_text[:5000]}"
    )


def _create(project: str, summary: str, description: str, issue_type: str) -> str:
    url, client = _client()
    payload = {
        "fields": {
            "project": {"key": project},
            "summary": summary,
            "issuetype": {"name": issue_type},
        },
    }
    if description:
        payload["fields"]["description"] = {
            "type": "doc", "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": description}],
            }],
        }
    with client:
        resp = client.post(f"{url}/rest/api/3/issue", json=payload)
        if resp.status_code >= 400:
            return f"ERROR: jira create failed ({resp.status_code}): {resp.text[:300]}"
        data = resp.json()
    return f"created {data.get('key')}: {url}/browse/{data.get('key')}"


def _comment(issue_key: str, body: str) -> str:
    _require_key(issue_key)
    url, client = _client()
    payload = {
        "body": {
            "type": "doc", "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": body}],
            }],
        },
    }
    with client:
        resp = client.post(f"{url}/rest/api/3/issue/{issue_key}/comment", json=payload)
        if resp.status_code >= 400:
            return f"ERROR: jira comment failed ({resp.status_code}): {resp.text[:300]}"
    return f"commented on {issue_key}"


def _transition(issue_key: str, target_status: str) -> str:
    _require_key(issue_key)
    url, client = _client()
    with client:
        # Fetch valid transitions, pick by name.
        resp = client.get(f"{url}/rest/api/3/issue/{issue_key}/transitions")
        resp.raise_for_status()
        transitions = resp.json().get("transitions") or []
        target = next(
            (t for t in transitions if (t.get("to") or {}).get("name", "").lower() == target_status.lower()),
            None,
        )
        if not target:
            names = ", ".join(
                (t.get("to") or {}).get("name", "?") for t in transitions
            )
            return f"ERROR: no transition to {target_status!r}. Available: {names}"
        resp = client.post(
            f"{url}/rest/api/3/issue/{issue_key}/transitions",
            json={"transition": {"id": target["id"]}},
        )
        if resp.status_code >= 400:
            return f"ERROR: transition failed ({resp.status_code}): {resp.text[:300]}"
    return f"transitioned {issue_key} -> {target_status}"


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
                (args.get("jql") or "").strip() or "order by updated DESC",
                max(1, min(int(args.get("limit") or 25), 100)),
            )
        if op == "get":
            iid = (args.get("issue_key") or "").strip()
            if not iid:
                return "ERROR: get requires issue_key"
            return _get(iid)
        if op == "create":
            project = (args.get("project") or "").strip()
            summary = (args.get("summary") or "").strip()
            if not project or not summary:
                return "ERROR: create requires project and summary"
            return _create(
                project, summary,
                args.get("description") or "",
                (args.get("issue_type") or "Task").strip(),
            )
        if op == "comment":
            iid = (args.get("issue_key") or "").strip()
            body = args.get("body") or ""
            if not iid or not body:
                return "ERROR: comment requires issue_key and body"
            return _comment(iid, body)
        if op == "transition":
            iid = (args.get("issue_key") or "").strip()
            status = (args.get("status") or "").strip()
            if not iid or not status:
                return "ERROR: transition requires issue_key and status"
            return _transition(iid, status)
    except (RuntimeError, ValueError) as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Jira request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def jira() -> Tool:
    return Tool(
        name="jira",
        description=(
            "Read / write Jira issues via REST v3. ops: search (JQL), "
            "get (by key like 'PROJ-123'), create (project + summary "
            "+ optional description / issue_type), comment (key + "
            "body), transition (key + status name). Auth via JIRA_URL "
            "+ JIRA_USER + JIRA_API_TOKEN."
        ),
        input_schema=_JIRA_SCHEMA,
        fn=_run,
    )
