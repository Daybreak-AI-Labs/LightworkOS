"""Vercel tool — deployments + projects + domains.

Auth: ``VERCEL_TOKEN`` (account / personal token).
``VERCEL_TEAM_ID`` optional (scopes calls to a team).

ops:
  - projects(limit)
  - deployments(project_id, limit)
  - deployment_get(deployment_id)
  - deployment_logs(deployment_id, limit)
  - cancel(deployment_id, confirm)
  - domains(project_id)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_VC_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["projects", "deployments", "deployment_get",
                     "deployment_logs", "cancel", "domains"],
        },
        "project_id": {"type": "string"},
        "deployment_id": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.vercel.com"


def _token() -> str:
    t = os.environ.get("VERCEL_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Vercel requires VERCEL_TOKEN.")
    return t


def _team() -> str:
    return os.environ.get("VERCEL_TEAM_ID", "").strip()


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _params_with_team(params: dict) -> dict:
    t = _team()
    if t:
        params = dict(params)
        params["teamId"] = t
    return params


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=_params_with_team(params or {}), timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _patch(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.patch)(f"{_API}{path}", headers=_headers(),
                    json=body, params=_params_with_team({}), timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_projects(args: dict) -> str:
    code, data = _get("/v9/projects",
                       {"limit": max(1, min(int(args.get("limit") or 20), 100))})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: projects ({code}): {data}"
    rows = data.get("projects") or []
    if not rows:
        return "no projects"
    return "\n".join(
        f"  {p.get('id')}  {(p.get('name') or '?'):<30}  "
        f"framework={p.get('framework', '?')}  "
        f"latest={(p.get('latestDeployments') or [{}])[0].get('readyState', '?')}"
        for p in rows
    )


def _op_deployments(args: dict) -> str:
    params = {"limit": max(1, min(int(args.get("limit") or 20), 100))}
    pid = (args.get("project_id") or "").strip()
    if pid:
        params["projectId"] = pid
    code, data = _get("/v6/deployments", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: deployments ({code}): {data}"
    rows = data.get("deployments") or []
    if not rows:
        return "no deployments"
    return "\n".join(
        f"  {d.get('uid')}  [{d.get('state', '?'):>10}]  "
        f"{(d.get('name') or '?'):<30}  {d.get('source', '?'):>8}  "
        f"created={d.get('created')}"
        for d in rows
    )


def _op_deployment_get(args: dict) -> str:
    did = (args.get("deployment_id") or "").strip()
    if not did:
        return "ERROR: deployment_get requires deployment_id"
    seg = safe_path_segment(did)
    if seg is None:
        return "ERROR: deployment_get requires a valid deployment_id"
    code, data = _get(f"/v13/deployments/{seg}")
    if code == 404:
        return f"deployment {did} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: deployment_get ({code}): {data}"
    return (
        f"{data.get('id') or data.get('uid')}  state={data.get('readyState') or data.get('state')}\n"
        f"  name:     {data.get('name')}\n"
        f"  url:      https://{data.get('url')}\n"
        f"  created:  {data.get('created')}\n"
        f"  source:   {data.get('source')}\n"
        f"  meta:     {(data.get('meta') or {})}"
    )


def _op_deployment_logs(args: dict) -> str:
    did = (args.get("deployment_id") or "").strip()
    if not did:
        return "ERROR: deployment_logs requires deployment_id"
    seg = safe_path_segment(did)
    if seg is None:
        return "ERROR: deployment_logs requires a valid deployment_id"
    limit = max(1, min(int(args.get("limit") or 100), 1000))
    code, data = _get(f"/v2/deployments/{seg}/events", {"limit": limit})
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: deployment_logs ({code}): {data}"
    if not data:
        return "no log events"
    return "\n".join(
        f"  {ev.get('created')}  [{ev.get('type', '?'):>10}]  "
        f"{(ev.get('payload') or {}).get('text', '')[:200]}"
        for ev in data
    )


def _op_cancel(args: dict) -> str:
    did = (args.get("deployment_id") or "").strip()
    if not did:
        return "ERROR: cancel requires deployment_id"
    seg = safe_path_segment(did)
    if seg is None:
        return "ERROR: cancel requires a valid deployment_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would cancel deployment {did}. Re-run with confirm=true."
    code, data = _patch(f"/v12/deployments/{seg}/cancel", {})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: cancel ({code}): {data}"
    return f"cancelled {did} (state={data.get('readyState') or data.get('state')})"


def _op_domains(args: dict) -> str:
    pid = (args.get("project_id") or "").strip()
    if not pid:
        return "ERROR: domains requires project_id"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: domains requires a valid project_id"
    code, data = _get(f"/v9/projects/{seg}/domains")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: domains ({code}): {data}"
    rows = data.get("domains") or []
    if not rows:
        return "no domains"
    return "\n".join(
        f"  {(d.get('name') or '?'):<40}  verified={d.get('verified')}  "
        f"git_branch={d.get('gitBranch', '?')}"
        for d in rows
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "projects":        _op_projects,
            "deployments":     _op_deployments,
            "deployment_get":  _op_deployment_get,
            "deployment_logs": _op_deployment_logs,
            "cancel":          _op_cancel,
            "domains":         _op_domains,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Vercel request failed: {type(e).__name__}: {e}"


def vercel_tool() -> Tool:
    return Tool(
        name="vercel",
        description=(
            "Vercel deployments + projects. ops: projects, "
            "deployments, deployment_get, deployment_logs, cancel "
            "(confirm=true), domains. Auth: VERCEL_TOKEN + "
            "optional VERCEL_TEAM_ID."
        ),
        input_schema=_VC_SCHEMA,
        fn=_run,
    )
