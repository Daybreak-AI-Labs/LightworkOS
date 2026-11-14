"""GitHub Actions tool — workflow runs + dispatches.

Direct REST API access (separate from MCP github tools) so the agent
can: list recent runs, watch a specific run, cancel a hanging run,
or trigger a workflow on-demand via workflow_dispatch.

Auth: ``GITHUB_TOKEN`` (PAT or installation token with ``actions:read``
plus ``actions:write`` for dispatch / cancel).

ops:
  - runs(owner, repo, workflow, branch, status, limit)
  - run_get(owner, repo, run_id)
  - jobs(owner, repo, run_id)
  - dispatch(owner, repo, workflow, ref, inputs, confirm)
  - cancel(owner, repo, run_id, confirm)
  - workflows(owner, repo)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_GHA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["runs", "run_get", "jobs", "dispatch",
                     "cancel", "workflows"],
        },
        "owner": {"type": "string"},
        "repo": {"type": "string"},
        "workflow": {
            "type": "string",
            "description": "Workflow file name (e.g. 'ci.yml') or id.",
        },
        "branch": {"type": "string"},
        "status": {"type": "string"},
        "ref": {"type": "string", "description": "Branch / tag (dispatch)."},
        "inputs": {"type": "object", "description": "Workflow inputs (dispatch)."},
        "run_id": {"type": "integer"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _token() -> str:
    t = (
        os.environ.get("GITHUB_TOKEN", "")
        or os.environ.get("GH_TOKEN", "")
    ).strip()
    if not t:
        raise RuntimeError(
            "GitHub Actions requires GITHUB_TOKEN (PAT) or GH_TOKEN."
        )
    return t


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"https://api.github.com{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"https://api.github.com{path}", headers=_headers(),
                   json=body or {}, timeout=30.0)
    try:
        return r.status_code, r.json() if r.text else {}
    except ValueError:
        return r.status_code, r.text[:300]


def _slug(args: dict) -> tuple[str, str] | str:
    owner = (args.get("owner") or "").strip()
    repo = (args.get("repo") or "").strip()
    if not owner or not repo:
        return "ERROR: owner and repo are required"
    owner_seg, repo_seg = safe_path_segment(owner), safe_path_segment(repo)
    if owner_seg is None or repo_seg is None:
        return "ERROR: owner and repo must be valid path segments"
    return owner_seg, repo_seg


def _op_runs(args: dict) -> str:
    res = _slug(args)
    if isinstance(res, str):
        return res
    owner, repo = res
    workflow = (args.get("workflow") or "").strip()
    base = f"/repos/{owner}/{repo}/actions"
    if workflow:
        wf_seg = safe_path_segment(workflow)
        if wf_seg is None:
            return "ERROR: runs requires a valid workflow"
        path = f"{base}/workflows/{wf_seg}/runs"
    else:
        path = f"{base}/runs"
    params: dict = {"per_page": max(1, min(int(args.get("limit") or 20), 100))}
    if args.get("branch"):
        params["branch"] = args["branch"]
    if args.get("status"):
        params["status"] = args["status"]
    code, data = _get(path, params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: runs ({code}): {data}"
    rows = data.get("workflow_runs") or []
    if not rows:
        return "no runs"
    return "\n".join(
        f"  {r.get('id'):>12}  [{r.get('status', '?'):>10}]  "
        f"{r.get('conclusion') or '-':>10}  "
        f"{(r.get('name') or '')[:30]:<30}  "
        f"{r.get('head_branch', '?')}  {r.get('event', '?')}"
        for r in rows
    )


def _op_run_get(args: dict) -> str:
    res = _slug(args)
    if isinstance(res, str):
        return res
    owner, repo = res
    rid = int(args.get("run_id") or 0)
    if not rid:
        return "ERROR: run_get requires run_id"
    code, data = _get(f"/repos/{owner}/{repo}/actions/runs/{rid}")
    if code == 404:
        return f"run {rid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: run_get ({code}): {data}"
    return (
        f"#{data.get('id')}  status={data.get('status')}  "
        f"conclusion={data.get('conclusion')}\n"
        f"  workflow: {data.get('name')}\n"
        f"  branch:   {data.get('head_branch')}\n"
        f"  event:    {data.get('event')}\n"
        f"  started:  {data.get('run_started_at')}\n"
        f"  updated:  {data.get('updated_at')}\n"
        f"  url:      {data.get('html_url')}"
    )


def _op_jobs(args: dict) -> str:
    res = _slug(args)
    if isinstance(res, str):
        return res
    owner, repo = res
    rid = int(args.get("run_id") or 0)
    if not rid:
        return "ERROR: jobs requires run_id"
    code, data = _get(f"/repos/{owner}/{repo}/actions/runs/{rid}/jobs")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: jobs ({code}): {data}"
    rows = data.get("jobs") or []
    if not rows:
        return "no jobs"
    return "\n".join(
        f"  {j.get('id'):>14}  [{j.get('status', '?'):>10}]  "
        f"{j.get('conclusion') or '-':>10}  {(j.get('name') or '')[:60]}"
        for j in rows
    )


def _op_dispatch(args: dict) -> str:
    res = _slug(args)
    if isinstance(res, str):
        return res
    owner, repo = res
    workflow = (args.get("workflow") or "").strip()
    ref = (args.get("ref") or "main").strip()
    if not workflow:
        return "ERROR: dispatch requires workflow"
    wf_seg = safe_path_segment(workflow)
    if wf_seg is None:
        return "ERROR: dispatch requires a valid workflow"
    if not as_bool(args.get("confirm")):
        return (
            f"DRY RUN: would dispatch {workflow}@{ref} in {owner}/{repo}. "
            "Re-run with confirm=true."
        )
    inputs = args.get("inputs") if isinstance(args.get("inputs"), dict) else {}
    code, data = _post(
        f"/repos/{owner}/{repo}/actions/workflows/{wf_seg}/dispatches",
        {"ref": ref, "inputs": {str(k): str(v) for k, v in inputs.items()}},
    )
    if code >= 400:
        return f"ERROR: dispatch ({code}): {data}"
    return f"dispatched {workflow}@{ref}"


def _op_cancel(args: dict) -> str:
    res = _slug(args)
    if isinstance(res, str):
        return res
    owner, repo = res
    rid = int(args.get("run_id") or 0)
    if not rid:
        return "ERROR: cancel requires run_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would cancel run {rid}. Re-run with confirm=true."
    code, data = _post(f"/repos/{owner}/{repo}/actions/runs/{rid}/cancel")
    if code >= 400:
        return f"ERROR: cancel ({code}): {data}"
    return f"cancelled run {rid}"


def _op_workflows(args: dict) -> str:
    res = _slug(args)
    if isinstance(res, str):
        return res
    owner, repo = res
    code, data = _get(f"/repos/{owner}/{repo}/actions/workflows")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: workflows ({code}): {data}"
    rows = data.get("workflows") or []
    if not rows:
        return "no workflows"
    return "\n".join(
        f"  {w.get('id'):>10}  [{w.get('state', '?'):>8}]  "
        f"{(w.get('name') or '')[:40]:<40}  {w.get('path')}"
        for w in rows
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
            "runs":      _op_runs,
            "run_get":   _op_run_get,
            "jobs":      _op_jobs,
            "dispatch":  _op_dispatch,
            "cancel":    _op_cancel,
            "workflows": _op_workflows,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: GitHub Actions request failed: {type(e).__name__}: {e}"


def github_actions() -> Tool:
    return Tool(
        name="github_actions",
        description=(
            "GitHub Actions REST. ops: runs (workflow + branch + "
            "status filters), run_get, jobs, dispatch "
            "(workflow_dispatch with inputs; confirm=true required), "
            "cancel (confirm=true), workflows (list). Auth: "
            "GITHUB_TOKEN / GH_TOKEN with actions:read[+write]."
        ),
        input_schema=_GHA_SCHEMA,
        fn=_run,
    )
