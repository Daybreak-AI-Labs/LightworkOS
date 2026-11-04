"""Fresh-process browser smoke test for every governed static UI route."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
CORE_ROOT = REPO_ROOT / "packages" / "maverick-core"


_CHILD_SCRIPT = r"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from maverick_dashboard import app as dashboard_app
from maverick_dashboard import settings_store, ui_visibility
from maverick_dashboard.route_identity import iter_compatible_route_contexts


report_path = Path(sys.argv[1])
client = TestClient(
    dashboard_app.app,
    base_url="http://127.0.0.1",
    headers={"Origin": "http://127.0.0.1"},
    raise_server_exceptions=False,
)
failures: list[str] = []
# Auth-off plus a selected active tenant renders each enabled destination.
# If a page adds an intentional redirect or client-error feature gate,
# document that contract here rather
# than allowing every 3xx/4xx to conceal a broken destination.
DOCUMENTED_STATUS_GATES: dict[str, set[int]] = {
    # These workflows are explicitly opt-in; team reviews also require a
    # named human account, which this auth-off smoke does not impersonate.
    "/project-reviews": {403},
    "/outcome-pilots": {403},
    # Research jobs and governed knowledge access bind every page view to a
    # named account plus a selected workspace, so the auth-off smoke is
    # refused by design.
    "/research": {403},
    "/knowledge-access": {403},
    # These opt-in personal surfaces require a named account; the smoke's
    # local installation credential intentionally cannot impersonate one.
    "/companion": {403},
    "/companion/admin": {403},
    "/deliverable-bundles": {403},
    "/preferences": {403},
    "/task-handoffs": {403},
    "/today": {403},
    "/my-data": {403},
    "/content-access": {403},
    "/notifications": {403},
    "/access-requests": {403},
    "/devices": {403},
    # Human conversation handoff binds every view to the named person who
    # takes or shares the conversation (human_conversation_handoffs.authority).
    "/human-conversations": {403},
    # Employee activation is also switched off by default.
    "/get-started/employee": {403},
    # Owned-rule and learning-review pages show only the signed-in person's
    # own work, so the auth-off smoke gets their sign-in page.
    "/learning/recheck-rules": {403},
    "/learning/distinctions": {403},
    "/learning/rules-together": {403},
    "/learning/request-program": {403},
    "/learning/applicability": {403},
    "/learning/recovery-visibility": {403},
    "/learning/portable-rules": {403},
    "/learning/work-restructuring": {403},
    "/learning/approval-challenges": {403},
    "/learning/instructions": {403},
    "/learning/rule-evolution": {401},
    "/learning/acquisition": {401},
    # Task mapping is switched off by default.
    "/compliance/scope-actions/mapping": {403},
}

created = client.post(
    "/api/v1/admin/tenants",
    json={"id": "fresh-html-smoke", "plan": "enterprise"},
)
if created.status_code != 201:
    failures.append(
        f"tenant creation returned {created.status_code}: {created.text[:300]}"
    )
selected = client.put(
    "/api/v1/workspace/active-tenant",
    json={"tenant_id": "fresh-html-smoke"},
)
if selected.status_code != 200:
    failures.append(
        f"tenant selection returned {selected.status_code}: {selected.text[:300]}"
    )

pages = tuple(page["path"] for page in ui_visibility.PAGES)
if len(pages) != len(set(pages)):
    failures.append("ui_visibility.PAGES contains duplicate paths")

registered_get: set[str] = set()
for route in iter_compatible_route_contexts(dashboard_app.app.routes):
    path = getattr(route, "path", None)
    methods = set(getattr(route, "methods", ()) or ())
    if isinstance(path, str) and "GET" in methods:
        registered_get.add(path)
missing_routes = sorted(set(pages) - registered_get)
if missing_routes:
    failures.append(f"PAGES entries without an exact GET route: {missing_routes}")

statuses: dict[str, int] = {}
content_types: dict[str, str] = {}
settings_html = ""
for path in pages:
    response = client.get(
        path,
        headers={"Accept": "text/html", "Origin": "http://127.0.0.1"},
        follow_redirects=False,
    )
    statuses[path] = response.status_code
    content_type = response.headers.get("content-type", "")
    content_types[path] = content_type
    if path == "/settings":
        settings_html = response.text
    allowed_statuses = {200, *DOCUMENTED_STATUS_GATES.get(path, set())}
    if response.status_code >= 500:
        failures.append(f"{path} returned {response.status_code}")
    if response.status_code in {404, 405}:
        failures.append(
            f"{path} is registered as a UI page but returned {response.status_code}"
        )
    elif response.status_code not in allowed_statuses:
        failures.append(
            f"{path} returned undocumented status {response.status_code}; "
            "add only an intentional route gate to DOCUMENTED_STATUS_GATES"
        )
    if not 300 <= response.status_code < 400 and not content_type.startswith("text/html"):
        failures.append(
            f"{path} returned non-HTML content type {content_type!r} "
            f"for status {response.status_code}"
        )
    if response.status_code == 500 or (
        response.status_code < 300
        and "The dashboard caught an unexpected error" in response.text
    ):
        failures.append(f"{path} rendered the unhandled-error page")

if "/settings" not in pages:
    failures.append("/settings is missing from ui_visibility.PAGES")
if statuses.get("/settings") != 200:
    failures.append(f"/settings returned {statuses.get('/settings')}")
for spec in settings_store.PROVIDERS:
    marker = f'name="provider" value="{spec["name"]}"'
    if marker not in settings_html:
        failures.append(f"/settings omitted provider row {spec['name']!r}")

report = {
    "dashboard_import": str(Path(dashboard_app.__file__).resolve()),
    "page_count": len(pages),
    "statuses": statuses,
    "content_types": content_types,
    "failures": failures,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
print(json.dumps(statuses, sort_keys=True))
if failures:
    raise SystemExit(1)
"""


def _fresh_process_env(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "profile"
    state = tmp_path / "state"
    config_path = state / "config.toml"
    state.mkdir(parents=True)
    config_path.write_text(
        "[dashboard]\nrequire_auth = false\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("MAVERICK_OIDC_"):
            env.pop(name, None)
    for name in (
        "MAVERICK_CLIENT_CONFIG",
        "MAVERICK_CONFIG_OVERLAY",
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_INVITES",
        "MAVERICK_DASHBOARD_SESSION_SECRET",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_PROXY_AUTH_HEADER",
        "MAVERICK_TENANT",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
        "MOONSHOT_API_KEY",
        "DEEPSEEK_API_KEY",
        "XAI_API_KEY",
        "GROK_API_KEY",
        "VLLM_BASE_URL",
        "OPENAI_COMPATIBLE_BASE_URL",
    ):
        env.pop(name, None)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "MAVERICK_HOME": str(state),
            "MAVERICK_CONFIG": str(config_path),
            "MAVERICK_DASHBOARD_REQUIRE_AUTH": "0",
            "MAVERICK_ENTERPRISE": "0",
            "MAVERICK_SECURE_DEFAULT": "0",
            "MAVERICK_AUDIT_SIGN": "0",
            "MAVERICK_VOICE_AUTO_FETCH": "0",
            "PYTHONPATH": os.pathsep.join((str(PACKAGE_ROOT), str(CORE_ROOT))),
        }
    )
    return env


def test_every_registered_static_page_survives_fresh_html_process(
    tmp_path: Path,
) -> None:
    script_path = tmp_path / "fresh_html_smoke.py"
    report_path = tmp_path / "fresh_html_smoke_report.json"
    script_path.write_text(_CHILD_SCRIPT, encoding="utf-8")

    completed = subprocess.run(  # noqa: S603 - exact interpreter + generated script
        [sys.executable, str(script_path), str(report_path)],
        cwd=REPO_ROOT,
        env=_fresh_process_env(tmp_path),
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    report = (
        json.loads(report_path.read_text(encoding="utf-8"))
        if report_path.exists()
        else {}
    )

    assert completed.returncode == 0, (
        f"fresh-process UI smoke failed\nreport={json.dumps(report, indent=2)}\n"
        f"stdout={completed.stdout}\nstderr={completed.stderr}"
    )
    assert report["page_count"] == len(report["statuses"])
    assert report["page_count"] >= 100
    assert report["failures"] == []
    assert Path(report["dashboard_import"]).is_relative_to(PACKAGE_ROOT)
