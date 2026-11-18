"""Single-computer features never answer with a server error on a shared deployment.

Some features keep their records only on a single-computer installation: their
record collections are pinned with ``required_backend="local"``. On a
deployment whose saved records live in shared Postgres, those collections
refuse before any I/O. The live site answered that refusal with 500 or 503 on
about twenty reads, so pages stayed on "Checking current choices..." and the
Copilot catalog for /learning failed whole.

The routes checked here are found from the code, not listed by hand: every
dashboard module that pins a collection to the local backend (or imports a
core module that does), and every GET route whose handler uses one of those
modules. Each route is called on a simulated shared deployment. A request that
met a single-computer refusal must not answer 5xx.

The deployment is simulated by the governed-record selector alone (Postgres
with an address nothing listens on); no database is opened, because the
refusal happens before any I/O.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import re
import textwrap
from pathlib import Path

import maverick
import maverick_dashboard
import pytest
from fastapi.testclient import TestClient
from maverick import config, governed_records, world_model
from maverick.candidate_promotion import CandidatePromotionUnavailable
from maverick.governed_records import GovernedRecordLocalOnly
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import auth, product_operations, rbac, workspace_tenants
from maverick_dashboard.app import app
from maverick_dashboard.route_identity import iter_compatible_route_contexts

TENANT = "single-computer-routes"
OWNER = "user:alice"
SHARED_DSN = "postgresql://lightwork@127.0.0.1:9/shared-deployment-simulation"
_LOCAL_PIN = re.compile(r"required_backend\s*=\s*[\"']local[\"']")

# The reads the live Postgres site answered with 500 or 503 (CloudWatch and the
# page sweep, 2026-11-18). Each must now read as plainly unavailable.
LIVE_READS = (
    "/api/v1/learning/rule-requalification/history",
    "/api/v1/learning/rules-together/history",
    "/api/v1/learning/applicability/history",
    "/api/v1/learning/portable-rules/history",
    "/api/v1/learning/work-restructuring/history",
    "/api/v1/learning/request-program",
    "/api/v1/learning/approval-challenges?offset=0",
    "/api/v1/learning/instructions",
    "/api/v1/research/local-flow-release",
    "/api/v1/generated-tool-removals",
    "/api/v1/private-task-computation/history",
    "/api/v1/governed-rule-evolution/history",
    "/api/v1/operator-acquisition/history",
)


def _package_imports(tree: ast.AST, package: str) -> set[str]:
    """Top-level module names of ``package`` that ``tree`` imports."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1:
                found.update([node.module.split(".")[0]] if node.module else
                             [alias.name for alias in node.names])
            elif node.level == 0 and node.module == package:
                found.update(alias.name for alias in node.names)
            elif node.level == 0 and node.module and node.module.startswith(package + "."):
                found.add(node.module.split(".")[1])
        elif isinstance(node, ast.Import):
            found.update(alias.name.split(".")[1] for alias in node.names
                         if alias.name.startswith(package + "."))
    return found


def _local_only_modules() -> set[str]:
    """Dashboard modules that open a collection kept only on a single computer."""
    core = Path(maverick.__file__).parent
    dashboard = Path(maverick_dashboard.__file__).parent
    core_local = {path.stem for path in core.glob("*.py") if _LOCAL_PIN.search(path.read_text(encoding="utf-8"))}
    local = set()
    for path in dashboard.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if _LOCAL_PIN.search(text) or _package_imports(ast.parse(text), "maverick") & core_local:
            local.add(path.stem)
    return local


def _uses_local_only(endpoint, local: set[str]) -> bool:
    """Whether a route handler's own module or own code uses a local-only module."""
    module = endpoint.__module__.rsplit(".", 1)[-1]
    if not endpoint.__module__.startswith("maverick_dashboard."):
        return False
    if module in local:
        return True
    source = Path(inspect.getsourcefile(endpoint)).read_text(encoding="utf-8")
    aliases = set()
    for node in ast.parse(source).body:
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            for alias in node.names:
                target = node.module.split(".")[0] if node.module else alias.name
                if target in local:
                    aliases.add(alias.asname or alias.name)
    body = ast.parse(textwrap.dedent(inspect.getsource(endpoint)))
    if _package_imports(body, "maverick_dashboard") & local:
        return True
    return any(isinstance(node, ast.Name) and node.id in aliases for node in ast.walk(body))


def _concrete(path: str) -> str:
    return re.sub(r"\{(\w+)(?::(\w+))?\}",
                  lambda match: "1" if match.group(2) == "int" else "missing-" + match.group(1), path)


def local_only_reads() -> list[str]:
    local = _local_only_modules()
    paths = set()
    for route in iter_compatible_route_contexts(app.routes):
        endpoint = getattr(route, "endpoint", None)
        if (endpoint is None or "GET" not in (getattr(route, "methods", None) or ())
                or not route.path.startswith("/api/")):
            continue
        if _uses_local_only(endpoint, local):
            paths.add(_concrete(route.path))
    return sorted(paths)


@pytest.fixture
def shared(tmp_path, monkeypatch, request):
    """A named workspace administrator on a deployment whose records are shared."""
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    key = hashlib.sha256(("single-computer-routes:" + request.node.nodeid).encode()).digest()
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    for name in ("MAVERICK_TENANT", "MAVERICK_REPLICA_COUNT", "MAVERICK_GOVERNED_RECORDS_BACKEND",
                 "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    from maverick import crypto_at_rest

    crypto_at_rest._reset_shared_key_identity_for_testing()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda actor: actor == OWNER)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **_kw: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token}))
    config.reset_config_cache()
    from maverick.tenant.registry import create_tenant, get_tenant

    if get_tenant(TENANT) is None:
        create_tenant(TENANT)
    rbac.set_role(OWNER, "admin", actor=OWNER)
    rbac.set_tenant_role(TENANT, OWNER, "admin", actor=OWNER)
    workspace_tenants.set_selection(OWNER, TENANT)
    # Only the saved-record selector says "shared"; the world stays local.
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", SHARED_DSN)
    governed_records._reset_process_authority_pin_for_testing()
    refused: list[str] = []
    original_local_only = GovernedRecordLocalOnly.__init__
    original_unavailable = CandidatePromotionUnavailable.__init__

    def local_only(self, *args, **kwargs):
        refused.append(type(self).__name__)
        original_local_only(self, *args, **kwargs)

    def unavailable(self, *args, **kwargs):
        if args and "single-computer" in str(args[0]):
            refused.append(type(self).__name__)
        original_unavailable(self, *args, **kwargs)

    monkeypatch.setattr(GovernedRecordLocalOnly, "__init__", local_only)
    monkeypatch.setattr(CandidatePromotionUnavailable, "__init__", unavailable)
    client = TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False,
                        headers={"Origin": "http://127.0.0.1", "Authorization": "Bearer " + OWNER.removeprefix("user:"),
                                 "X-Lightwork-Expected-Tenant": TENANT})
    yield client, refused, tmp_path / "config.toml"
    governed_records._reset_process_authority_pin_for_testing()
    crypto_at_rest._reset_shared_key_identity_for_testing()
    config.reset_config_cache()


def _features_on(path: Path) -> None:
    """Turn on every product feature switch, so no read stops at "turned off" first."""
    names = sorted(name for name, value in config.get_features().items() if isinstance(value, bool))
    path.write_text("[features]\n" + "".join(f"{name} = true\n" for name in names)
                    + '\n[copilot]\noperation_families = ["learning"]\n', encoding="utf-8")
    config.reset_config_cache()


def test_the_route_list_comes_from_the_code_and_covers_the_live_failures():
    paths = local_only_reads()
    assert len(paths) >= 30, paths
    for live in LIVE_READS:
        assert live.split("?")[0] in paths, live


@pytest.mark.parametrize("features", ["default", "all on"])
def test_no_local_only_read_answers_a_server_error_on_a_shared_deployment(shared, features):
    client, refused, config_path = shared
    if features == "all on":
        _features_on(config_path)
    failures = []
    met = set()
    for path in local_only_reads():
        refused.clear()
        response = client.get(path)
        if refused:
            met.add(path)
            if response.status_code >= 500:
                failures.append(f"{response.status_code} {path}: {response.text[:160]}")
    assert not failures, "\n".join(failures)
    # The simulation must reach the stores, or the check above proves nothing.
    assert len(met) >= 10, sorted(met)


def test_the_live_reads_say_plainly_that_the_feature_needs_a_single_computer(shared):
    client, _refused, config_path = shared
    _features_on(config_path)
    for path in LIVE_READS:
        response = client.get(path)
        assert response.status_code == 200, (path, response.status_code, response.text[:300])
        value = response.json()
        assert value["available"] is False, path
        assert "single-computer installation" in value["message"], path


@pytest.mark.parametrize("features", ["default", "all on"])
def test_the_copilot_catalog_never_fails_whole_on_a_shared_deployment(shared, features):
    client, _refused, config_path = shared
    if features == "all on":
        _features_on(config_path)
    pages = sorted({page for adapter in product_operations.adapters().values()
                    for page in adapter.pages if "*" not in page and page.startswith("/")})
    for page in ["/learning", *pages]:
        response = client.post("/api/v1/copilot/product-operations/catalog", json={"page": page})
        assert response.status_code < 500, (page, response.status_code, response.text[:300])
    learning = client.post("/api/v1/copilot/product-operations/catalog", json={"page": "/learning"})
    assert learning.status_code == 200, learning.text


def test_a_local_only_write_is_refused_plainly_not_as_a_server_error(shared):
    client, refused, config_path = shared
    _features_on(config_path)
    writes = {
        "/api/v1/generated-tool-removals/review": ("/api/v1/generated-tool-removals", {
            "tool": "a" * 64, "action": "remove"}),
        "/api/v1/learning/rule-requalification/review": ("/api/v1/learning/rule-requalification/history", {
            "kind": "recheck", "flow": "missing", "evidence": "missing"}),
    }
    met = []
    for path, (read, body) in writes.items():
        context = client.get(read).json()["context"]
        refused.clear()
        response = client.post(path, json={"context": context, **body})
        if refused:
            met.append(path)
            assert response.status_code == 409, (path, response.text)
            assert "single-computer installation" in response.json()["detail"], path
            assert response.json()["available"] is False, path
    assert met, "no write reached a single-computer store"


def test_a_single_computer_page_shows_the_message_instead_of_its_controls(shared):
    client, _refused, config_path = shared
    _features_on(config_path)
    for page in ("/learning/recheck-rules", "/learning/rules-together", "/learning/applicability",
                 "/learning/portable-rules", "/learning/work-restructuring", "/learning/request-program",
                 "/learning/flow-checks", "/learning/rule-evolution", "/learning/acquisition",
                 "/learning/instructions", "/learning/approval-challenges", "/private-task-computation"):
        response = client.get(page, headers={"Accept": "text/html"})
        assert response.status_code == 200, (page, response.status_code)
        assert "needs a single-computer installation of Lightwork" in response.text, page
        assert "<form" not in response.text.split("<main", 1)[-1].split("</main>", 1)[0], page
