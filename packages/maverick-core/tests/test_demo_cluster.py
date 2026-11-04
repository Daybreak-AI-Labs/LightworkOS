"""Contract tests for the public read-only demo blueprint
(deploy/reference-architectures/demo-cluster). Same posture as
test_reference_architectures.py: static validation that the artifacts parse,
agree on the canonical port/image/state path, enforce the read-only proxy
posture, and bake in no secrets. PyYAML isn't a core dep, so YAML files get
light regex contracts."""
from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DC = _REPO_ROOT / "deploy" / "reference-architectures" / "demo-cluster"
_PORT = "8765"
_STATE = "/home/maverick/.maverick"


def test_compose_invariants():
    text = (_DC / "docker-compose.yml").read_text(encoding="utf-8")
    # The three services and the canonical dashboard contract.
    for service in ("seed:", "dashboard:", "proxy:"):
        assert service in text
    assert 'command: ["dashboard", "--host", "0.0.0.0", "--port", "8765"]' in text
    assert "dockerfile: deploy/docker/Dockerfile" in text
    assert f"demo-state:{_STATE}" in text
    assert "restart: unless-stopped" in text
    # Resource limits on the long-running services.
    assert text.count("memory:") >= 2 and text.count("cpus:") >= 2
    # The dashboard must never be published on the host; only nginx is.
    assert f'- "{_PORT}"' in text          # expose (container-network only)
    assert f'"{_PORT}:{_PORT}"' not in text  # no host port mapping
    assert '- "8080:8080"' in text
    # Token comes from the environment, never a literal.
    assert "${MAVERICK_DASHBOARD_TOKEN:?" in text


def test_nginx_template_is_a_path_allowlist_proxy():
    text = (_DC / "nginx.conf.template").read_text(encoding="utf-8")
    assert "location = /demo" in text
    assert "location = /healthz" in text
    assert "return 302 /demo" in text
    assert re.search(r"location\s+/\s*\{\s*return\s+404;", text)
    assert text.count("limit_except GET HEAD") == 2
    # Bearer injected only on the redacted demo page; visitors never see it.
    assert text.count('proxy_set_header Authorization "Bearer ${MAVERICK_DASHBOARD_TOKEN}"') == 1
    assert f"proxy_pass http://dashboard:{_PORT}" in text


def test_seed_script_compiles_and_uses_the_real_world_model_api():
    path = _DC / "seed_demo.py"
    source = path.read_text(encoding="utf-8")
    compile(source, str(path), "exec")  # raises on syntax errors
    assert "from maverick.world_model import" in source
    assert "create_goal" in source and "set_goal_status" in source
    assert 'owner="demo"' in source
    # Only statuses the world model actually writes; nothing left 'active'.
    assert '"failed"' not in source
    for status in ('"done"', '"blocked"', '"cancelled"'):
        assert status in source


def test_k8s_manifest_invariants():
    text = (_DC / "k8s.yaml").read_text(encoding="utf-8")
    docs = [d for d in text.split("\n---\n") if d.strip()]
    # PVC + nginx ConfigMap + Deployment + Service. (The seed ConfigMap is
    # created from seed_demo.py via kubectl, see the header comment.)
    assert len(docs) == 4
    for kind in ("PersistentVolumeClaim", "ConfigMap", "Deployment", "Service"):
        assert f"kind: {kind}" in text
    assert "replicas: 1" in text  # SQLite state -> single writer
    # Dashboard binds loopback inside the pod; only nginx has a containerPort.
    assert 'args: ["dashboard", "--host", "127.0.0.1", "--port", "8765"]' in text
    assert "containerPort: 8080" in text
    assert f"containerPort: {_PORT}" not in text
    assert f"mountPath: {_STATE}" in text
    assert "secretKeyRef" in text and "MAVERICK_DASHBOARD_TOKEN" in text
    assert "location = /demo" in text
    assert "return 302 /demo" in text
    assert "return 404" in text
    assert text.count("limit_except GET HEAD") == 2
    assert text.count("limits:") >= 3      # resources on every container
    assert "seed_demo.py" in text          # init container runs the seeder


def test_readme_documents_the_honest_posture():
    text = (_DC / "README.md").read_text(encoding="utf-8")
    # The blueprint's core honesty: no global read-only flag exists, so the
    # deny-proxy carries the posture, and DNS/TLS is a maintainer act.
    assert "no global read-only flag" in text
    assert "path-allowlist" in text
    assert "method-only" in text
    assert "limit_except" in text
    assert "TLS" in text and "demo.maverick.dev" in text


def test_dashboard_public_demo_route_is_redacted():
    text = (
        _REPO_ROOT / "packages" / "maverick-dashboard" / "maverick_dashboard" / "app.py"
    ).read_text(encoding="utf-8")
    assert '@app.get("/demo", response_class=HTMLResponse)' in text
    assert 'owner="demo"' in text
    route = text[text.index('def public_demo'):text.index('@app.get("/overview", response_class=HTMLResponse)')]
    assert "get_facts" not in route
    assert "UsageLedger" not in route
    assert "default_audit_log" not in route


def test_no_baked_secrets_in_demo_cluster():
    suspicious = re.compile(r"sk-ant-[a-zA-Z0-9]{8,}|AKIA[A-Z0-9]{16}")
    for path in _DC.rglob("*"):
        if path.is_file():
            assert not suspicious.search(path.read_text(encoding="utf-8", errors="ignore")), path
