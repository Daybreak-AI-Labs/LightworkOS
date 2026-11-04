"""Contract tests for the deployment reference architectures + devcontainer
. Static validation: the artifacts parse, agree
on the canonical port/command/state path, and bake in no secrets."""
from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RA = _REPO_ROOT / "deploy" / "reference-architectures"
_PORT = "8765"
_STATE = "/home/maverick/.maverick"


def test_readme_lists_all_four_platforms():
    text = (_RA / "README.md").read_text(encoding="utf-8")
    for platform in ("Kubernetes", "ECS", "Fly.io", "Railway"):
        assert platform in text


def test_kubernetes_manifest_invariants():
    # PyYAML isn't a core dep; parse with a light regex contract instead.
    text = (_RA / "kubernetes" / "maverick.yaml").read_text(encoding="utf-8")
    docs = [d for d in text.split("\n---\n") if d.strip()]
    assert len(docs) == 3  # PVC + Deployment + Service
    assert "kind: PersistentVolumeClaim" in text
    assert "kind: Deployment" in text and "kind: Service" in text
    assert f"containerPort: {_PORT}" in text
    assert f"mountPath: {_STATE}" in text
    assert "replicas: 1" in text  # SQLite state -> single writer
    assert "secretRef" in text
    assert re.search(r'args: \["dashboard", "--host", "0\.0\.0\.0", "--port", "8765"\]', text)


def test_ecs_task_definition_parses_and_matches_contract():
    data = json.loads((_RA / "ecs" / "task-definition.json").read_text())
    c = data["containerDefinitions"][0]
    assert c["command"][0] == "dashboard" and _PORT in c["command"]
    assert c["portMappings"][0]["containerPort"] == int(_PORT)
    assert c["mountPoints"][0]["containerPath"] == _STATE
    # Provider key comes from SSM, never a plaintext env value.
    assert any(s["name"] == "ANTHROPIC_API_KEY" for s in c["secrets"])
    env_names = {e.get("name") for e in c.get("environment", [])}
    assert "ANTHROPIC_API_KEY" not in env_names
    assert data["volumes"][0]["efsVolumeConfiguration"]["transitEncryption"] == "ENABLED"


def test_fly_toml_parses_and_matches_contract():
    data = tomllib.loads((_RA / "flyio" / "fly.toml").read_text(encoding="utf-8"))
    assert data["http_service"]["internal_port"] == int(_PORT)
    # The volume holds all runtime state: MAVERICK_HOME points at its mount.
    assert data["mounts"][0]["destination"] == data["env"]["MAVERICK_HOME"]
    assert data["experimental"]["cmd"][0] == "dashboard" and _PORT in data["experimental"]["cmd"]
    assert data["http_service"]["force_https"] is True


def test_railway_json_parses_and_matches_contract():
    data = json.loads((_RA / "railway" / "railway.json").read_text())
    assert data["build"]["dockerfilePath"] == "deploy/docker/Dockerfile"
    assert _PORT in data["deploy"]["startCommand"]
    assert data["deploy"]["numReplicas"] == 1


def test_devcontainer_parses_and_bootstraps():
    dc_dir = _REPO_ROOT / ".devcontainer"
    data = json.loads((dc_dir / "devcontainer.json").read_text())
    assert int(_PORT) in data["forwardPorts"]
    assert "post-create.sh" in data["postCreateCommand"]
    script = (dc_dir / "post-create.sh").read_text()
    # The shared installer selects the reviewed cohort from its manifest.
    assert "scripts/install_release_cohort.py --editable" in script
    assert "pytest" in script


def test_no_baked_secrets_anywhere():
    suspicious = re.compile(r"sk-ant-[a-zA-Z0-9]{8,}|AKIA[A-Z0-9]{16}")
    for path in list(_RA.rglob("*")) + list((_REPO_ROOT / ".devcontainer").rglob("*")):
        if path.is_file():
            assert not suspicious.search(path.read_text(encoding="utf-8", errors="ignore")), path
