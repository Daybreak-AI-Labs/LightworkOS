"""Explicit production executor configuration; no host-execution fallback."""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

from ..file_lock import atomic_write_text, ensure_private_directory
from ..paths import maverick_home


def _kubeconfig(raw: str) -> str:
    if len(raw.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Executor kubeconfig exceeds the one MiB limit")
    try:
        config = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("Executor kubeconfig must be a flattened JSON kubeconfig") from exc
    if not isinstance(config, dict) or config.get("kind") != "Config" or config.get("apiVersion") != "v1":
        raise ValueError("Executor kubeconfig must be a v1 Config")
    contexts = config.get("contexts", [])
    if not isinstance(contexts, list) or len(contexts) != 1 or not isinstance(contexts[0], dict) or contexts[0].get("name") != config.get("current-context"):
        raise ValueError("Executor kubeconfig must contain exactly its selected context")
    users, clusters = config.get("users", []), config.get("clusters", [])
    if not isinstance(users, list) or not isinstance(clusters, list) or len(users) != 1 or len(clusters) != 1:
        raise ValueError("Executor kubeconfig must contain one user and one cluster")
    if not isinstance(users[0], dict) or not isinstance(clusters[0], dict):
        raise ValueError("Executor kubeconfig identity is malformed")
    context = contexts[0].get("context", {})
    user, cluster = users[0].get("user", {}), clusters[0].get("cluster", {})
    if not all(isinstance(item, dict) for item in (context, user, cluster)):
        raise ValueError("Executor kubeconfig identity is malformed")
    if context.get("user") != users[0].get("name") or context.get("cluster") != clusters[0].get("name"):
        raise ValueError("Executor kubeconfig references an unknown identity")
    _validate_identity(user, cluster)
    clean = {key: config[key] for key in ("kind", "apiVersion", "current-context", "contexts", "users", "clusters")}
    encoded = json.dumps(clean, sort_keys=True)
    directory = ensure_private_directory(maverick_home() / "sandbox-authority")
    path = directory / "executor.json"
    atomic_write_text(path, encoded)
    return str(path)


def _validate_identity(user, cluster):
    if set(user) - {"token", "client-certificate-data", "client-key-data"}:
        raise ValueError("Executor kubeconfig must use inline credentials; command plugins and file references are refused")
    if not user.get("token") and not (user.get("client-certificate-data") and user.get("client-key-data")):
        raise ValueError("Executor kubeconfig has no inline credential")
    if any(not isinstance(value, str) or not value for value in user.values()):
        raise ValueError("Executor inline credentials must be nonempty strings")
    if set(cluster) - {"server", "certificate-authority-data", "tls-server-name", "disable-compression"}:
        raise ValueError("Executor kubeconfig must verify TLS without proxies or local file references")
    if any(not isinstance(value, str) for key, value in cluster.items() if key != "disable-compression"):
        raise ValueError("Executor cluster endpoint and certificates must be strings")
    endpoint = urlsplit(cluster.get("server", ""))
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError("Executor cluster must have an HTTPS endpoint without embedded credentials")
    if not cluster.get("certificate-authority-data"):
        raise ValueError("Executor kubeconfig must embed its cluster CA")


def deployment_isolation_mode() -> str | None:
    """Read the deployment pin, preserving explicit off and invalid modes."""
    from ..config import env_flag

    mode = os.environ.get("MAVERICK_DEPLOYMENT_ISOLATION", "")
    if not mode or env_flag("MAVERICK_DEPLOYMENT_ISOLATION") is False:
        return None
    if mode != "kubernetes":
        raise ValueError("MAVERICK_DEPLOYMENT_ISOLATION must be kubernetes; no local fallback is allowed")
    return mode


def deployment_kubernetes_config() -> dict | None:
    if deployment_isolation_mode() is None:
        return None
    namespace = os.environ.get("MAVERICK_EXECUTOR_NAMESPACE", "lightwork-execution")
    image = os.environ.get("MAVERICK_EXECUTOR_IMAGE", "")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace) or namespace in {"default", "kube-system"}:
        raise ValueError("Production execution requires a dedicated Kubernetes namespace")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[a-f0-9]{64}", image):
        raise ValueError("Production execution requires MAVERICK_EXECUTOR_IMAGE pinned by sha256 digest")
    raw = os.environ.get("MAVERICK_EXECUTOR_KUBECONFIG_SECRET", "")
    if not raw:
        raise ValueError("Production executor credential is missing; provision the Kubernetes executor before accepting client work")
    return {"backend": "kubernetes", "require_container": True, "namespace": namespace,
            "image": image, "kubeconfig": _kubeconfig(raw), "context": None,
            "allow_network": False, "extra_kubectl_args": [], "run_as_user": 1000,
            "memory": "4g", "cpus": "2"}
