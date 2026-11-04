"""Air-gapped preflight verification.

A regulated / classified deployment needs to *prove* there is no outbound path
before it trusts the box. Full OS-level air-gapping (firewall, no NIC) is the
operator's job; this is the **application-layer audit** that catches the ways
Lightwork's own config would still reach the network: a remote model provider, a
non-deny-all egress policy, or a sandbox allowed network access. ``maverick
airgap check`` runs it and exits non-zero on any finding, so it can gate a
deployment.

Pure config inspection — a config dict in, a list of violations out — so it's
deterministic and tested without touching the network. The runtime *enforcement*
(the egress chokepoint, local-first routing) ships separately; this verifies the
deployment is actually configured for them.
"""
from __future__ import annotations


def audit(*, config=None) -> dict:
    """Audit a config for outbound paths. Returns ``{clean, violations}``."""
    if config is None:
        try:
            from .config import load_config
            config = load_config() or {}
        except Exception:  # pragma: no cover -- never block the check
            config = {}
    violations: list[str] = []
    violations += _audit_providers(config)
    violations += _audit_egress(config)
    violations += _audit_sandbox(config)
    violations += _audit_telemetry(config)
    return {"clean": not violations, "violations": violations}


def _endpoint_is_local(provider: str, config: dict) -> bool:
    """Is ``provider``'s *resolved endpoint* local, for the audited ``config``?

    The name-only check trusts the provider prefix, so a built-in "local" provider
    (ollama / vllm / tgi / the ``local`` alias) pointed off-box via
    ``[providers.<name>] base_url`` was reported clean while every prompt left the
    box. This resolves the effective endpoint from the audited config and validates
    it with the enterprise egress-lock locality check (loopback/private only).

    Compliance posture: this is a proof-of-no-egress tool, so any failure to prove
    an endpoint local (a cloud provider, a non-local base_url, or an unevaluable
    strict check) returns ``False`` — fail toward FLAGGING, never toward clean.
    """
    try:
        from . import enterprise
        from .providers import _canonical
    except Exception:
        return False
    try:
        canon = _canonical(provider)
        # Known cloud providers are never local, whatever base_url is set.
        if canon in enterprise.CLOUD_PROVIDERS:
            return False
        # Resolve the endpoint the audited config pins for this provider; the dict
        # under audit is the source of truth (accept the canonical or raw key).
        providers = config.get("providers") or {}
        pcfg = providers.get(canon) or providers.get(provider) or {}
        base_url = pcfg.get("base_url") if isinstance(pcfg, dict) else None
        if isinstance(base_url, str) and base_url.strip():
            return enterprise._is_local_endpoint(base_url.strip())
        # No endpoint pinned in the audited config -> defer to the enterprise
        # endpoint-validating check (built-in localhost default + env-var URLs).
        return enterprise.is_local_provider(canon)
    except Exception:
        return False


def _audit_providers(config: dict) -> list[str]:
    from .llm import ROLE_MODELS
    from .provider_local_first import _provider_of
    models = dict(ROLE_MODELS)
    for role, spec in (config.get("models") or {}).items():
        if isinstance(spec, str) and spec.strip():
            models[role] = spec
    remote = sorted({spec for spec in models.values()
                     if not _endpoint_is_local(_provider_of(spec), config)})
    if remote:
        return [f"remote model(s) in use: {', '.join(remote)} — route every role "
                "to a local provider (ollama / vllm / tgi) whose endpoint is "
                "loopback/private"]
    return []


def _audit_egress(config: dict) -> list[str]:
    egress = config.get("egress") or {}
    deny = egress.get("deny") or []
    violations: list[str] = []
    if "*" not in deny:
        violations.append(
            'egress is not deny-all — set [egress] deny = ["*"] to block '
            "all outbound hosts")

    # [egress] deny is honored only by a handful of callers
    # (tenant.egress.egress_allowed) — NOT the process-wide runtime guard
    # (egress_guard.py), which wraps httpx/requests across ~80 connectors
    # and every provider SDK. That guard's default-deny (enterprise.
    # egress_permitted) returns True UNCONDITIONALLY whenever enterprise
    # mode is off, whatever [egress] says. A config could pass the check
    # above and still leave every connector free to reach the internet.
    # deployment_enterprise_enabled(config=...) mirrors the runtime's own
    # enterprise_enabled() precedence (compliance floor > MAVERICK_ENTERPRISE
    # env > [enterprise] mode) but reads [enterprise] mode from THIS audited
    # config rather than the live one, keeping the audit a pure function of
    # its input. Any failure to resolve it flags rather than clears (fail
    # toward flagging, never toward clean, matching _endpoint_is_local).
    try:
        from . import enterprise
        enterprise_on = enterprise.deployment_enterprise_enabled(
            config=config, source_errors=())
    except Exception:
        enterprise_on = False
    if not enterprise_on:
        violations.append(
            "[enterprise] mode is not enabled for this config (and no "
            "compliance profile requires the egress lock) — the runtime "
            "egress guard that wraps httpx/requests across connectors and "
            'provider SDKs only enforces default-deny when enterprise mode '
            'is on; [egress] deny = ["*"] alone is honored by a small '
            "subset of call sites, not the process-wide guard. Set "
            "[enterprise] mode = true (or an active compliance profile "
            "requiring the egress lock) to actually block outbound "
            "requests at the enforced seam.")
    else:
        allowed = (config.get("enterprise") or {}).get("allowed_hosts") or []
        if allowed:
            hosts = ", ".join(sorted(str(h) for h in allowed))
            violations.append(
                f"[enterprise] allowed_hosts is non-empty ({hosts}) — these "
                "hosts are explicitly permitted outbound tool egress, which "
                "is incompatible with an air-gapped deployment; clear "
                "allowed_hosts")
    return violations


def _truthy(val) -> bool:
    return val is True or (isinstance(val, str) and val.strip().lower() in
                           {"1", "true", "yes", "on"})


def _audit_sandbox(config: dict) -> list[str]:
    sb = config.get("sandbox") or {}
    backend = str(sb.get("backend") or "local").strip().lower()
    val = sb.get("allow_network")
    network_policy = str(sb.get("network_policy") or "").strip().lower()
    if backend == "kubernetes":
        # A transient `kubectl run` pod has full egress by default and the
        # backend refuses to run with allow_network=false (it cannot self-
        # enforce no-egress). The only k8s config that actually runs air-gapped
        # is allow_network=true behind an operator-applied cluster-level
        # deny-all NetworkPolicy — invisible to static config inspection. So
        # the audit can only clear k8s when the operator explicitly asserts
        # that policy; otherwise egress is unprovable.
        if _truthy(val) and network_policy in {"deny-all", "deny_all", "deny"}:
            return []
        return ["[sandbox] backend=kubernetes egress cannot be proven by config "
                "inspection — a cluster-level deny-all NetworkPolicy must be "
                "applied out-of-band; assert it with allow_network = true and "
                'network_policy = "deny-all"']
    if _truthy(val):
        return ["[sandbox] allow_network is on — the sandbox can reach the network"]
    if backend in {"docker", "podman", "gvisor"}:
        return []
    if backend == "devcontainer":
        if val is False or (isinstance(val, str) and val.strip().lower() in
                            {"0", "false", "no", "off"}):
            return []
        return ["[sandbox] backend=devcontainer defaults to network access — set "
                "allow_network = false or use a deny-by-default backend"]
    if backend == "firecracker":
        network = str(sb.get("network") or "egress-deny").strip().lower()
        if network == "egress-deny":
            return []
        return [f"[sandbox] firecracker network={network!r} can reach the network "
                "— set network = \"egress-deny\""]
    if backend == "ssh":
        return ["[sandbox] backend=ssh uses a remote host with its own network access"]
    if backend == "modal":
        return ["[sandbox] backend=modal runs in a cloud sandbox with network access"]
    if backend.startswith("ep:"):
        return ["[sandbox] entry-point backends cannot be proven air-gapped by "
                "static config inspection"]
    if backend == "local":
        return ["[sandbox] backend=local uses the host network — choose a sandbox "
                "backend with network disabled"]
    return [f"[sandbox] backend={backend!r} is not recognized; air-gap status "
            "cannot be proven"]


def _audit_telemetry(config: dict) -> list[str]:
    """Flag config-visible telemetry / forwarding sinks that open outbound sockets.

    These reach the network directly, not through the ``[egress]`` deny list the
    LLM/tool paths honor, so the other passes are blind to them: Sentry error
    reporting, OTLP trace and metrics export, SIEM audit forwarding, and outbound
    webhooks all ship run data off-box. The OTLP switches are read from
    ``[observability]`` as the All settings page writes them, with the runtime's own
    truth rules, so a value the runtime would treat as on is flagged. (Prometheus is
    an inbound 127.0.0.1 listener, not egress, so it is not flagged here.)
    """
    from .observability import setting_is_blank_or_off, switch_is_on

    violations: list[str] = []
    obs = config.get("observability") or {}
    # Read as the runtime reads them, so a switch the runtime treats as off (a TOML false,
    # "off") is not flagged.
    if not setting_is_blank_or_off(obs.get("sentry_dsn")):
        violations.append(
            "[observability] sentry_dsn is set — Sentry ships errors/traces off-box; "
            "clear it (and unset MAVERICK_SENTRY_DSN) for an air-gapped deployment")
    if switch_is_on(obs.get("otel_exporter"), extra_on=frozenset({"otlp"})):
        violations.append(
            "[observability] otel_exporter is set — timing traces are sent to an OpenTelemetry "
            "collector off-box; clear it (and unset MAVERICK_OTEL_EXPORTER) for an air-gapped "
            "deployment")
    # Parsed as the runtime parses MAVERICK_OTEL_METRICS: only a true value is on.
    if switch_is_on(obs.get("otlp_metrics")):
        violations.append(
            "[observability] otlp_metrics is on — measurements are sent to an OpenTelemetry "
            "collector off-box; turn it off (and unset MAVERICK_OTEL_METRICS) for an "
            "air-gapped deployment")
    siem = str((config.get("audit") or {}).get("siem_dest") or "").strip()
    if siem:
        violations.append(
            "[audit] siem_dest is set — audit events are forwarded to a network "
            "collector; clear it for an air-gapped deployment")
    outbound = (config.get("webhooks") or {}).get("outbound") or []
    if isinstance(outbound, str):
        outbound = [outbound]
    targets = sorted({str(u).strip() for u in outbound if str(u).strip()})
    if targets:
        violations.append(
            f"[webhooks] outbound target(s): {', '.join(targets)} — outbound "
            "webhooks POST run data off-box; clear [webhooks] outbound for an "
            "air-gapped deployment")
    return violations


__all__ = ["audit"]
