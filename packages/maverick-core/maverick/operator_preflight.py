"""Deterministic, offline operator preflight for a fresh Lightwork install.

``maverick doctor`` deliberately performs live checks (provider API, Docker
daemon, database).  That is useful diagnostics, but it is a poor automation
contract: the output is human-only and can change with the network.  This
module supplies the complementary read-only preflight used by installers,
deployment scripts, and the first-run dashboard:

* stable ordering and JSON shape;
* no network requests and no state creation;
* every blocker has one copyable remediation command;
* a ``run`` profile for the agent runtime and a stricter ``cockpit`` profile
  for the dashboard plus AI Evidence-Ready Gateway.

It reports configuration, not legal or regulatory compliance.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

Status = Literal["ready", "blocked", "attention"]
Profile = Literal["run", "cockpit"]

SCHEMA = "lightwork.operator-preflight.v1"


@dataclass(frozen=True)
class Check:
    """One stable, secret-free readiness check."""

    id: str
    label: str
    status: Status
    detail: str
    remediation: str = ""


@dataclass(frozen=True)
class Report:
    """Structured operator preflight result."""

    schema: str
    profile: Profile
    ready: bool
    blocker_count: int
    attention_count: int
    checks: tuple[Check, ...]
    next_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "checks": [asdict(check) for check in self.checks],
        }


def _config_state() -> tuple[Check, dict[str, Any] | None]:
    from .config import config_path, config_source_errors, load_config

    path = config_path()
    try:
        cfg = load_config()
        errors = config_source_errors()
    except Exception as exc:
        return (
            Check(
                "config",
                "Configuration",
                "blocked",
                f"Configuration could not be loaded ({type(exc).__name__}).",
                "maverick config-lint",
            ),
            None,
        )
    if errors:
        names = ", ".join(sorted(Path(item).name for item in errors))
        return (
            Check(
                "config",
                "Configuration",
                "blocked",
                f"Active configuration is unreadable or invalid: {names}.",
                "maverick config-lint",
            ),
            None,
        )
    if not isinstance(cfg, dict):
        return (
            Check(
                "config",
                "Configuration",
                "blocked",
                "Configuration root must be a TOML table.",
                "maverick config-lint",
            ),
            None,
        )
    return (
        Check(
            "config",
            "Configuration",
            "ready",
            f"Loaded {path}." if path.is_file() else "Loaded current saved settings and environment choices.",
        ),
        cfg,
    )


def _provider_state(cfg: dict[str, Any] | None) -> tuple[Check, bool]:
    if cfg is None:
        return (
            Check(
                "provider",
                "Model provider",
                "blocked",
                "Provider readiness cannot be established until config is valid.",
                "maverick config-lint",
            ),
            False,
        )
    try:
        routed = _routed_configuration_missing(cfg)
        ready = sorted(provider for provider, missing in routed.items() if not missing)
        configured = bool(ready)
    except Exception:
        ready = []
        configured = False
    if not configured:
        return (
            Check(
                "provider",
                "Model provider",
                "blocked",
                "No selected model route has complete offline prerequisites.",
                "Lightwork Settings > Models",
            ),
            False,
        )
    return (
        Check(
            "provider",
            "Model provider",
            "ready",
            f"Ready selected provider route(s): {', '.join(ready)}.",
        ),
        True,
    )


def _model_specs(cfg: dict[str, Any]) -> tuple[str, ...]:
    """Deterministically resolve every model route a normal swarm may use.

    The resolver is shared with ``model_for_role`` for environment, tenant
    role edits, config, dashboard pins, and the admin allow-list. Dynamic
    cost/local/energy routing performs live probes and therefore belongs to
    ``doctor``, not this offline preflight.
    """
    try:
        from .llm import ROLE_MODELS, offline_model_for_role
    except Exception:
        return ()
    configured = cfg.get("models")
    configured = configured if isinstance(configured, dict) else {}
    roles = set(ROLE_MODELS) | {
        str(role)
        for role, value in configured.items()
        if isinstance(value, str) and value.strip()
    }
    specs = {
        offline_model_for_role(role, config=cfg)
        for role in roles
    }
    return tuple(sorted(specs))


def _provider_table(cfg: dict[str, Any], provider: str) -> Mapping[str, Any]:
    providers = cfg.get("providers")
    if not isinstance(providers, dict):
        return {}
    value = providers.get(provider)
    return value if isinstance(value, dict) else {}


def _present(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _route_configuration_missing(
    provider: str,
    cfg: dict[str, Any],
) -> tuple[str, ...]:
    """Return missing non-network prerequisites for one routed provider."""

    from .config import (
        PROVIDER_KEY_ENV_MAP,
        azure_provider_configuration_missing,
    )

    table = _provider_table(cfg, provider)
    configured_key = _present(table.get("api_key")) or any(
        _present(os.environ.get(name))
        for name in PROVIDER_KEY_ENV_MAP.get(provider, ())
    )
    if provider in {"ollama", "vllm", "tgi"}:
        # Each has a documented localhost default and an internal placeholder
        # key. Live server reachability belongs to `doctor`.
        return ()
    if provider == "openai_compatible":
        base = _present(table.get("base_url")) or _present(
            os.environ.get("OPENAI_COMPATIBLE_BASE_URL")
        )
        key = configured_key or _present(
            os.environ.get("OPENAI_COMPATIBLE_API_KEY")
        )
        return tuple(
            item
            for item, present in (("base_url", base), ("api_key", key))
            if not present
        )
    if provider == "azure":
        return azure_provider_configuration_missing(dict(table))
    if provider == "bedrock":
        key = _present(table.get("api_key")) or _present(
            os.environ.get("BEDROCK_API_KEY")
        )
        region = (
            _present(os.environ.get("AWS_REGION"))
            or _present(os.environ.get("AWS_DEFAULT_REGION"))
            or _present(table.get("region"))
        )
        return tuple(
            item
            for item, present in (("api_key", key), ("region", region))
            if not present
        )
    if provider == "vertex":
        # Google ADC carries no key: the project and region are the prerequisites
        # (the model id is named per route). Sign-in itself is checked when a
        # client is built, not here.
        project = (
            _present(table.get("project_id"))
            or _present(os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID"))
            or _present(os.environ.get("GOOGLE_CLOUD_PROJECT"))
        )
        region = _present(table.get("region")) or _present(os.environ.get("CLOUD_ML_REGION"))
        return tuple(
            item
            for item, present in (("project_id", project), ("region", region))
            if not present
        )
    if provider == "codex_cli":
        try:
            from .providers.codex_cli_provider import _auth_file_present

            authenticated = configured_key or _auth_file_present()
        except Exception:
            authenticated = configured_key
        return () if authenticated else ("login",)
    if provider not in {
        "anthropic",
        "openai",
        "openrouter",
        "gemini",
        "moonshot",
        "deepseek",
        "xai",
    }:
        return ("known provider",)
    return () if configured_key else ("api_key",)


def _routed_configuration_missing(
    cfg: dict[str, Any],
) -> dict[str, tuple[str, ...]]:
    """Canonical provider prerequisite state for every selected model route."""
    from .providers import _canonical

    routed: dict[str, tuple[str, ...]] = {}
    for spec in _model_specs(cfg):
        provider = _canonical(
            spec.split(":", 1)[0] if ":" in spec else "anthropic"
        )
        routed[provider] = _route_configuration_missing(provider, cfg)
    return routed


def _format_route_missing(
    missing: Mapping[str, tuple[str, ...]],
) -> str:
    """Render secret-free, copyable provider prerequisites for operators."""
    from .config import PROVIDER_KEY_ENV_MAP

    exact_hints = {
        ("openai_compatible", "base_url"): "OPENAI_COMPATIBLE_BASE_URL",
        ("azure", "endpoint"): "AZURE_OPENAI_ENDPOINT",
        ("azure", "deployment"): "AZURE_OPENAI_DEPLOYMENT",
        (
            "azure",
            "authentication",
        ): "AZURE_OPENAI_API_KEY or Azure Entra credentials",
        ("bedrock", "region"): "AWS_REGION",
        ("vertex", "project_id"): "GOOGLE_CLOUD_PROJECT or ANTHROPIC_VERTEX_PROJECT_ID",
        ("vertex", "region"): "CLOUD_ML_REGION",
        ("codex_cli", "login"): "codex login",
    }
    rendered: list[str] = []
    for provider, fields in sorted(missing.items()):
        labels: list[str] = []
        for field in fields:
            if field == "api_key" and PROVIDER_KEY_ENV_MAP.get(provider):
                labels.append("/".join(PROVIDER_KEY_ENV_MAP[provider]))
            else:
                labels.append(exact_hints.get((provider, field), field))
        rendered.append(f"{provider}: {', '.join(labels)}")
    return "; ".join(rendered)


def _role_configuration_missing(
    role: str,
    cfg: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    """Return the deterministic effective provider and prerequisites for ROLE."""
    from .llm import offline_model_for_role
    from .providers import _canonical

    spec = offline_model_for_role(role, config=cfg)
    provider = _canonical(
        spec.split(":", 1)[0] if ":" in spec else "anthropic"
    )
    return provider, _route_configuration_missing(provider, cfg)


def _route_state(cfg: dict[str, Any] | None) -> Check:
    if cfg is None:
        return Check(
            "model_routes",
            "Model routes",
            "blocked",
            "Model routes cannot be checked until config is valid.",
            "maverick config-lint",
        )
    try:
        routed = _routed_configuration_missing(cfg)
    except Exception as exc:
        return Check(
            "model_routes",
            "Model routes",
            "blocked",
            f"Model routes could not be inspected ({type(exc).__name__}).",
            "maverick config-lint",
        )
    missing = {
        provider: fields for provider, fields in routed.items() if fields
    }
    if missing:
        detail = _format_route_missing(missing)
        return Check(
            "model_routes",
            "Model routes",
            "blocked",
            f"Routed provider setup is incomplete ({detail}).",
            "Lightwork Settings > Models",
        )
    labels = ", ".join(sorted(routed)) or "none"
    return Check(
        "model_routes",
        "Model routes",
        "ready",
        f"Offline prerequisites are present for: {labels}.",
    )


def _sdk_state(
    cfg: dict[str, Any] | None,
    provider_configured: bool,
) -> Check:
    if cfg is None or not provider_configured:
        return Check(
            "provider_dependencies",
            "Provider dependencies",
            "blocked",
            "Dependency readiness is waiting on a configured provider.",
            "Lightwork Settings > Models",
        )
    try:
        from .providers import missing_sdks

        missing = missing_sdks(_model_specs(cfg))
    except Exception as exc:
        return Check(
            "provider_dependencies",
            "Provider dependencies",
            "blocked",
            f"Provider dependencies could not be inspected ({type(exc).__name__}).",
            "maverick doctor",
        )
    if missing:
        return Check(
            "provider_dependencies",
            "Provider dependencies",
            "blocked",
            " ".join(missing),
            "maverick doctor",
        )
    return Check(
        "provider_dependencies",
        "Provider dependencies",
        "ready",
        "SDK or local-provider executable is available for routed models.",
    )


def _nearest_existing_parent(path: Path) -> Path | None:
    candidate = path
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent
    return candidate


def _storage_state(cfg: dict[str, Any] | None) -> Check:
    if cfg is None:
        return Check(
            "storage",
            "Runtime storage",
            "blocked",
            "Storage readiness cannot be established until config is valid.",
            "maverick config-lint",
        )
    backend = str(
        os.environ.get("MAVERICK_WORLD_BACKEND")
        or (cfg.get("world_model") or {}).get("backend")
        or "sqlite"
    ).strip().lower()
    if backend == "postgres":
        return Check(
            "storage",
            "Runtime storage",
            "attention",
            "Postgres is configured; this offline preflight does not open it.",
            "maverick doctor",
        )
    if backend != "sqlite":
        return Check(
            "storage",
            "Runtime storage",
            "blocked",
            f"Unsupported world-model backend {backend!r}.",
            "maverick config-lint",
        )
    try:
        from .paths import diagnostic_data_dir

        db_path = diagnostic_data_dir("world.db")
    except Exception as exc:
        return Check(
            "storage",
            "Runtime storage",
            "blocked",
            f"Storage path could not be resolved ({type(exc).__name__}).",
            "maverick doctor",
        )
    if db_path.exists():
        if not db_path.is_file() or not os.access(db_path, os.R_OK | os.W_OK):
            return Check(
                "storage",
                "Runtime storage",
                "blocked",
                f"{db_path} is not a readable, writable regular file.",
                "maverick doctor",
            )
        return Check(
            "storage",
            "Runtime storage",
            "ready",
            f"SQLite state is readable and writable at {db_path}.",
        )
    parent = _nearest_existing_parent(db_path.parent)
    if parent is None or not parent.is_dir() or not os.access(parent, os.W_OK):
        return Check(
            "storage",
            "Runtime storage",
            "blocked",
            f"The parent for {db_path} cannot be created or written.",
            "maverick doctor",
        )
    return Check(
        "storage",
        "Runtime storage",
        "ready",
        f"SQLite state will be created at {db_path} on first use.",
    )


def _dashboard_state(*, required: bool) -> Check:
    try:
        installed = importlib.util.find_spec("maverick_dashboard") is not None
    except Exception:
        installed = False
    if installed:
        return Check(
            "dashboard",
            "Operator dashboard",
            "ready",
            "Dashboard package is installed.",
        )
    return Check(
        "dashboard",
        "Operator dashboard",
        "blocked" if required else "attention",
        "Dashboard package is not installed.",
        (
            "python -m pip install -e ./packages/maverick-dashboard"
            if required
            else "maverick doctor"
        ),
    )


def _tenant_state(
    cfg: dict[str, Any] | None,
    *,
    required: bool,
) -> Check:
    """Report whether evidence records have an explicit company boundary."""

    if cfg is None:
        return Check(
            "tenant_scope",
            "Company / tenant scope",
            "blocked" if required else "attention",
            "Tenant scope cannot be checked until config is valid.",
            "maverick config-lint",
        )
    try:
        from .paths import current_tenant_id_strict

        tenant = current_tenant_id_strict()
    except Exception as exc:
        return Check(
            "tenant_scope",
            "Company / tenant scope",
            "blocked",
            f"Tenant scope could not be resolved ({type(exc).__name__}).",
            "maverick config-lint",
        )
    if tenant:
        return Check(
            "tenant_scope",
            "Company / tenant scope",
            "ready",
            f"Evidence state is bound to tenant {tenant!r}.",
        )
    return Check(
        "tenant_scope",
        "Company / tenant scope",
        "blocked" if required else "attention",
        (
            "No company or tenant is selected. Evidence records require an "
            "explicit tenant boundary."
        ),
        "maverick config edit",
    )


def _feature_enabled(
    cfg: dict[str, Any] | None,
    module_name: str,
) -> bool:
    """Mirror the three default-off feature gates without importing stores."""

    if cfg is None:
        return False
    graph = (
        isinstance(cfg.get("evidence_graph"), dict)
        and cfg["evidence_graph"].get("enable") is True
    )
    if module_name == "evidence_graph":
        return graph
    if module_name == "ai_evidence_gateway":
        override = os.environ.get("MAVERICK_EVIDENCE_GATEWAY")
        if override is not None:
            return override.strip().lower() in {"1", "true", "yes", "on"}
        section = cfg.get("evidence_gateway")
        return isinstance(section, dict) and section.get("enable") is True
    if module_name == "model_risk_assurance":
        section = cfg.get("model_risk_assurance")
        return (
            graph
            and isinstance(section, dict)
            and section.get("enable") is True
            and isinstance(section.get("gate_promotions", False), bool)
        )
    return False


def _feature_state(
    cfg: dict[str, Any] | None,
    check_id: str,
    label: str,
    module_name: str,
    remediation: str,
    *,
    required: bool,
) -> Check:
    active = _feature_enabled(cfg, module_name)
    if active:
        return Check(check_id, label, "ready", "Enabled with valid dependencies.")
    return Check(
        check_id,
        label,
        "blocked" if required else "attention",
        "Disabled or a required dependency is not enabled.",
        remediation,
    )


def _module_available(name: str) -> bool:
    """Return whether an optional runtime dependency can be imported."""

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _ed25519_public_bytes(private_bytes: bytes) -> bytes:
    """Derive an Ed25519 public key using the audit runtime's primitives."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _injected_audit_key_error(value: str) -> str:
    """Validate an injected key without consuming or caching its environment."""

    from .audit.signing import _decode_injected_key

    private_bytes = _decode_injected_key(value)
    if private_bytes is None:
        return (
            "The injected audit signing key is not a runtime-compatible "
            "hex/base64 32-byte Ed25519 private key."
        )
    try:
        _ed25519_public_bytes(private_bytes)
    except (ImportError, ValueError):
        return (
            "The injected audit signing key could not be validated as an "
            "Ed25519 private key."
        )
    return ""


def _decode_wrapped_audit_key(value: str) -> bytes | None:
    """Decode the wrapped-key envelope exactly as the audit runtime does."""

    import base64
    import binascii

    raw = value.strip()
    if not raw:
        return None
    try:
        wrapped = bytes.fromhex(raw)
    except ValueError:
        try:
            wrapped = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            return None
    return wrapped or None


def _wrapped_audit_key_error(value: str, cfg: dict[str, Any]) -> str:
    """Validate offline KMS envelope prerequisites without calling the KMS."""

    wrapped = _decode_wrapped_audit_key(value)
    if wrapped is None:
        return (
            "The KMS-wrapped audit signing key is not valid runtime-compatible "
            "hex/base64 material."
        )
    kms_cfg = cfg.get("kms")
    if not isinstance(kms_cfg, dict):
        return (
            "The KMS-wrapped audit signing key has no valid [kms] "
            "configuration."
        )
    provider = str(kms_cfg.get("provider") or "").strip().lower()
    try:
        from .kms_backends import (
            _AWS_MAGIC,
            _AZURE_MAGIC,
            _GCP_MAGIC,
            _VAULT_MAGIC,
            build_cloud_kms,
        )

        # Construction validates the runtime provider and key-id prerequisites.
        # Cloud clients are lazy, so this is deterministic and makes no request.
        build_cloud_kms(provider, cfg=kms_cfg)
    except Exception:
        return (
            "The KMS-wrapped audit signing key has incomplete or invalid "
            "offline KMS configuration."
        )
    envelope_magic = {
        "aws": _AWS_MAGIC,
        "azure": _AZURE_MAGIC,
        "gcp": _GCP_MAGIC,
        "vault": _VAULT_MAGIC,
    }[provider]
    if not wrapped.startswith(envelope_magic) or len(wrapped) == len(
        envelope_magic
    ):
        return (
            "The KMS-wrapped audit signing key does not use the configured "
            "provider's runtime envelope format."
        )
    if provider == "vault":
        try:
            wrapped[len(envelope_magic) :].decode("utf-8")
        except UnicodeError:
            return (
                "The KMS-wrapped audit signing key does not use the configured "
                "provider's runtime envelope format."
            )
    dependencies = {
        "aws": ("boto3",),
        "azure": ("azure.keyvault.keys.crypto", "azure.identity"),
        "gcp": ("google.cloud.kms",),
        "vault": ("hvac",),
    }[provider]
    if not all(_module_available(dependency) for dependency in dependencies):
        return (
            "The configured KMS backend dependency needed to unwrap the audit "
            "signing key is not installed."
        )
    return ""


def _local_audit_key_error(
    key_dir: Path,
    private_keys: tuple[Path, ...],
) -> str:
    """Validate existing local keypairs without changing their ACLs or bytes."""

    from .file_lock import (
        atomic_read_bytes,
        atomic_read_text,
        private_path_is_restricted,
    )

    active_pointer = key_dir / "active"
    if active_pointer.exists():
        if not private_path_is_restricted(active_pointer, 0o600):
            return "The local audit active-key pointer is not owner-restricted."
        try:
            active_key_id = atomic_read_text(active_pointer).strip()
        except (OSError, UnicodeError):
            return "The local audit active-key pointer is unreadable."
        if (
            not re.fullmatch(r"[0-9a-f]{16}", active_key_id)
            or not (key_dir / f"{active_key_id}.key").is_file()
            or not (key_dir / f"{active_key_id}.pub").is_file()
        ):
            return "The local audit active-key pointer is invalid."

    for private_path in private_keys:
        if not re.fullmatch(r"[0-9a-f]{16}", private_path.stem):
            return "A local audit private-key filename has an invalid key id."
        public_path = private_path.with_suffix(".pub")
        if (
            not private_path_is_restricted(private_path, 0o600)
            or not private_path_is_restricted(public_path, 0o644)
        ):
            return "A local audit signing-key path is not properly restricted."
        try:
            private_bytes = atomic_read_bytes(private_path)
            public_bytes = atomic_read_bytes(public_path)
        except OSError:
            return "A local audit signing keypair is unreadable."
        if len(private_bytes) != 32 or len(public_bytes) != 32:
            return (
                "A local audit signing keypair does not contain two raw "
                "32-byte Ed25519 keys."
            )
        if hashlib.sha256(public_bytes).hexdigest()[:16] != private_path.stem:
            return "A local audit public key does not match its key id."
        try:
            derived_public = _ed25519_public_bytes(private_bytes)
        except (ImportError, ValueError):
            return (
                "A local audit private key could not be validated as an "
                "Ed25519 private key."
            )
        if derived_public != public_bytes:
            return "A local audit private/public signing keypair does not match."
    return ""


def _gateway_evidence_checks(  # noqa: C901 - explicit read-only posture matrix
    cfg: dict[str, Any] | None,
) -> tuple[Check, Check, Check, Check]:
    """Inspect signing custody, trust, and ledger paths without creating state."""

    waiting = (
        Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "attention",
            "Gateway custody checks are waiting on an enabled evidence gateway.",
            "maverick preflight --profile cockpit",
        ),
        Check(
            "gateway_signing",
            "Gateway signing capability",
            "attention",
            "Gateway signing checks are waiting on an enabled evidence gateway.",
            "maverick preflight --profile cockpit",
        ),
        Check(
            "gateway_trust_registry",
            "Gateway trust registry",
            "attention",
            "Gateway trust checks are waiting on an enabled evidence gateway.",
            "maverick preflight --profile cockpit",
        ),
        Check(
            "gateway_ledgers",
            "Gateway signed ledgers",
            "attention",
            "Gateway ledger checks are waiting on an enabled evidence gateway.",
            "maverick preflight --profile cockpit",
        ),
    )
    if not _feature_enabled(cfg, "ai_evidence_gateway"):
        return waiting
    try:
        from .file_lock import private_path_is_restricted
        from .paths import current_tenant_id_strict, diagnostic_data_dir

        key_dir = diagnostic_data_dir("audit", "keys")
        ledger_dir = diagnostic_data_dir("ai_evidence_gateway")
        tenant = current_tenant_id_strict()
    except Exception as exc:
        blocked = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "blocked",
            f"Gateway evidence paths could not be resolved ({type(exc).__name__}).",
            "maverick doctor",
        )
        return (
            blocked,
            Check(
                "gateway_signing",
                "Gateway signing capability",
                "blocked",
                "Signing capability cannot be established until custody paths resolve.",
                "maverick doctor",
            ),
            Check(
                "gateway_trust_registry",
                "Gateway trust registry",
                "blocked",
                "Trust registry cannot be established until custody paths resolve.",
                "maverick doctor",
            ),
            Check(
                "gateway_ledgers",
                "Gateway signed ledgers",
                "blocked",
                "Signed-ledger paths could not be resolved.",
                "maverick doctor",
            ),
        )
    if not tenant:
        return tuple(
            Check(
                check.id,
                check.label,
                "attention",
                "Gateway evidence checks are waiting on an explicit tenant.",
                "maverick config edit",
            )
            for check in waiting
        )

    def directory_admission(path: Path) -> str:
        if path.exists():
            if (
                not path.is_dir()
                or not os.access(path, os.R_OK | os.W_OK)
                or not private_path_is_restricted(path, 0o700)
            ):
                return "existing path is not a private readable/writable directory"
            return ""
        parent = _nearest_existing_parent(path.parent)
        if (
            parent is None
            or not parent.is_dir()
            or not os.access(parent, os.W_OK)
        ):
            return "nearest existing parent cannot create the private directory"
        return ""

    custody_path_error = directory_admission(key_dir)
    ledger_path_error = directory_admission(ledger_dir)

    injected_value = os.environ.get("MAVERICK_AUDIT_SIGNING_KEY", "")
    wrapped_value = os.environ.get(
        "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED",
        "",
    )
    injected = bool(injected_value.strip())
    wrapped = bool(wrapped_value.strip())
    injected_markers = (
        tuple(key_dir.glob("*.injected")) if key_dir.is_dir() else ()
    )
    private_keys = (
        tuple(sorted(key_dir.glob("*.key"))) if key_dir.is_dir() else ()
    )
    audit_cfg = cfg.get("audit") if isinstance(cfg, dict) else {}
    require_offhost = (
        str(
            os.environ.get("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "")
        ).strip().lower()
        in {"1", "true", "yes", "on"}
        or (
            isinstance(audit_cfg, dict)
            and audit_cfg.get("require_offhost_key") is True
        )
    )
    injected_error = (
        _injected_audit_key_error(injected_value) if injected else ""
    )
    wrapped_error = (
        _wrapped_audit_key_error(wrapped_value, cfg)
        if wrapped and isinstance(cfg, dict)
        else ""
    )
    local_error = (
        _local_audit_key_error(key_dir, private_keys)
        if key_dir.is_dir() and not custody_path_error
        else ""
    )
    material_error = injected_error or wrapped_error or local_error
    offhost = (injected and not injected_error) or (
        wrapped and not wrapped_error
    )
    if custody_path_error:
        custody = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "blocked",
            f"Gateway key custody is unsafe: {custody_path_error}.",
            "maverick doctor",
        )
    elif material_error:
        custody = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "blocked",
            f"Gateway signing-key material failed validation. {material_error}",
            "maverick doctor",
        )
    elif offhost:
        custody = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "ready",
            "An externally managed or injected signing-key posture is present.",
        )
    elif require_offhost:
        custody = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "blocked",
            "Off-host signing-key custody is required but not configured.",
            "configure KMS-wrapped or injected audit signing-key custody",
        )
    elif private_keys:
        custody = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "attention",
            (
                "A validated, restricted local signing key is present; use "
                "off-host custody for stronger production separation."
            ),
            "configure KMS-wrapped or injected audit signing-key custody",
        )
    else:
        custody = Check(
            "gateway_key_custody",
            "Gateway signing-key custody",
            "attention",
            "No signing key has been provisioned yet; preflight did not create one.",
            "configure KMS-wrapped or injected audit signing-key custody",
        )

    crypto_ready = _module_available("cryptography")
    if not crypto_ready:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "blocked",
            "Ed25519 signing support is not installed.",
            "python -m pip install cryptography",
        )
    elif material_error:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "blocked",
            (
                "Ed25519 support is installed, but configured signing-key "
                "material failed validation."
            ),
            "maverick doctor",
        )
    elif require_offhost and not offhost:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "blocked",
            (
                "Signing would be refused because off-host key custody is "
                "required and no validated off-host source is configured."
            ),
            "maverick doctor",
        )
    elif injected:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "ready",
            "The injected Ed25519 signing key passed offline validation.",
        )
    elif wrapped:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "ready",
            (
                "The KMS-wrapped signing-key envelope and offline backend "
                "prerequisites passed; preflight did not contact the KMS."
            ),
        )
    elif private_keys:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "ready",
            "The local Ed25519 private/public keypair passed validation.",
        )
    else:
        signing = Check(
            "gateway_signing",
            "Gateway signing capability",
            "ready",
            "Ed25519 signing support is installed.",
        )

    trust_error = (
        f"The audit trust-registry path is unsafe: {custody_path_error}."
        if custody_path_error
        else ""
    )
    if not trust_error and local_error:
        trust_error = (
            "The protected local signing-key registry failed validation."
        )
    trusted_count = 0
    trusted_keys: dict[str, str] = {}
    if not trust_error and key_dir.exists() and not key_dir.is_dir():
        trust_error = "The audit trust-registry path is not a directory."
    elif not trust_error and key_dir.is_dir():
        try:
            from .file_lock import atomic_read_bytes

            for public_path in sorted(key_dir.glob("*.pub")):
                if not re.fullmatch(r"[0-9a-f]{16}", public_path.stem):
                    raise ValueError("invalid key id")
                raw = atomic_read_bytes(public_path)
                if (
                    len(raw) != 32
                    or hashlib.sha256(raw).hexdigest()[:16]
                    != public_path.stem
                    or not private_path_is_restricted(public_path, 0o644)
                ):
                    raise ValueError("malformed or unprotected public key")
                has_custody = (
                    public_path.with_suffix(".key").exists()
                    or public_path.with_suffix(".injected").exists()
                )
                if not has_custody:
                    raise ValueError("unprovisioned public key")
                trusted_count += 1
                trusted_keys[public_path.stem] = raw.hex()
            for marker_path in injected_markers:
                if (
                    not re.fullmatch(r"[0-9a-f]{16}", marker_path.stem)
                    or not marker_path.with_suffix(".pub").is_file()
                    or not private_path_is_restricted(marker_path, 0o600)
                    or atomic_read_bytes(marker_path)
                ):
                    raise ValueError("malformed injected-key marker")
        except (OSError, ValueError):
            trust_error = "The protected trust registry failed validation."
    if trust_error:
        trust = Check(
            "gateway_trust_registry",
            "Gateway trust registry",
            "blocked",
            trust_error,
            "maverick doctor",
        )
    elif trusted_count:
        trust = Check(
            "gateway_trust_registry",
            "Gateway trust registry",
            "ready",
            f"{trusted_count} protected public trust root(s) are present.",
        )
    else:
        trust = Check(
            "gateway_trust_registry",
            "Gateway trust registry",
            "attention",
            "No public trust root exists yet; preflight did not provision one.",
            "issue the first governed gateway delivery after configuring custody",
        )

    ledger_error = (
        f"Gateway ledger custody is unsafe: {ledger_path_error}."
        if ledger_path_error
        else ""
    )
    initialized = 0
    if not ledger_error:
        from .ai_evidence_ledger import SegmentedReceiptLedger

        for stem, identity_key, payload_key in (
            (
                "interaction_receipts",
                "receipt_id",
                "receipt_payload_sha256",
            ),
            ("assurance_packets", "packet_id", "packet_sha256"),
        ):
            legacy = ledger_dir / f"{stem}.ndjson"
            artifacts = (
                legacy,
                ledger_dir / f"{stem}.segments",
                ledger_dir / f"{stem}.index.sqlite3",
                ledger_dir / f"{stem}.index-state.json",
            )
            if not any(path.exists() for path in artifacts):
                continue
            initialized += 1
            if not trusted_keys:
                ledger_error = (
                    "An existing signed gateway ledger has no validated "
                    "protected trust root."
                )
                break
            ledger = SegmentedReceiptLedger(
                legacy,
                tenant_id=tenant,
                identity_key=identity_key,
                payload_key=payload_key,
            )
            valid, detail = ledger.verify_integrity_read_only(
                trusted_public_keys=trusted_keys,
            )
            if not valid:
                ledger_error = (
                    f"The {stem.replace('_', ' ')} ledger failed read-only "
                    f"integrity validation ({detail})."
                )
                break
    if ledger_error:
        ledgers = Check(
            "gateway_ledgers",
            "Gateway signed ledgers",
            "blocked",
            ledger_error,
            "maverick doctor",
        )
    elif initialized:
        ledgers = Check(
            "gateway_ledgers",
            "Gateway signed ledgers",
            "ready",
            (
                f"{initialized} gateway ledger namespace(s) passed signed "
                "row, authenticated-state, and read-only index verification."
            ),
        )
    else:
        ledgers = Check(
            "gateway_ledgers",
            "Gateway signed ledgers",
            "attention",
            "No gateway ledger exists yet; preflight did not create evidence state.",
            "issue the first governed gateway delivery",
        )
    return custody, signing, trust, ledgers


def collect(profile: Profile = "run") -> Report:
    """Collect a stable, offline preflight report.

    ``run`` blocks only what prevents a normal agent run. ``cockpit`` also
    requires the dashboard, evidence graph, evidence gateway, and Model Risk
    Officer.  The function performs no network requests and creates no state.
    """

    if profile not in {"run", "cockpit"}:
        raise ValueError("profile must be 'run' or 'cockpit'")
    config_check, cfg = _config_state()
    provider_check, provider_configured = _provider_state(cfg)
    checks: list[Check] = [
        config_check,
        provider_check,
        _route_state(cfg),
        _sdk_state(cfg, provider_configured),
        _storage_state(cfg),
    ]
    cockpit_required = profile == "cockpit"
    checks.append(_dashboard_state(required=cockpit_required))
    checks.append(_tenant_state(cfg, required=cockpit_required))
    checks.extend(
        [
            _feature_state(
                cfg,
                "evidence_graph",
                "Evidence graph",
                "evidence_graph",
                (
                    "set [evidence_graph] enable = true in "
                    "~/.maverick/config.toml"
                ),
                required=cockpit_required,
            ),
            _feature_state(
                cfg,
                "evidence_gateway",
                "AI Evidence-Ready Gateway",
                "ai_evidence_gateway",
                (
                    "set [evidence_gateway] enable = true in "
                    "~/.maverick/config.toml"
                ),
                required=cockpit_required,
            ),
            _feature_state(
                cfg,
                "model_risk_assurance",
                "Model Risk & AI Assurance Officer",
                "model_risk_assurance",
                (
                    "set [model_risk_assurance] enable = true in "
                    "~/.maverick/config.toml"
                ),
                required=cockpit_required,
            ),
        ]
    )
    if cockpit_required:
        checks.extend(_gateway_evidence_checks(cfg))
    blockers = [check for check in checks if check.status == "blocked"]
    attention = [check for check in checks if check.status == "attention"]
    if blockers:
        next_action = blockers[0].remediation
    elif profile == "run":
        next_action = 'maverick start "hello"'
    elif attention:
        next_action = attention[0].remediation
    else:
        next_action = "maverick dashboard"
    return Report(
        schema=SCHEMA,
        profile=profile,
        ready=not blockers,
        blocker_count=len(blockers),
        attention_count=len(attention),
        checks=tuple(checks),
        next_action=next_action,
    )


def render(report: Report) -> str:
    """Render a compact, copyable text report."""

    verdict = "READY" if report.ready else "BLOCKED"
    lines = [
        f"Lightwork offline preflight [{report.profile}]: {verdict}",
        (
            f"{report.blocker_count} blocker(s), "
            f"{report.attention_count} attention item(s)"
        ),
    ]
    marker = {"ready": "OK", "blocked": "BLOCK", "attention": "CHECK"}
    for check in report.checks:
        lines.append(f"  [{marker[check.status]}] {check.label}: {check.detail}")
        if check.remediation:
            lines.append(f"          Fix: {check.remediation}")
    lines.append(f"Next action: {report.next_action}")
    lines.append(
        "Offline preflight checks configuration only; run `maverick doctor` "
        "for live connectivity."
    )
    return "\n".join(lines)


def render_json(report: Report) -> str:
    """Render the stable JSON automation contract."""

    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


__all__ = [
    "Check",
    "Profile",
    "Report",
    "SCHEMA",
    "collect",
    "render",
    "render_json",
]
