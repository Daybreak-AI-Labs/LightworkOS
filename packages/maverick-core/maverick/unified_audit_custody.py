"""Tenant-exact custody orchestration for the unified audit projection.

This module composes existing audit primitives; it does not replace them.  A
run verifies the signed tenant audit, publishes an independently consumable
checkpoint into a tenant-local staging directory, optionally pushes already
anchored and already sealed closed days through the existing WORM sink, and
optionally forwards only unified-audit projection rows to an HTTPS SIEM
namespace.  The SIEM cursor is at-least-once: an ambiguous transport result is
replayed with the same ``projection_event_id`` on the next bounded run.

No run seals audit files.  Sealing is an explicit operator boundary because an
immutable WORM upload of plaintext cannot be undone safely.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from . import unified_audit as audit
from .audit import checkpoints, forwarder, signing, worm
from .audit.export import to_jsonl
from .audit.sealing import segment_text
from .file_lock import atomic_write_text, cross_process_lock, ensure_private_file
from .paths import canonical_tenant_id, data_dir

_STATE_SCHEMA = "lightwork.unified-audit-custody-state.v1"
_STATUS_SCHEMA = "lightwork.unified-audit-custody-status.v1"
_RUN_SCHEMA = "lightwork.unified-audit-custody-run.v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_AUDIT_FILES = 10_000
_MAX_STATE_BYTES = 64 * 1024


class UnifiedAuditCustodyError(RuntimeError):
    """Custody configuration, integrity, or dependency failure."""


class UnifiedAuditCustodyBackoff(UnifiedAuditCustodyError):
    """The durable retry window has not elapsed."""


class _WormPusher(Protocol):
    def __call__(self, **kwargs: Any) -> Mapping[str, str]: ...


@dataclass(frozen=True, slots=True)
class CustodySettings:
    enable: bool = False
    authority_revision: int = 1
    checkpoint_enable: bool = True
    worm_enable: bool = False
    siem_enable: bool = False
    siem_destination_template: str = ""
    max_siem_events_per_run: int = 500
    retry_backoff_seconds: int = 30
    max_retry_backoff_seconds: int = 3_600

    def __post_init__(self) -> None:
        if not all(
            type(value) is bool
            for value in (
                self.enable,
                self.checkpoint_enable,
                self.worm_enable,
                self.siem_enable,
            )
        ):
            raise UnifiedAuditCustodyError("custody enablement values must be booleans")
        if self.enable and not any(
            (self.checkpoint_enable, self.worm_enable, self.siem_enable)
        ):
            raise UnifiedAuditCustodyError("enabled custody requires at least one custody target")
        bounds = (
            (self.authority_revision, 1, 2**31 - 1, "authority_revision"),
            (self.max_siem_events_per_run, 1, 5_000, "max_siem_events_per_run"),
            (self.retry_backoff_seconds, 1, 86_400, "retry_backoff_seconds"),
            (
                self.max_retry_backoff_seconds,
                self.retry_backoff_seconds,
                604_800,
                "max_retry_backoff_seconds",
            ),
        )
        for value, minimum, maximum, label in bounds:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise UnifiedAuditCustodyError(f"custody {label} is outside its bound")
        if not isinstance(self.siem_destination_template, str):
            raise UnifiedAuditCustodyError("custody SIEM destination template is invalid")
        if self.siem_enable:
            _validate_siem_template(self.siem_destination_template)


@dataclass(frozen=True, slots=True)
class CustodyRunResult:
    outcome: str
    checkpoint_published: bool
    checkpoint_verified: bool
    worm_files_considered: int
    worm_files_custodied: int
    siem_events_forwarded: int
    siem_replay_possible: bool
    next_retry_at: float
    run_sha256: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise UnifiedAuditCustodyError("custody material is not canonical") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        value = float(clock())
    except (TypeError, ValueError, OverflowError) as exc:
        raise UnifiedAuditCustodyError("custody clock is unavailable") from exc
    if not math.isfinite(value) or value < 0:
        raise UnifiedAuditCustodyError("custody clock is invalid")
    return value


def _tenant_sha256(tenant_id: str) -> str:
    return hashlib.sha256(f"lightwork.unified-audit.tenant.v1:{tenant_id}".encode()).hexdigest()


def _validate_siem_template(template: str) -> None:
    if (
        not template
        or len(template) > 2_048
        or template.count("{tenant_sha256}") != 1
    ):
        raise UnifiedAuditCustodyError(
            "custody SIEM destination must contain one {tenant_sha256} namespace"
        )
    parsed = urlparse(template.replace("{tenant_sha256}", "0" * 64))
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise UnifiedAuditCustodyError("custody SIEM destination must use HTTPS")
    if "{tenant_sha256}" not in tuple(part for part in urlparse(template).path.split("/") if part):
        raise UnifiedAuditCustodyError(
            "custody SIEM tenant namespace must be an exact URL path segment"
        )
    try:
        forwarder.parse_dest(template.replace("{tenant_sha256}", "0" * 64))
    except ValueError as exc:
        raise UnifiedAuditCustodyError("custody SIEM destination is invalid") from exc


def settings_from(config: Mapping[str, Any], *, tenant_id: str) -> CustodySettings:
    """Parse the closed, default-off tenant custody configuration."""

    canonical_tenant_id(tenant_id)
    if not isinstance(config, Mapping):
        raise UnifiedAuditCustodyError("custody configuration is unavailable")
    audit_section = config.get("audit") or {}
    if not isinstance(audit_section, Mapping):
        raise UnifiedAuditCustodyError("[audit] must be a table")
    unified = audit_section.get("unified") or {}
    if not isinstance(unified, Mapping):
        raise UnifiedAuditCustodyError("[audit.unified] must be a table")
    raw = unified.get("custody") or {}
    if not isinstance(raw, Mapping):
        raise UnifiedAuditCustodyError("[audit.unified.custody] must be a table")
    allowed = {
        "enable",
        "authority_revision",
        "checkpoint_enable",
        "worm_enable",
        "siem_enable",
        "siem_destination_template",
        "max_siem_events_per_run",
        "retry_backoff_seconds",
        "max_retry_backoff_seconds",
    }
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise UnifiedAuditCustodyError(
            "unknown [audit.unified.custody] key: " + ", ".join(unknown)
        )
    try:
        settings = CustodySettings(**{key: raw[key] for key in allowed if key in raw})
        core = audit.require_enabled(config) if settings.enable else audit.config_from(config)
    except (TypeError, audit.UnifiedAuditError) as exc:
        raise UnifiedAuditCustodyError(str(exc)) from exc
    if settings.enable and not core.enable:
        raise UnifiedAuditCustodyError("custody requires enabled unified audit")
    if settings.worm_enable:
        worm_cfg = audit_section.get("worm") or {}
        if not isinstance(worm_cfg, Mapping):
            raise UnifiedAuditCustodyError("[audit.worm] must be a table")
        provider = str(worm_cfg.get("provider") or "").strip().lower()
        if provider not in {"local", "s3", "aws"}:
            raise UnifiedAuditCustodyError("custody WORM provider is unavailable")
        if provider in {"s3", "aws"}:
            prefix = worm_cfg.get("prefix")
            if not isinstance(prefix, str) or prefix.count("{tenant_sha256}") != 1:
                raise UnifiedAuditCustodyError(
                    "S3 custody prefix must contain one {tenant_sha256} namespace"
                )
            if not str(worm_cfg.get("bucket") or "").strip():
                raise UnifiedAuditCustodyError("S3 custody bucket is unavailable")
    return settings


def enabled(config: Mapping[str, Any], *, tenant_id: str) -> bool:
    try:
        return settings_from(config, tenant_id=tenant_id).enable
    except (TypeError, ValueError, UnifiedAuditCustodyError):
        return False


def authority_sha256(
    config: Mapping[str, Any],
    *,
    tenant_id: str,
    settings: CustodySettings | None = None,
) -> str:
    selected = settings or settings_from(config, tenant_id=tenant_id)
    audit_section = config.get("audit")
    assert isinstance(audit_section, Mapping)
    worm_cfg = audit_section.get("worm") if selected.worm_enable else None
    return _sha256(
        {
            "schema": "lightwork.unified-audit-custody-authority.v1",
            "tenant_sha256": _tenant_sha256(canonical_tenant_id(tenant_id)),
            "settings": asdict(selected),
            "worm": dict(worm_cfg) if isinstance(worm_cfg, Mapping) else {},
        }
    )


def _default_state() -> dict[str, Any]:
    return {
        "schema": _STATE_SCHEMA,
        "tenant_sha256": "",
        "authority_revision": 0,
        "authority_sha256": "",
        "previous_authority_sha256": "",
        "rotation_count": 0,
        "cursor": None,
        "consecutive_failures": 0,
        "next_retry_at": 0.0,
        "last_success_at": 0.0,
        "last_error_code": None,
        "last_run_sha256": None,
    }


def _state_digest(payload: Mapping[str, Any]) -> str:
    return _sha256({key: value for key, value in payload.items() if key != "state_sha256"})


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _default_state()
    ensure_private_file(path, 0o600)
    if path.stat().st_size > _MAX_STATE_BYTES:
        raise UnifiedAuditCustodyError("custody state exceeds its bound")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UnifiedAuditCustodyError("custody state is unreadable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != _STATE_SCHEMA
        or not isinstance(payload.get("state_sha256"), str)
        or not _DIGEST.fullmatch(payload["state_sha256"])
        or payload["state_sha256"] != _state_digest(payload)
    ):
        raise UnifiedAuditCustodyError("custody state integrity is invalid")
    return payload


def _save_state(path: Path, payload: Mapping[str, Any]) -> None:
    material = dict(payload)
    material["state_sha256"] = _state_digest(material)
    atomic_write_text(
        path,
        json.dumps(material, sort_keys=True, separators=(",", ":")) + "\n",
        mode=0o600,
    )


def _apply_authority(
    state: dict[str, Any],
    *,
    tenant_sha256: str,
    revision: int,
    digest: str,
) -> dict[str, Any]:
    current_tenant = state.get("tenant_sha256")
    current_revision = state.get("authority_revision")
    current_digest = state.get("authority_sha256")
    if current_tenant not in {"", tenant_sha256}:
        raise UnifiedAuditCustodyError("custody state tenant binding is invalid")
    if not isinstance(current_revision, int) or isinstance(current_revision, bool):
        raise UnifiedAuditCustodyError("custody state authority revision is invalid")
    if current_revision > revision:
        raise UnifiedAuditCustodyError("custody authority revision rollback refused")
    if current_revision == revision and current_revision != 0 and current_digest != digest:
        raise UnifiedAuditCustodyError("custody authority changed without a revision")
    selected = dict(state)
    if current_revision < revision:
        selected.update(
            previous_authority_sha256=current_digest or "",
            rotation_count=int(state.get("rotation_count") or 0) + (1 if current_revision else 0),
            cursor=None,
            consecutive_failures=0,
            next_retry_at=0.0,
            last_error_code=None,
        )
    selected.update(
        tenant_sha256=tenant_sha256,
        authority_revision=revision,
        authority_sha256=digest,
    )
    return selected


def _build_worm_sink(
    config: Mapping[str, Any],
    *,
    tenant_id: str,
    tenant_sha256: str,
):
    audit_section = config.get("audit")
    assert isinstance(audit_section, Mapping)
    raw = audit_section.get("worm")
    assert isinstance(raw, Mapping)
    cfg = dict(raw)
    provider = str(cfg.get("provider") or "").strip().lower()
    if provider == "local":
        configured = cfg.get("dir")
        base = Path(str(configured)).expanduser() if configured else data_dir(
            "unified-audit-worm", tenant=tenant_id
        )
        cfg["dir"] = str(base / "tenants" / tenant_sha256)
    else:
        cfg["prefix"] = str(cfg["prefix"]).replace("{tenant_sha256}", tenant_sha256)
        if not cfg["prefix"].endswith("/"):
            cfg["prefix"] += "/"
    return worm.build_sink(cfg)


def _resolved_siem_destination(settings: CustodySettings, tenant_sha256: str) -> str:
    destination = settings.siem_destination_template.replace(
        "{tenant_sha256}", tenant_sha256
    )
    parsed = urlparse(destination)
    if tenant_sha256 not in tuple(part for part in parsed.path.split("/") if part):
        raise UnifiedAuditCustodyError("resolved SIEM destination lost tenant namespace")
    forwarder.parse_dest(destination)
    return destination


def _verify_audit(audit_dir: Path) -> tuple[Path, ...]:
    if not audit_dir.exists():
        return ()
    files = tuple(signing.day_files(audit_dir))
    if len(files) > _MAX_AUDIT_FILES:
        raise UnifiedAuditCustodyError("custody audit file count exceeds its bound")
    for path in files:
        if signing.verify_chain(path):
            raise UnifiedAuditCustodyError("signed audit chain verification failed")
    if signing.verify_anchors(audit_dir):
        raise UnifiedAuditCustodyError("signed audit anchor verification failed")
    return files


def _rows(path: Path) -> list[dict[str, Any]]:
    try:
        text = segment_text(path, fail_soft=False)
    except Exception as exc:
        raise UnifiedAuditCustodyError("signed audit segment is unreadable") from exc
    if signing.verify_chain(path):
        raise UnifiedAuditCustodyError("signed audit chain verification failed")
    try:
        confirmed = segment_text(path, fail_soft=False)
    except Exception as exc:
        raise UnifiedAuditCustodyError("signed audit segment is unreadable") from exc
    if not hashlib.sha256(text.encode()).digest() == hashlib.sha256(
        confirmed.encode()
    ).digest():
        raise UnifiedAuditCustodyError("signed audit segment changed during custody read")
    rows: list[dict[str, Any]] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise UnifiedAuditCustodyError("signed audit segment contains invalid JSON") from exc
        if not isinstance(row, dict):
            raise UnifiedAuditCustodyError("signed audit row is invalid")
        rows.append(row)
    return rows


def _siem_batch(
    files: Sequence[Path],
    *,
    cursor: object,
    tenant_sha256: str,
    limit: int,
) -> tuple[list[str], dict[str, Any] | None]:
    start_day = None
    start_line = 0
    start_hash = ""
    if cursor is not None:
        if not isinstance(cursor, Mapping):
            raise UnifiedAuditCustodyError("custody SIEM cursor is invalid")
        start_day = cursor.get("day")
        start_line = cursor.get("line")
        start_hash = cursor.get("row_sha256")
        if (
            not isinstance(start_day, str)
            or not _DAY.fullmatch(start_day)
            or not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or start_line < 1
            or not isinstance(start_hash, str)
            or not _DIGEST.fullmatch(start_hash)
        ):
            raise UnifiedAuditCustodyError("custody SIEM cursor is invalid")
    by_day = {path.stem: path for path in files}
    if start_day is not None and start_day not in by_day:
        later = [path for path in files if path.stem > start_day]
        if not later:
            return [], dict(cursor)  # no newer retained evidence exists
        start_day = None
        start_line = 0
        start_hash = ""

    lines: list[str] = []
    new_cursor = dict(cursor) if isinstance(cursor, Mapping) else None
    reached = start_day is None
    for path in files:
        if not reached:
            if path.stem != start_day:
                continue
            reached = True
        rows = _rows(path)
        offset = 0
        if path.stem == start_day:
            if start_line > len(rows) or rows[start_line - 1].get("hash") != start_hash:
                raise UnifiedAuditCustodyError("custody SIEM cursor no longer matches audit evidence")
            offset = start_line
        for line_number, row in enumerate(rows[offset:], start=offset + 1):
            row_hash = row.get("hash")
            if not isinstance(row_hash, str) or not _DIGEST.fullmatch(row_hash):
                raise UnifiedAuditCustodyError("custody encountered an unsigned audit row")
            new_cursor = {
                "day": path.stem,
                "line": line_number,
                "row_sha256": row_hash,
            }
            if row.get("kind") != "unified_audit_projection":
                continue
            if row.get("tenant_sha256") != tenant_sha256:
                raise UnifiedAuditCustodyError("unified-audit row tenant binding is invalid")
            event_id = row.get("projection_event_id")
            if not isinstance(event_id, str) or not _DIGEST.fullmatch(event_id):
                raise UnifiedAuditCustodyError("unified-audit delivery identity is invalid")
            lines.append(to_jsonl(row))
            if len(lines) >= limit:
                return lines, new_cursor
    return lines, new_cursor


class UnifiedAuditCustodyRuntime:
    """One-tenant, one-run-at-a-time production custody composition."""

    def __init__(
        self,
        *,
        tenant_id: str,
        config_loader: Callable[[], Mapping[str, Any]],
        clock: Callable[[], float] = time.time,
        checkpoint_publisher: Callable[..., Path] = checkpoints.publish_checkpoint,
        checkpoint_verifier: Callable[..., Sequence[object]] = checkpoints.verify_checkpoints,
        worm_pusher: _WormPusher = worm.push_closed_dayfiles,
        siem_forwarder: Callable[..., int] = forwarder.forward,
    ) -> None:
        self.tenant_id = canonical_tenant_id(tenant_id)
        dependencies = (
            config_loader,
            clock,
            checkpoint_publisher,
            checkpoint_verifier,
            worm_pusher,
            siem_forwarder,
        )
        if not all(callable(value) for value in dependencies):
            raise TypeError("custody dependencies must be callable")
        self._config_loader = config_loader
        self._clock = clock
        self._checkpoint_publisher = checkpoint_publisher
        self._checkpoint_verifier = checkpoint_verifier
        self._worm_pusher = worm_pusher
        self._siem_forwarder = siem_forwarder

    @property
    def _audit_dir(self) -> Path:
        return data_dir("audit", tenant=self.tenant_id)

    @property
    def _checkpoint_dir(self) -> Path:
        return data_dir("unified-audit", "checkpoints", tenant=self.tenant_id)

    @property
    def _state_path(self) -> Path:
        return data_dir("unified-audit", "custody-state.json", tenant=self.tenant_id)

    @property
    def _lock_target(self) -> Path:
        return data_dir("unified-audit", "custody-run", tenant=self.tenant_id)

    def _authority(self) -> tuple[Mapping[str, Any], CustodySettings, str]:
        try:
            config = self._config_loader()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise UnifiedAuditCustodyError("custody configuration is unavailable") from exc
        if not isinstance(config, Mapping):
            raise UnifiedAuditCustodyError("custody configuration is unavailable")
        settings = settings_from(config, tenant_id=self.tenant_id)
        if not settings.enable:
            raise UnifiedAuditCustodyError("unified_audit_custody_disabled")
        return config, settings, authority_sha256(
            config, tenant_id=self.tenant_id, settings=settings
        )

    def _assert_authority(self, expected: str) -> None:
        _config, _settings, observed = self._authority()
        if observed != expected:
            raise UnifiedAuditCustodyError("custody authority changed during operation")

    def readiness(self) -> dict[str, Any]:
        """Validate configuration only; never open stores or contact providers."""

        try:
            config, settings, digest = self._authority()
            audit_section = config.get("audit")
            assert isinstance(audit_section, Mapping)
            provider = "disabled"
            if settings.worm_enable:
                worm_cfg = audit_section.get("worm")
                assert isinstance(worm_cfg, Mapping)
                provider = str(worm_cfg.get("provider") or "").lower()
            result: dict[str, Any] = {
                "schema": _STATUS_SCHEMA,
                "enabled": True,
                "ready": True,
                "authority_revision": settings.authority_revision,
                "authority_sha256": digest,
                "checkpoint_enabled": settings.checkpoint_enable,
                "worm_enabled": settings.worm_enable,
                "worm_provider": provider,
                "siem_enabled": settings.siem_enable,
                "siem_delivery": "at_least_once" if settings.siem_enable else "disabled",
                "tenant_namespace_sha256": _tenant_sha256(self.tenant_id),
                "automatic_sealing_performed": False,
                "independent_operation_verified": False,
                "off_host_key_custody_verified": False,
                "s3_object_lock_acceptance_verified": False,
                "siem_acceptance_verified": False,
                "live_customer_acceptance_verified": False,
            }
        except (TypeError, ValueError, UnifiedAuditCustodyError):
            result = {
                "schema": _STATUS_SCHEMA,
                "enabled": False,
                "ready": False,
                "automatic_sealing_performed": False,
                "independent_operation_verified": False,
                "off_host_key_custody_verified": False,
                "s3_object_lock_acceptance_verified": False,
                "siem_acceptance_verified": False,
                "live_customer_acceptance_verified": False,
            }
        result["status_sha256"] = _sha256(result)
        return result

    def run_once(self) -> CustodyRunResult:
        config, settings, authority_digest = self._authority()
        now = _clock_value(self._clock)
        tenant_digest = _tenant_sha256(self.tenant_id)
        with cross_process_lock(self._lock_target, strict=True):
            state = _apply_authority(
                _load_state(self._state_path),
                tenant_sha256=tenant_digest,
                revision=settings.authority_revision,
                digest=authority_digest,
            )
            retry_at = float(state.get("next_retry_at") or 0.0)
            if now < retry_at:
                raise UnifiedAuditCustodyBackoff("custody retry backoff is active")
            try:
                result, cursor = self._execute(
                    config=config,
                    settings=settings,
                    authority_digest=authority_digest,
                    tenant_digest=tenant_digest,
                    cursor=state.get("cursor"),
                    now=now,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                failures = int(state.get("consecutive_failures") or 0) + 1
                delay = min(
                    settings.max_retry_backoff_seconds,
                    settings.retry_backoff_seconds * (2 ** min(failures - 1, 16)),
                )
                state.update(
                    consecutive_failures=failures,
                    next_retry_at=now + delay,
                    last_error_code=type(exc).__name__,
                )
                _save_state(self._state_path, state)
                if isinstance(exc, UnifiedAuditCustodyError):
                    raise
                raise UnifiedAuditCustodyError("custody dependency operation failed") from exc
            state.update(
                cursor=cursor,
                consecutive_failures=0,
                next_retry_at=0.0,
                last_success_at=now,
                last_error_code=None,
                last_run_sha256=result.run_sha256,
            )
            _save_state(self._state_path, state)
            return result

    def _execute(
        self,
        *,
        config: Mapping[str, Any],
        settings: CustodySettings,
        authority_digest: str,
        tenant_digest: str,
        cursor: object,
        now: float,
    ) -> tuple[CustodyRunResult, dict[str, Any] | None]:
        files = _verify_audit(self._audit_dir)
        checkpoint_published = False
        checkpoint_verified = False
        today = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
        current = self._audit_dir / f"{today}.ndjson"
        if settings.checkpoint_enable and current.exists():
            self._assert_authority(authority_digest)
            self._checkpoint_publisher(
                self._audit_dir,
                self._checkpoint_dir,
                day=today,
            )
            checkpoint_published = True
            breaks = self._checkpoint_verifier(self._audit_dir, self._checkpoint_dir)
            if breaks:
                raise UnifiedAuditCustodyError("custody checkpoint verification failed")
            checkpoint_verified = True

        worm_report: Mapping[str, str] = {}
        if settings.worm_enable:
            self._assert_authority(authority_digest)
            sink = _build_worm_sink(
                config,
                tenant_id=self.tenant_id,
                tenant_sha256=tenant_digest,
            )
            audit_section = config.get("audit")
            assert isinstance(audit_section, Mapping)
            worm_cfg = audit_section.get("worm")
            assert isinstance(worm_cfg, Mapping)
            retention_days = int(worm_cfg.get("retention_days") or 2_555)
            worm_report = self._worm_pusher(
                audit_dir=self._audit_dir,
                today=today,
                sink=sink,
                retention_days=retention_days,
            )
            if any(
                value not in {"pushed", "re-pushed (changed)", "already pushed"}
                for value in worm_report.values()
            ):
                raise UnifiedAuditCustodyError("custody WORM operation is incomplete")

        siem_lines: list[str] = []
        next_cursor = dict(cursor) if isinstance(cursor, Mapping) else None
        if settings.siem_enable:
            siem_lines, next_cursor = _siem_batch(
                files,
                cursor=cursor,
                tenant_sha256=tenant_digest,
                limit=settings.max_siem_events_per_run,
            )
            if siem_lines:
                self._assert_authority(authority_digest)
                destination = _resolved_siem_destination(settings, tenant_digest)
                count = self._siem_forwarder(siem_lines, destination)
                if count != len(siem_lines):
                    raise UnifiedAuditCustodyError("custody SIEM delivery was incomplete")
                self._assert_authority(authority_digest)

        # Every side effect above is idempotent or at-least-once. Recheck the
        # exact policy one final time before advancing the durable cursor.
        self._assert_authority(authority_digest)

        custodied = sum(
            value in {"pushed", "re-pushed (changed)", "already pushed"}
            for value in worm_report.values()
        )
        body = {
            "schema": _RUN_SCHEMA,
            "outcome": "completed",
            "checkpoint_published": checkpoint_published,
            "checkpoint_verified": checkpoint_verified,
            "worm_files_considered": len(worm_report),
            "worm_files_custodied": custodied,
            "siem_events_forwarded": len(siem_lines),
            "siem_replay_possible": bool(siem_lines),
            "next_retry_at": 0.0,
            "authority_sha256": authority_digest,
            "tenant_sha256": tenant_digest,
        }
        return (
            CustodyRunResult(
                outcome="completed",
                checkpoint_published=checkpoint_published,
                checkpoint_verified=checkpoint_verified,
                worm_files_considered=len(worm_report),
                worm_files_custodied=custodied,
                siem_events_forwarded=len(siem_lines),
                siem_replay_possible=bool(siem_lines),
                next_retry_at=0.0,
                run_sha256=_sha256(body),
            ),
            next_cursor,
        )


__all__ = [
    "authority_sha256",
    "CustodyRunResult",
    "CustodySettings",
    "enabled",
    "settings_from",
    "UnifiedAuditCustodyBackoff",
    "UnifiedAuditCustodyError",
    "UnifiedAuditCustodyRuntime",
]
