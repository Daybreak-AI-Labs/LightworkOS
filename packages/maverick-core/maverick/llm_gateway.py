"""A governed pass-through LLM gateway for agents that never enroll.

This covers agents that are not enrolled: agents built anywhere point their
OpenAI-compatible base URL at Lightwork instead of the provider, and every call crosses a governed checkpoint — its own bearer, a
model allowlist, bounded bodies, the platform's SSRF-pinned and
enterprise-egress-guarded upstream path — while a caller ledger turns
unknown traffic into shadow-AI discovery. Bodies are never stored: the
ledger keeps caller digests, models, counts, token usage, and content
digests only.

Current scope, stated plainly: independently configured fixed OpenAI
``/v1/chat/completions`` and native Anthropic ``/v1/messages`` upstreams,
optional deterministic prompt screening plus secret/PII redaction on both
directions, and durable per-bearer-team call/input/output ceilings. Streaming,
the OpenAI Responses API, provider contract acceptance, and traffic that never
arrives at the gateway are out of scope.  Interception is opt-in per estate:
point the agents at the gateway; nothing here can see traffic that never
arrives.

Kernel rule 3 (budget caps) and this gateway, decided: proxied calls are
the CALLER's spend on the caller's own provider key, not a kernel agent
run, so they do not flow through :class:`maverick.budget.Budget` — there
is no goal, no role, and no platform dollar at stake. The governed limits
that do apply here are the gateway's own: bearer auth, the model
allowlist, bounded request/response bodies, and the caller ledger that
makes the spend visible. Routing a foreign agent's tokens through a
kernel Budget would cap someone else's bill with the platform's knobs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import runtime_metrics
from .constant_time import text_equals
from .governed_records import GovernedRecordStore, RecordConflict

log = logging.getLogger(__name__)

LEDGER_SCHEMA = "lightwork.llm-gateway-caller.v1"
_LEDGER = GovernedRecordStore("llm_gateway", "LGC", "llm_gateway_caller")
_MAX_CALLERS = 2_000
_MAX_LIST = 500
_ABS_MAX_BODY = 4 * 1024 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_UPSTREAM_TIMEOUT_SECONDS = 120.0
_MAX_TEAMS = 128
_MAX_TEAM_BUDGET = 2_000_000_000
_MAX_COMPLETION_TOKENS = 1_000_000
_TEAM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_ANTHROPIC_VERSION_RE = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}\Z")
TEAM_BUDGET_SCHEMA = "lightwork.llm-gateway-team-budget.v1"


# Credentials the dashboard may store sealed in the settings overlay.
_SECRET_KEYS = ("gateway_token", "upstream_token", "anthropic_upstream_token")


def _token(env_name: str, config_key: str) -> str:
    """A gateway credential: its environment variable, else the sealed setting.

    Read on demand and never copied into the settings dict, so status views
    that show the gateway configuration can never carry a credential.
    """
    value = os.environ.get(env_name, "")
    if value:
        return value
    try:
        from .config import load_global_config

        section = (load_global_config() or {}).get("llm_gateway") or {}
    except Exception:
        return ""
    stored = section.get(config_key) if isinstance(section, dict) else None
    return stored.strip() if isinstance(stored, str) else ""


class LLMGatewayError(RuntimeError):
    """Base failure for the governed LLM gateway."""


class LLMGatewayConfigError(LLMGatewayError):
    """The gateway is not enabled or configured safely."""


def _team_password_names(section: Mapping[str, Any]) -> tuple[str, ...]:
    """Teams with a sealed dashboard password (``[llm_gateway.team_passwords]``).

    Validated like ``team_tokens`` names; the passwords themselves never leave
    :func:`_team_password`."""
    raw = section.get("team_passwords", {})
    if not isinstance(raw, dict) or len(raw) > _MAX_TEAMS:
        raise LLMGatewayConfigError("llm_gateway.team_passwords must be a bounded team table")
    for team, password in raw.items():
        if not isinstance(team, str) or team == "default" or not _TEAM_RE.fullmatch(team):
            raise LLMGatewayConfigError("llm_gateway team name is invalid")
        if not isinstance(password, str) or not password.strip():
            raise LLMGatewayConfigError(f"llm_gateway.team_passwords.{team} must be text")
    return tuple(sorted(raw))


def _team_password(team: str) -> str:
    """A team's sealed dashboard password, read on demand (never kept in settings)."""
    try:
        from .config import load_global_config

        section = (load_global_config() or {}).get("llm_gateway") or {}
    except Exception:
        return ""
    table = section.get("team_passwords") if isinstance(section, dict) else None
    stored = table.get(team) if isinstance(table, dict) else None
    return stored.strip() if isinstance(stored, str) else ""


def get_llm_gateway_config() -> dict[str, Any]:  # noqa: C901 - strict config boundary
    from .config import load_global_config

    try:
        config = load_global_config()
    except Exception as exc:
        raise LLMGatewayConfigError("llm_gateway configuration is unavailable") from exc
    section = (config or {}).get("llm_gateway") or {}
    if not isinstance(section, dict):
        raise LLMGatewayConfigError("llm_gateway must be a table")
    known = {
        "enable",
        "upstream_url",
        "upstream_token_env",
        "gateway_token_env",
        "allowed_models",
        "max_body_bytes",
        "screen_prompts",
        "redact_prompts",
        "redact_completions",
        "anthropic_upstream_url",
        "anthropic_upstream_token_env",
        "anthropic_version",
        "team_tokens",
        "team_budgets",
        "budget_window_seconds",
        "default_max_output_tokens",
        # Sealed dashboard secrets; the environment variables named by the
        # *_token_env keys still win (see _token).
        *_SECRET_KEYS,
        # Per-team passwords sealed on the dashboard (see _team_password).
        "team_passwords",
    }
    unknown = set(section) - known
    if unknown:
        raise LLMGatewayConfigError(
            f"unknown llm_gateway keys: {', '.join(sorted(unknown))}"
        )
    for key in _SECRET_KEYS:
        if key in section and not isinstance(section[key], str):
            raise LLMGatewayConfigError(f"llm_gateway.{key} must be text")
    flag = section.get("enable", False)
    if not isinstance(flag, bool):
        raise LLMGatewayConfigError("llm_gateway.enable must be a boolean")
    upstream = str(section.get("upstream_url") or "").strip().rstrip("/")
    if flag and not upstream.startswith("https://"):
        raise LLMGatewayConfigError("llm_gateway.upstream_url must be an https URL")
    upstream_token_env = str(
        section.get("upstream_token_env") or "LLM_GATEWAY_UPSTREAM_TOKEN"
    ).strip()
    gateway_token_env = str(
        section.get("gateway_token_env") or "MAVERICK_GATEWAY_TOKEN"
    ).strip()
    if not upstream_token_env or not gateway_token_env:
        raise LLMGatewayConfigError("llm_gateway token env names must be non-empty")
    if not _ENV_RE.fullmatch(upstream_token_env) or not _ENV_RE.fullmatch(
        gateway_token_env
    ):
        raise LLMGatewayConfigError(
            "llm_gateway token env names must be environment variable names"
        )
    models = section.get("allowed_models", [])
    if not isinstance(models, list) or not all(
        isinstance(model, str) and model.strip() for model in models
    ):
        raise LLMGatewayConfigError("llm_gateway.allowed_models must be a string list")
    max_body = section.get("max_body_bytes", 1024 * 1024)
    if (
        isinstance(max_body, bool)
        or not isinstance(max_body, int)
        or not 4096 <= max_body <= _ABS_MAX_BODY
    ):
        raise LLMGatewayConfigError(
            f"llm_gateway.max_body_bytes must be between 4096 and {_ABS_MAX_BODY}"
        )
    screen = section.get("screen_prompts", False)
    if not isinstance(screen, bool):
        raise LLMGatewayConfigError("llm_gateway.screen_prompts must be a boolean")
    redact_prompts = section.get("redact_prompts", False)
    redact_completions = section.get("redact_completions", False)
    if not isinstance(redact_prompts, bool) or not isinstance(
        redact_completions, bool
    ):
        raise LLMGatewayConfigError(
            "llm_gateway redaction settings must be booleans"
        )
    anthropic_upstream = str(
        section.get("anthropic_upstream_url") or ""
    ).strip().rstrip("/")
    if anthropic_upstream and not anthropic_upstream.startswith("https://"):
        raise LLMGatewayConfigError(
            "llm_gateway.anthropic_upstream_url must be an https URL"
        )
    anthropic_token_env = str(
        section.get("anthropic_upstream_token_env")
        or "LLM_GATEWAY_ANTHROPIC_TOKEN"
    ).strip()
    if not _ENV_RE.fullmatch(anthropic_token_env):
        raise LLMGatewayConfigError(
            "llm_gateway.anthropic_upstream_token_env must be an environment "
            "variable name"
        )
    anthropic_version = str(
        section.get("anthropic_version") or "2023-06-01"
    ).strip()
    if not _ANTHROPIC_VERSION_RE.fullmatch(anthropic_version):
        raise LLMGatewayConfigError(
            "llm_gateway.anthropic_version must be an ISO date such as 2023-06-01"
        )
    team_tokens_raw = section.get("team_tokens", {})
    if not isinstance(team_tokens_raw, dict) or len(team_tokens_raw) > _MAX_TEAMS:
        raise LLMGatewayConfigError(
            "llm_gateway.team_tokens must be a bounded team-to-env table"
        )
    team_tokens: list[tuple[str, str]] = []
    seen_envs = {gateway_token_env}
    for team, env_name in sorted(team_tokens_raw.items(), key=lambda item: str(item[0])):
        if (
            not isinstance(team, str)
            or team == "default"
            or not _TEAM_RE.fullmatch(team)
        ):
            raise LLMGatewayConfigError("llm_gateway team name is invalid")
        if not isinstance(env_name, str) or not _ENV_RE.fullmatch(env_name):
            raise LLMGatewayConfigError(
                f"llm_gateway.team_tokens.{team} must name an environment variable"
            )
        if env_name in seen_envs:
            raise LLMGatewayConfigError(
                "llm_gateway team token env names must be unique"
            )
        seen_envs.add(env_name)
        team_tokens.append((team, env_name))
    team_password_teams = _team_password_names(section)
    budget_window = section.get("budget_window_seconds", 3_600)
    if (
        isinstance(budget_window, bool)
        or not isinstance(budget_window, int)
        or not 60 <= budget_window <= 31_622_400
    ):
        raise LLMGatewayConfigError(
            "llm_gateway.budget_window_seconds must be between 60 and 31622400"
        )
    default_max_output = section.get("default_max_output_tokens", 4_096)
    if (
        isinstance(default_max_output, bool)
        or not isinstance(default_max_output, int)
        or not 1 <= default_max_output <= _MAX_COMPLETION_TOKENS
    ):
        raise LLMGatewayConfigError(
            "llm_gateway.default_max_output_tokens must be between 1 and 1000000"
        )
    team_budgets_raw = section.get("team_budgets", {})
    if not isinstance(team_budgets_raw, dict) or len(team_budgets_raw) > _MAX_TEAMS:
        raise LLMGatewayConfigError(
            "llm_gateway.team_budgets must be a bounded team table"
        )
    known_teams = {"default", *(team for team, _env in team_tokens), *team_password_teams}
    team_budgets: list[tuple[str, dict[str, int]]] = []
    for team, raw_budget in sorted(
        team_budgets_raw.items(), key=lambda item: str(item[0])
    ):
        if not isinstance(team, str) or team not in known_teams:
            raise LLMGatewayConfigError(
                "llm_gateway.team_budgets may only name default or configured teams"
            )
        if not isinstance(raw_budget, dict):
            raise LLMGatewayConfigError(
                f"llm_gateway.team_budgets.{team} must be a table"
            )
        unknown_budget = set(raw_budget) - {
            "max_requests", "max_prompt_tokens", "max_completion_tokens"
        }
        if unknown_budget:
            raise LLMGatewayConfigError(
                f"llm_gateway.team_budgets.{team} has unknown keys: "
                + ", ".join(sorted(str(key) for key in unknown_budget))
            )
        budget: dict[str, int] = {}
        for key in (
            "max_requests", "max_prompt_tokens", "max_completion_tokens"
        ):
            value = raw_budget.get(key, 0)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= _MAX_TEAM_BUDGET
            ):
                raise LLMGatewayConfigError(
                    f"llm_gateway.team_budgets.{team}.{key} must be between "
                    f"0 and {_MAX_TEAM_BUDGET}"
                )
            budget[key] = int(value)
        team_budgets.append((team, budget))
    return {
        "enable": flag,
        "upstream_url": upstream,
        "upstream_token_env": upstream_token_env,
        "gateway_token_env": gateway_token_env,
        "allowed_models": [model.strip() for model in models],
        "max_body_bytes": max_body,
        "screen_prompts": screen,
        "redact_prompts": redact_prompts,
        "redact_completions": redact_completions,
        "anthropic_upstream_url": anthropic_upstream,
        "anthropic_upstream_token_env": anthropic_token_env,
        "anthropic_version": anthropic_version,
        "team_tokens": tuple(team_tokens),
        # Team names only: the passwords are read on demand (_team_password).
        "team_password_teams": team_password_teams,
        "team_budgets": tuple(team_budgets),
        "budget_window_seconds": int(budget_window),
        "default_max_output_tokens": int(default_max_output),
    }


def enabled() -> bool:
    try:
        return get_llm_gateway_config()["enable"] is True
    except Exception:
        return False


def _caller_digest(team: str) -> str:
    """Return a stable opaque caller key without retaining bearer material."""

    return hashlib.sha256(f"llm-gateway-team:{team}".encode()).hexdigest()[:24]


def _team_for_token(caller_token: str, settings: Mapping[str, Any]) -> str | None:
    """Resolve a configured opaque team only through its dedicated bearer.

    A caller cannot choose a team with a header or request field: that would
    let it move spending to another team's budget.  The legacy
    ``gateway_token_env`` maps to ``default`` so deployments retain their
    existing one-token setup, while an operator may add team-specific env
    references under ``[llm_gateway.team_tokens]``.
    """

    token = str(caller_token or "")
    if not token:
        return None
    candidates = [("default", str(settings["gateway_token_env"]))]
    candidates.extend(
        (str(team), str(env_name))
        for team, env_name in settings.get("team_tokens", ())
    )
    # A team with only a dashboard password; a team named in both uses its
    # environment variable when that is set (the environment wins).
    named = {team for team, _env in candidates}
    candidates.extend(
        (str(team), "") for team in settings.get("team_password_teams", ())
        if team not in named
    )
    matched: list[str] = []
    for team, env_name in candidates:
        if team == "default":
            expected = _token(env_name, "gateway_token")
        else:
            expected = (os.environ.get(env_name, "") if env_name else "") \
                or _team_password(team)
        if expected and text_equals(token, expected):
            matched.append(team)
    # A malformed deployment environment with duplicate secret VALUES should
    # not make budget identity ambiguous.  Fail closed instead of selecting
    # the first table entry.
    return matched[0] if len(matched) == 1 else None


def _authorized(caller_token: str, settings: Mapping[str, Any]) -> bool:
    return _team_for_token(caller_token, settings) is not None


def verify_gateway_bearer(token: str) -> bool:
    """Whether ``token`` is the configured gateway bearer.

    The one public auth check for every gateway-credentialed surface, so
    the web layer never reaches into private helpers and a hardening
    change lands everywhere at once. False when the gateway is disabled
    or unconfigured.
    """

    try:
        settings = get_llm_gateway_config()
    except LLMGatewayConfigError:
        return False
    if settings["enable"] is not True:
        return False
    return _authorized(str(token or ""), settings)


@dataclass(frozen=True)
class TeamBudgetReservation:
    """A conservative pre-egress reservation for one external completion.

    Foreign LLM traffic must not be charged to a kernel-agent ``Budget``:
    there is no platform goal or platform provider account.  Instead this
    records only an operator-configured team ceiling.  Input is estimated
    conservatively before egress and output is reserved from the request's
    declared cap; a confirmed smaller provider usage may release capacity.
    If the gateway loses the post-egress response, the reservation remains.
    """

    allowed: bool
    reason: str
    team: str
    window_started: float | None = None
    prompt_reserved: int = 0
    completion_reserved: int = 0
    remaining_requests: int | None = None
    remaining_prompt_tokens: int | None = None
    remaining_completion_tokens: int | None = None


class TeamTokenBudget:
    """Durable, cross-process fixed-window token/call limiter.

    This is intentionally small and local like the sidecar call budget.  Its
    state contains only a SHA-256 team key, counters, and window timestamp —
    never bearer values, prompts, completions, model names, or provider
    responses.  Any unavailable/malformed authority fails closed when a
    ceiling is configured.
    """

    def __init__(self, *, path: Path | None = None, clock: Callable[[], float] | None = None) -> None:
        self._path = path
        self._clock = clock or time.time

    def _state_path(self) -> Path:
        if self._path is not None:
            return self._path
        from .paths import data_dir

        # Keep budget state in a distinct private directory.  The caller
        # ledger is a governed-record collection under ``llm_gateway`` and
        # treats any foreign JSON filename in that directory as tampering.
        return data_dir("llm_gateway_team_budget", "team_budget.json")

    @staticmethod
    def _enabled(limits: Mapping[str, int]) -> bool:
        return any(int(limits.get(key, 0) or 0) > 0 for key in (
            "max_requests", "max_prompt_tokens", "max_completion_tokens"
        ))

    @staticmethod
    def _row_key(team: str) -> str:
        return hashlib.sha256(f"llm-gateway-budget:{team}".encode()).hexdigest()

    def reserve(
        self,
        team: str,
        limits: Mapping[str, int],
        *,
        prompt_tokens: int,
        completion_tokens: int,
        window_seconds: int,
        now: float | None = None,
    ) -> TeamBudgetReservation:
        """Reserve worst-case usage before the request crosses egress."""

        if not self._enabled(limits):
            return TeamBudgetReservation(True, "budget_disabled", team)
        if (
            not isinstance(prompt_tokens, int)
            or not isinstance(completion_tokens, int)
            or prompt_tokens < 0
            or completion_tokens < 0
        ):
            return TeamBudgetReservation(False, "budget_invalid_request", team)
        current_time = float(self._clock() if now is None else now)
        if not current_time > 0:
            return TeamBudgetReservation(False, "budget_authority", team)
        path = self._state_path()
        try:
            from .file_lock import (
                atomic_read_text,
                atomic_write_text,
                cross_process_lock,
                ensure_private_directory,
                ensure_private_file,
            )

            ensure_private_directory(path.parent)
            with cross_process_lock(path, strict=True):
                state: dict[str, Any] = {"schema": TEAM_BUDGET_SCHEMA, "rows": {}}
                if path.exists():
                    ensure_private_file(path)
                    raw = atomic_read_text(path)
                    if len(raw.encode("utf-8")) > _MAX_RESPONSE_BYTES:
                        raise ValueError("team budget state exceeds its byte bound")
                    state = json.loads(raw)
                if (
                    not isinstance(state, dict)
                    or state.get("schema") != TEAM_BUDGET_SCHEMA
                    or not isinstance(state.get("rows"), dict)
                ):
                    raise ValueError("team budget state is malformed")
                rows = state["rows"]
                key = self._row_key(team)
                row = rows.get(key, {})
                if not isinstance(row, dict):
                    raise ValueError("team budget row is malformed")
                started = row.get("window_started")
                used_requests = row.get("requests")
                used_prompt = row.get("prompt_tokens")
                used_completion = row.get("completion_tokens")
                invalid_row = (
                    isinstance(started, bool)
                    or not isinstance(started, (int, float))
                    or isinstance(used_requests, bool)
                    or not isinstance(used_requests, int)
                    or isinstance(used_prompt, bool)
                    or not isinstance(used_prompt, int)
                    or isinstance(used_completion, bool)
                    or not isinstance(used_completion, int)
                    or used_requests < 0
                    or used_prompt < 0
                    or used_completion < 0
                    or current_time < float(started)
                    or current_time - float(started) >= window_seconds
                )
                if invalid_row:
                    started, used_requests, used_prompt, used_completion = (
                        current_time, 0, 0, 0
                    )
                proposed_requests = used_requests + 1
                proposed_prompt = used_prompt + prompt_tokens
                proposed_completion = used_completion + completion_tokens
                max_requests = int(limits.get("max_requests", 0) or 0)
                max_prompt = int(limits.get("max_prompt_tokens", 0) or 0)
                max_completion = int(limits.get("max_completion_tokens", 0) or 0)
                if (
                    (max_requests and proposed_requests > max_requests)
                    or (max_prompt and proposed_prompt > max_prompt)
                    or (max_completion and proposed_completion > max_completion)
                ):
                    return TeamBudgetReservation(
                        False,
                        "budget_exhausted",
                        team,
                        window_started=float(started),
                        remaining_requests=(
                            max(0, max_requests - used_requests)
                            if max_requests else None
                        ),
                        remaining_prompt_tokens=(
                            max(0, max_prompt - used_prompt) if max_prompt else None
                        ),
                        remaining_completion_tokens=(
                            max(0, max_completion - used_completion)
                            if max_completion else None
                        ),
                    )
                rows[key] = {
                    "window_started": float(started),
                    "requests": proposed_requests,
                    "prompt_tokens": proposed_prompt,
                    "completion_tokens": proposed_completion,
                }
                atomic_write_text(
                    path,
                    json.dumps(state, sort_keys=True, separators=(",", ":")),
                    mode=0o600,
                )
                return TeamBudgetReservation(
                    True,
                    "budget_reserved",
                    team,
                    window_started=float(started),
                    prompt_reserved=prompt_tokens,
                    completion_reserved=completion_tokens,
                    remaining_requests=(
                        max(0, max_requests - proposed_requests) if max_requests else None
                    ),
                    remaining_prompt_tokens=(
                        max(0, max_prompt - proposed_prompt) if max_prompt else None
                    ),
                    remaining_completion_tokens=(
                        max(0, max_completion - proposed_completion)
                        if max_completion else None
                    ),
                )
        except Exception:
            log.warning("llm_gateway: team budget authority is unavailable", exc_info=True)
            return TeamBudgetReservation(False, "budget_authority", team)

    def reconcile(
        self,
        reservation: TeamBudgetReservation,
        *,
        prompt_tokens: int | None,
        completion_tokens: int | None,
        window_seconds: int,
        now: float | None = None,
    ) -> None:
        """Settle a reservation against confirmed provider usage.

        Reconciliation runs only after a bounded valid success payload.
        Unused reserved capacity is released; provider usage larger than the
        reservation is charged, so the overage counts against the team
        ceiling (later requests are refused) instead of being dropped.
        """

        if not reservation.allowed or reservation.window_started is None:
            return
        # Missing/malformed provider usage is not evidence of zero spend.
        # Keep the full pre-egress reservation in that case.
        prompt_release = (
            max(0, reservation.prompt_reserved - _safe_usage_int(prompt_tokens))
            if prompt_tokens is not None
            else 0
        )
        completion_release = (
            max(
                0,
                reservation.completion_reserved - _safe_usage_int(completion_tokens),
            )
            if completion_tokens is not None
            else 0
        )
        prompt_over = (
            max(0, _safe_usage_int(prompt_tokens) - reservation.prompt_reserved)
            if prompt_tokens is not None
            else 0
        )
        completion_over = (
            max(0, _safe_usage_int(completion_tokens) - reservation.completion_reserved)
            if completion_tokens is not None
            else 0
        )
        prompt_release -= prompt_over
        completion_release -= completion_over
        if not prompt_release and not completion_release:
            return
        current_time = float(self._clock() if now is None else now)
        path = self._state_path()
        try:
            from .file_lock import (
                atomic_read_text,
                atomic_write_text,
                cross_process_lock,
                ensure_private_directory,
                ensure_private_file,
            )

            ensure_private_directory(path.parent)
            with cross_process_lock(path, strict=True):
                if not path.exists():
                    return
                ensure_private_file(path)
                raw = atomic_read_text(path)
                if len(raw.encode("utf-8")) > _MAX_RESPONSE_BYTES:
                    return
                state = json.loads(raw)
                if (
                    not isinstance(state, dict)
                    or state.get("schema") != TEAM_BUDGET_SCHEMA
                    or not isinstance(state.get("rows"), dict)
                ):
                    return
                row = state["rows"].get(self._row_key(reservation.team))
                if not isinstance(row, dict):
                    return
                started = row.get("window_started")
                if (
                    isinstance(started, bool)
                    or not isinstance(started, (int, float))
                    or float(started) != reservation.window_started
                    or current_time < float(started)
                    or current_time - float(started) >= window_seconds
                ):
                    return
                prompt_used = row.get("prompt_tokens")
                completion_used = row.get("completion_tokens")
                if (
                    isinstance(prompt_used, bool)
                    or not isinstance(prompt_used, int)
                    or isinstance(completion_used, bool)
                    or not isinstance(completion_used, int)
                ):
                    return
                # A negative release charges provider usage above the reservation.
                row["prompt_tokens"] = max(0, prompt_used - prompt_release)
                row["completion_tokens"] = max(
                    0, completion_used - completion_release
                )
                atomic_write_text(
                    path,
                    json.dumps(state, sort_keys=True, separators=(",", ":")),
                    mode=0o600,
                )
        except Exception:
            # A success is already paid for.  Preserve the conservative
            # reservation and avoid changing the provider response.
            log.warning("llm_gateway: team budget reconciliation was skipped", exc_info=True)


def _safe_usage_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


_TEAM_BUDGET = TeamTokenBudget()


def _team_budget_limits(settings: Mapping[str, Any], team: str) -> dict[str, int]:
    """Return the reviewed ceiling for an authenticated team, if any."""

    for configured_team, limits in settings.get("team_budgets", ()):
        if configured_team == team and isinstance(limits, Mapping):
            return {
                key: _safe_usage_int(limits.get(key, 0))
                for key in (
                    "max_requests", "max_prompt_tokens", "max_completion_tokens"
                )
            }
    return {
        "max_requests": 0,
        "max_prompt_tokens": 0,
        "max_completion_tokens": 0,
    }


def _provider_error(provider: str, status: int, message: str) -> tuple[int, dict[str, Any]]:
    """Return a protocol-native, body-safe client error envelope."""

    if provider == "anthropic":
        error_type = (
            "authentication_error" if status == 401
            else "permission_error" if status == 403
            else "invalid_request_error" if 400 <= status < 500
            else "api_error"
        )
        return status, {"type": "error", "error": {"type": error_type, "message": message}}
    return status, {
        "error": {
            "message": message,
            "type": "invalid_request_error" if status < 500 else "server_error",
        }
    }


# Tool descriptions and schemas are shown to the model too, so they are
# screened, redacted and counted like message text.
_PROMPT_TEXT_KEYS = frozenset({
    "arguments", "content", "description", "input", "input_schema",
    "instructions", "parameters", "prompt", "system", "text",
})
_RESPONSE_TEXT_KEYS = frozenset({
    "arguments", "content", "input", "output_text", "refusal", "text",
})


def _json_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Copy JSON-compatible gateway data without retaining a caller object."""

    try:
        copied = json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise LLMGatewayError("the request must contain finite JSON-compatible data") from exc
    if not isinstance(copied, dict):  # defensive after a Mapping input
        raise LLMGatewayError("the request body must be a JSON object")
    return copied


def _redact_text(text: str) -> tuple[str, int]:
    """Apply secret then PII redaction, failing closed if the DLP path breaks."""

    try:
        from .safety.pii_detector import redact as redact_pii
        from .safety.secret_detector import redact as redact_secrets

        redacted, secret_matches = redact_secrets(text)
        redacted, pii_matches = redact_pii(redacted)
        return redacted, len(secret_matches) + len(pii_matches)
    except Exception as exc:
        raise LLMGatewayError("the gateway redaction authority is unavailable") from exc


def _transform_text_leaves(
    value: object,
    *,
    text_keys: frozenset[str],
    inherited_text: bool = False,
    depth: int = 0,
) -> tuple[object, int]:
    """Redact only semantic text fields, not model IDs or structural values."""

    if depth > 32:
        raise LLMGatewayError("the request nesting exceeds the gateway limit")
    if isinstance(value, str):
        return _redact_text(value) if inherited_text else (value, 0)
    if isinstance(value, list):
        out: list[object] = []
        total = 0
        for item in value:
            transformed, count = _transform_text_leaves(
                item, text_keys=text_keys, inherited_text=inherited_text, depth=depth + 1
            )
            out.append(transformed)
            total += count
        return out, total
    if isinstance(value, Mapping):
        out: dict[str, object] = {}
        total = 0
        for key, item in value.items():
            key_text = str(key)
            transformed, count = _transform_text_leaves(
                item,
                text_keys=text_keys,
                inherited_text=inherited_text or key_text in text_keys,
                depth=depth + 1,
            )
            out[key_text] = transformed
            total += count
        return out, total
    return value, 0


def _redact_prompt(body: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    copied = _json_copy(body)
    transformed, count = _transform_text_leaves(
        copied, text_keys=_PROMPT_TEXT_KEYS
    )
    if not isinstance(transformed, dict):  # pragma: no cover - guarded by _json_copy
        raise LLMGatewayError("the request body must be a JSON object")
    return transformed, count


def _redact_response(payload: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    copied = _json_copy(payload)
    transformed, count = _transform_text_leaves(
        copied, text_keys=_RESPONSE_TEXT_KEYS
    )
    if not isinstance(transformed, dict):  # pragma: no cover - guarded by _json_copy
        raise LLMGatewayError("the upstream response must be a JSON object")
    return transformed, count


def _collect_prompt_text(value: object, *, inherited_text: bool = False, depth: int = 0) -> list[str]:
    """Collect only text that can reach an LLM, for Shield and input reserve."""

    if depth > 32:
        return []
    if isinstance(value, str):
        return [value] if inherited_text else []
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            parts.extend(
                _collect_prompt_text(item, inherited_text=inherited_text, depth=depth + 1)
            )
        return parts
    if isinstance(value, Mapping):
        parts = []
        for key, item in value.items():
            parts.extend(
                _collect_prompt_text(
                    item,
                    inherited_text=inherited_text or str(key) in _PROMPT_TEXT_KEYS,
                    depth=depth + 1,
                )
            )
        return parts
    return []


def _estimate_prompt_tokens(body: Mapping[str, Any]) -> int:
    """Conservatively reserve input using UTF-8 bytes, never provider text."""

    # Four characters/token is often used as a rough accounting heuristic;
    # three UTF-8 bytes/token deliberately errs toward retaining less unused
    # capacity, not granting more.  This estimate is replaced with actual
    # provider usage only after a successful bounded response.
    size = sum(len(part.encode("utf-8", "ignore")) for part in _collect_prompt_text(body))
    return (size + 2) // 3 if size else 0


def _completion_cap(
    body: Mapping[str, Any],
    *,
    provider: str,
    require_cap: bool,
    default_cap: int,
) -> tuple[dict[str, Any], int]:
    """Return a bounded outbound copy and maximum completion reservation."""

    copied = _json_copy(body)
    keys = ("max_tokens",) if provider == "anthropic" else (
        "max_completion_tokens", "max_tokens"
    )
    value: object | None = None
    selected_key = keys[0]
    for key in keys:
        if key in copied:
            value = copied[key]
            selected_key = key
            break
    if value is None:
        if provider == "anthropic" or require_cap:
            value = default_cap
            copied[selected_key] = value
        else:
            return copied, 0
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_COMPLETION_TOKENS
    ):
        raise ValueError("the request completion-token cap must be between 1 and 1000000")
    # OpenAI ``n`` asks for that many completions, each up to the cap.
    choices = copied.get("n", 1) if provider != "anthropic" else 1
    if choices is None:
        choices = 1
    if isinstance(choices, bool) or not isinstance(choices, int) or not 1 <= choices <= 128:
        raise ValueError("the request choice count n must be between 1 and 128")
    return copied, int(value) * choices


def _usage_for_provider(
    provider: str, payload: Mapping[str, Any]
) -> dict[str, int] | None:
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        return None
    if provider == "anthropic":
        if "input_tokens" not in usage or "output_tokens" not in usage:
            return None
        return {
            "prompt_tokens": _safe_usage_int(usage.get("input_tokens")),
            "completion_tokens": _safe_usage_int(usage.get("output_tokens")),
        }
    if "prompt_tokens" not in usage or "completion_tokens" not in usage:
        return None
    return {
        "prompt_tokens": _safe_usage_int(usage.get("prompt_tokens")),
        "completion_tokens": _safe_usage_int(usage.get("completion_tokens")),
    }


def _default_upstream(
    url: str, headers: Mapping[str, str], body: Mapping[str, Any],
) -> tuple[int, Any]:
    """POST through the SSRF-pinned, enterprise-egress-guarded client."""

    from .enterprise import enterprise_egress_denial
    from .tools._ssrf import BlockedHost, safe_client

    deny = enterprise_egress_denial(url, tool="llm_gateway")
    if deny:
        raise LLMGatewayError(deny)
    try:
        with safe_client(url, timeout=_UPSTREAM_TIMEOUT_SECONDS) as client:
            response = client.post(url, headers=dict(headers), json=dict(body))
    except BlockedHost as exc:
        raise LLMGatewayError("blocked host (SSRF guard)") from exc
    text = response.text or ""
    if len(text.encode("utf-8", "ignore")) > _MAX_RESPONSE_BYTES:
        raise LLMGatewayError("upstream response exceeds the gateway byte cap")
    try:
        payload = response.json()
    except ValueError:
        payload = None
    return response.status_code, payload


def _record_call(
    *,
    caller: str,
    team: str = "default",
    model: str,
    status: str,
    prompt_sha256: str,
    usage: Mapping[str, Any] | None,
    now: float,
    requests: int = 1,
    redaction_count: int = 0,
) -> None:
    """Aggregate call(s) into the caller ledger; never store bodies.

    ``requests`` lets a pre-aggregated batch (OTel span ingestion) land as
    one CAS write instead of one per span.
    """

    runtime_metrics.increment(
        "lightwork_gateway_calls_total", status=str(status),
        amount=float(requests),
        help_text="LLM gateway calls by ledger status",
    )

    record_id = f"LGC-{hashlib.sha256(f'{caller}:{model}'.encode()).hexdigest()[:24]}"
    prompt_tokens = int((usage or {}).get("prompt_tokens") or 0)
    completion_tokens = int((usage or {}).get("completion_tokens") or 0)
    count = max(1, int(requests))
    safe_redaction_count = max(0, int(redaction_count))

    def mutate(row: dict[str, Any]) -> None:
        row["request_count"] = int(row.get("request_count") or 0) + count
        row["last_seen"] = now
        row["last_status"] = status
        row["last_prompt_sha256"] = prompt_sha256
        row["prompt_tokens"] = int(row.get("prompt_tokens") or 0) + prompt_tokens
        row["completion_tokens"] = (
            int(row.get("completion_tokens") or 0) + completion_tokens
        )
        row["redaction_count"] = int(row.get("redaction_count") or 0) + safe_redaction_count
        row["team"] = team

    # Shadow accounting must NEVER fail the call it is accounting for: by
    # the time this runs the upstream completion may already have been paid
    # for, and a full or contended ledger is not the caller's problem. Every
    # store outcome short of success degrades to a logged, dropped row.
    for _ in range(3):
        current = _LEDGER.get(record_id)
        if current is None:
            record = {
                "id": record_id,
                "schema": LEDGER_SCHEMA,
                "caller_digest": caller,
                "team": team,
                "model": model,
                "request_count": count,
                "first_seen": now,
                "last_seen": now,
                "last_status": status,
                "last_prompt_sha256": prompt_sha256,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "redaction_count": safe_redaction_count,
            }
            try:
                _LEDGER.create(
                    record,
                    action="llm_gateway_call",
                    actor="gateway:llm",
                    max_records=_MAX_CALLERS,
                )
                return
            except RecordConflict:
                continue
            except Exception:
                # Capacity reached (each blocked_model refusal and each
                # OTel service/model pair mints a row, so an outsider can
                # force this) or a backend fault: drop the row, keep the
                # response.
                log.warning(
                    "llm_gateway: caller ledger write dropped (capacity or "
                    "backend fault); the call itself is unaffected"
                )
                return
        try:
            saved = _LEDGER.update(
                record_id,
                mutate,
                expected_revision=int(current.get("revision") or 0),
                action="llm_gateway_call",
                actor="gateway:llm",
            )
        except RecordConflict:
            # Concurrent same-caller call won the CAS: re-read and retry.
            continue
        except Exception:
            log.warning(
                "llm_gateway: caller ledger update dropped (backend fault); "
                "the call itself is unaffected"
            )
            return
        if saved is not None:
            return
    log.warning("llm_gateway: caller ledger update lost a CAS race repeatedly")


_SCREEN_MAX_CHARS = 200_000
_SCREEN_OVERLAP_CHARS = 4_096


def _screen_messages(body: Mapping[str, Any]):
    """Deny-wins content screen over the request's message texts.

    Uses the in-kernel deterministic detector ensemble (injection, exfil,
    PII) — never the optional agent-shield SDK, so the gateway works
    without it (kernel rule: fail open on absence, but a FIRING detector
    still blocks). Returns the verdict, or None when there is no text.
    """

    text = "\n".join(chunk for chunk in _collect_prompt_text(body) if chunk)
    if not text:
        return None
    try:
        from .shield_ensemble import ShieldEnsemble

        # Every character is screened, in overlapping windows so a pattern
        # that straddles a window edge is still seen. Deny wins.
        ensemble = ShieldEnsemble()
        step = _SCREEN_MAX_CHARS - _SCREEN_OVERLAP_CHARS
        verdict = None
        for start in range(0, len(text), step):
            verdict = ensemble.evaluate(text[start:start + _SCREEN_MAX_CHARS])
            if not verdict.allowed:
                break
        return verdict
    except Exception as exc:
        error_type = re.sub(r"[^A-Za-z0-9_.-]", "_", type(exc).__name__)[:64]
        log.warning("llm_gateway: content screen unavailable; blocking (%s)", error_type)
        raise LLMGatewayError("The gateway's content screen is unavailable.") from exc


def _otel_attr(attributes: list, key: str) -> str:
    for attribute in attributes or []:
        if not isinstance(attribute, Mapping):
            continue
        if str(attribute.get("key") or "") != key:
            continue
        value = attribute.get("value")
        if isinstance(value, Mapping):
            for kind in ("stringValue", "intValue", "doubleValue", "boolValue"):
                if kind in value:
                    return str(value[kind])
    return ""


def ingest_otel_spans(payload: object) -> dict[str, int]:
    """Ingest OTLP/JSON GenAI spans into the shadow-caller ledger.

    Reads the OpenTelemetry GenAI semantic conventions — ``gen_ai.system``,
    ``gen_ai.request.model``, ``gen_ai.usage.input_tokens`` /
    ``output_tokens`` — from ``resourceSpans[].scopeSpans[].spans[]`` and
    aggregates one ledger row per (service, model). Span bodies, prompts,
    and completions are never read or stored; only the model identity and
    token counts. Any agent framework exporting standard OTel traces
    becomes governed telemetry without an SDK.
    """

    settings = get_llm_gateway_config()
    if settings["enable"] is not True:
        raise LLMGatewayConfigError(
            "the LLM gateway requires [llm_gateway] enable = true"
        )
    if not isinstance(payload, Mapping):
        raise ValueError("the OTLP payload must be a JSON object")
    now = time.time()
    ingested = 0
    skipped = 0
    # Pre-aggregate per (caller, model): a collector batch commonly holds
    # hundreds of spans for one service+model, and one governed CAS write
    # per PAIR beats one per span. Any malformed span — wrong shapes,
    # non-numeric usage values — counts as skipped and never aborts the
    # batch (a mid-batch abort plus collector retry double-counts).
    totals: dict[tuple[str, str], dict[str, int]] = {}
    for resource_spans in list(payload.get("resourceSpans") or [])[:100]:
        if not isinstance(resource_spans, Mapping):
            skipped += 1
            continue
        resource = resource_spans.get("resource") or {}
        service = _otel_attr(
            resource.get("attributes") if isinstance(resource, Mapping) else [],
            "service.name",
        ) or "unknown-service"
        caller = hashlib.sha256(
            f"otel-service:{service}".encode()
        ).hexdigest()[:24]
        for scope_spans in list(resource_spans.get("scopeSpans") or [])[:100]:
            if not isinstance(scope_spans, Mapping):
                continue
            for span in list(scope_spans.get("spans") or [])[:1000]:
                try:
                    if not isinstance(span, Mapping):
                        raise ValueError("span must be an object")
                    attributes = span.get("attributes") or []
                    system = _otel_attr(attributes, "gen_ai.system")
                    model = (
                        _otel_attr(attributes, "gen_ai.request.model")
                        or _otel_attr(attributes, "gen_ai.response.model")
                    )
                    if not system and not model:
                        raise ValueError("span carries no GenAI identity")
                    prompt_tokens = int(float(
                        _otel_attr(attributes, "gen_ai.usage.input_tokens")
                        or 0
                    ))
                    completion_tokens = int(float(
                        _otel_attr(attributes, "gen_ai.usage.output_tokens")
                        or 0
                    ))
                except Exception:
                    skipped += 1
                    continue
                bucket = totals.setdefault(
                    (caller, model or f"{system}:unknown"),
                    {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0},
                )
                bucket["requests"] += 1
                bucket["prompt_tokens"] += max(0, prompt_tokens)
                bucket["completion_tokens"] += max(0, completion_tokens)
                ingested += 1
    for (caller, model), bucket in totals.items():
        _record_call(
            caller=caller,
            model=model,
            status="otel",
            prompt_sha256="",
            usage={
                "prompt_tokens": bucket["prompt_tokens"],
                "completion_tokens": bucket["completion_tokens"],
            },
            now=now,
            requests=bucket["requests"],
        )
    return {"ingested": ingested, "skipped": skipped}


def _provider_upstream(
    provider: str, settings: Mapping[str, Any]
) -> tuple[str, dict[str, str]]:
    """Resolve one fixed provider endpoint and never accept it from callers."""

    if provider == "anthropic":
        base = str(settings.get("anthropic_upstream_url") or "")
        if not base:
            raise LLMGatewayConfigError(
                "Anthropic compatibility requires llm_gateway.anthropic_upstream_url"
            )
        token = _token(str(settings["anthropic_upstream_token_env"]), "anthropic_upstream_token")
        if not token:
            raise LLMGatewayError("The gateway's Anthropic upstream credential is not configured.")
        return f"{base}/v1/messages", {
            "x-api-key": token,
            "anthropic-version": str(settings["anthropic_version"]),
        }
    token = _token(str(settings["upstream_token_env"]), "upstream_token")
    if not token:
        raise LLMGatewayError("The gateway's upstream credential is not configured.")
    return f"{settings['upstream_url']}/v1/chat/completions", {
        "Authorization": f"Bearer {token}",
    }


def _handle_completion(  # noqa: C901 - the request boundary is deliberately linear
    body: object,
    *,
    caller_token: str,
    provider: str,
    upstream: Callable[[str, Mapping[str, str], Mapping[str, Any]], tuple[int, Any]]
    | None = None,
    now: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Enforce the common OpenAI/Anthropic runtime firewall chain."""

    settings = get_llm_gateway_config()
    if settings["enable"] is not True:
        raise LLMGatewayConfigError(
            "the LLM gateway requires [llm_gateway] enable = true"
        )
    team = _team_for_token(str(caller_token or ""), settings)
    if team is None:
        return _provider_error(provider, 401, "The gateway bearer is missing or wrong.")
    caller = _caller_digest(team)
    if not isinstance(body, Mapping):
        return _provider_error(provider, 400, "The request body must be a JSON object.")
    try:
        encoded = json.dumps(body, default=str, allow_nan=False).encode("utf-8", "ignore")
    except (TypeError, ValueError):
        return _provider_error(provider, 400, "The request must contain finite JSON data.")
    if len(encoded) > settings["max_body_bytes"]:
        return _provider_error(
            provider, 413, "The request exceeds the gateway's configured size cap."
        )
    model = str(body.get("model") or "").strip()
    if not model:
        return _provider_error(provider, 400, "The request names no model.")
    if body.get("stream"):
        return _provider_error(
            provider,
            400,
            "Streaming is not supported through this gateway yet; retry with stream disabled.",
        )
    current = time.time() if now is None else float(now)
    original_sha = hashlib.sha256(encoded).hexdigest()
    if settings["allowed_models"] and model not in settings["allowed_models"]:
        _record_call(
            caller=caller, team=team, model=model, status="blocked_model",
            prompt_sha256=original_sha, usage=None, now=current,
        )
        return _provider_error(
            provider, 403, f"Model {model!r} is not on the gateway's allowlist."
        )
    limits = _team_budget_limits(settings, team)
    try:
        outbound_body, completion_reservation = _completion_cap(
            body,
            provider=provider,
            require_cap=int(limits["max_completion_tokens"]) > 0,
            default_cap=int(settings["default_max_output_tokens"]),
        )
        prompt_redactions = 0
        if settings["redact_prompts"]:
            outbound_body, prompt_redactions = _redact_prompt(outbound_body)
        outbound_encoded = json.dumps(
            outbound_body, default=str, allow_nan=False
        ).encode("utf-8", "ignore")
    except ValueError as exc:
        return _provider_error(provider, 400, str(exc))
    except LLMGatewayError as exc:
        _record_call(
            caller=caller, team=team, model=model, status="redaction_unavailable",
            prompt_sha256=original_sha, usage=None, now=current,
        )
        return _provider_error(provider, 503, str(exc))
    if len(outbound_encoded) > settings["max_body_bytes"]:
        return _provider_error(
            provider, 413, "Redaction expanded the request beyond the gateway size cap."
        )
    prompt_sha = hashlib.sha256(outbound_encoded).hexdigest()
    if settings["screen_prompts"]:
        try:
            verdict = _screen_messages(outbound_body)
        except LLMGatewayError:
            _record_call(
                caller=caller, team=team, model=model, status="screen_unavailable",
                prompt_sha256=prompt_sha, usage=None, now=current,
                redaction_count=prompt_redactions,
            )
            return _provider_error(
                provider, 503,
                "The gateway's request safety check is unavailable. Nothing was sent "
                "to the AI service. Try again later or ask your administrator to check it.",
            )
        if verdict is not None and not verdict.allowed:
            _record_call(
                caller=caller, team=team, model=model, status="screened_blocked",
                prompt_sha256=prompt_sha, usage=None, now=current,
                redaction_count=prompt_redactions,
            )
            detectors = ", ".join(
                str(code.get("detector") or "unknown")
                for code in verdict.reason_codes
                if isinstance(code, Mapping)
            )
            return _provider_error(
                provider,
                403,
                "The gateway's content screen blocked this request "
                f"(severity {verdict.severity}; detectors: {detectors}). "
                "Contact your platform operator.",
            )
    try:
        url, headers = _provider_upstream(provider, settings)
    except LLMGatewayConfigError:
        raise
    except LLMGatewayError as exc:
        return _provider_error(provider, 503, str(exc))
    prompt_reservation = (
        _estimate_prompt_tokens(outbound_body)
        if int(limits["max_prompt_tokens"]) > 0
        else 0
    )
    reservation = _TEAM_BUDGET.reserve(
        team,
        limits,
        prompt_tokens=prompt_reservation,
        completion_tokens=(
            completion_reservation
            if int(limits["max_completion_tokens"]) > 0
            else 0
        ),
        window_seconds=int(settings["budget_window_seconds"]),
        now=current,
    )
    if not reservation.allowed:
        status = "budget_exhausted" if reservation.reason == "budget_exhausted" else "budget_authority"
        _record_call(
            caller=caller, team=team, model=model, status=status,
            prompt_sha256=prompt_sha, usage=None, now=current,
            redaction_count=prompt_redactions,
        )
        message = (
            "The gateway team budget is exhausted."
            if status == "budget_exhausted"
            else "The gateway team budget authority is unavailable; egress is denied."
        )
        return _provider_error(provider, 429 if status == "budget_exhausted" else 503, message)
    forward = upstream or _default_upstream
    try:
        status_code, payload = forward(url, headers, outbound_body)
    except LLMGatewayError as exc:
        _record_call(
            caller=caller, team=team, model=model, status="egress_denied",
            prompt_sha256=prompt_sha, usage=None, now=current,
            redaction_count=prompt_redactions,
        )
        return _provider_error(provider, 502, str(exc))
    except Exception:
        log.warning("llm_gateway: upstream request failed", exc_info=True)
        _record_call(
            caller=caller, team=team, model=model, status="upstream_error",
            prompt_sha256=prompt_sha, usage=None, now=current,
            redaction_count=prompt_redactions,
        )
        return _provider_error(provider, 502, "The upstream request failed.")
    if status_code >= 400 or not isinstance(payload, Mapping):
        _record_call(
            caller=caller, team=team, model=model, status=f"upstream_{status_code}",
            prompt_sha256=prompt_sha, usage=None, now=current,
            redaction_count=prompt_redactions,
        )
        return _provider_error(
            provider,
            502,
            f"The upstream returned status {status_code}; its body is not relayed through the gateway.",
        )
    usage = _usage_for_provider(provider, payload)
    response_redactions = 0
    try:
        response = _json_copy(payload)
        if settings["redact_completions"]:
            response, response_redactions = _redact_response(response)
    except LLMGatewayError as exc:
        # The upstream effect is known but an unredacted response is not safe
        # to relay.  Keep the reservation and report an explicit outage.
        _record_call(
            caller=caller, team=team, model=model, status="response_redaction_unavailable",
            prompt_sha256=prompt_sha, usage=None, now=current,
            redaction_count=prompt_redactions,
        )
        return _provider_error(provider, 503, str(exc))
    _TEAM_BUDGET.reconcile(
        reservation,
        prompt_tokens=usage["prompt_tokens"] if usage is not None else None,
        completion_tokens=(
            usage["completion_tokens"] if usage is not None else None
        ),
        window_seconds=int(settings["budget_window_seconds"]),
        now=current,
    )
    _record_call(
        caller=caller, team=team, model=model, status="ok",
        prompt_sha256=prompt_sha, usage=usage, now=current,
        redaction_count=prompt_redactions + response_redactions,
    )
    return 200, response


def handle_chat_completion(
    body: object,
    *,
    caller_token: str,
    upstream: Callable[[str, Mapping[str, str], Mapping[str, Any]], tuple[int, Any]]
    | None = None,
    now: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Handle one OpenAI-compatible ``/v1/chat/completions`` request."""

    return _handle_completion(
        body, caller_token=caller_token, provider="openai", upstream=upstream, now=now
    )


def handle_anthropic_message(
    body: object,
    *,
    caller_token: str,
    upstream: Callable[[str, Mapping[str, str], Mapping[str, Any]], tuple[int, Any]]
    | None = None,
    now: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Handle an Anthropic-compatible ``/v1/messages`` request.

    The endpoint follows the native Anthropic bearer/header shape upstream,
    but applies the exact same model, Shield, redaction, egress, team-budget,
    and privacy-safe ledger gates as the OpenAI-compatible endpoint.
    """

    return _handle_completion(
        body, caller_token=caller_token, provider="anthropic", upstream=upstream, now=now
    )


def gateway_status() -> dict[str, Any]:
    rows = _LEDGER.list(limit=_MAX_LIST)
    counts: dict[str, int] = {}
    callers: set[str] = set()
    requests = 0
    for row in rows:
        callers.add(str(row.get("caller_digest")))
        requests += int(row.get("request_count") or 0)
        status = str(row.get("last_status") or "")
        counts[status] = counts.get(status, 0) + 1
    return {
        "enabled": enabled(),
        "callers": len(callers),
        "caller_model_pairs": len(rows),
        "request_count": requests,
        "last_status_counts": counts,
    }


def list_callers(*, limit: int = 100) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
        raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
    rows = _LEDGER.list(limit=limit)
    rows.sort(key=lambda row: -float(row.get("last_seen") or 0.0))
    return [
        {
            "caller_digest": row.get("caller_digest"),
            "team": row.get("team", "default"),
            "model": row.get("model"),
            "request_count": row.get("request_count"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "last_status": row.get("last_status"),
            "prompt_tokens": row.get("prompt_tokens"),
            "completion_tokens": row.get("completion_tokens"),
            "redaction_count": row.get("redaction_count", 0),
        }
        for row in rows
    ]


__all__ = [
    "LLMGatewayConfigError",
    "LLMGatewayError",
    "LEDGER_SCHEMA",
    "TEAM_BUDGET_SCHEMA",
    "TeamTokenBudget",
    "enabled",
    "gateway_status",
    "get_llm_gateway_config",
    "handle_anthropic_message",
    "handle_chat_completion",
    "ingest_otel_spans",
    "list_callers",
    "verify_gateway_bearer",
]
