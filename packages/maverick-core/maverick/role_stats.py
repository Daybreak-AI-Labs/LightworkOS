"""Per-role credit tracking — routing memory fed by CSCA.

Counterfactual swarm credit (``maverick.credit``) tells us, after each fan-out,
which sub-agent *roles* actually moved the answer. This module accumulates that
signal across runs so the orchestrator can prefer the roles that historically
contribute and stop spawning the ones that ride along adding nothing. It's the
routing consumer of CSCA (the donation record is the learning consumer).

Storage: ``~/.maverick/role_stats.json`` (chmod 600), a flat map of
``role -> {runs, credit_sum, last}``. Fully fail-safe: stats are an
optimization, never a correctness dependency, so any I/O error degrades to "no
signal". Recording is gated on CSCA being enabled (``credit.enabled()``) since
that's what produces the signal.

Department dimension: a swarm spawned by a domain-pack agent records its
credit BOTH globally (key ``role``) and per department (key
``<domain>::<role>``), so routing guidance for a finance run is steered by
what contributed on past *finance* swarms, falling back to the global signal
when the department has too little history. Old stat files load unchanged.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .paths import data_dir

log = logging.getLogger(__name__)

DEFAULT_PATH = data_dir("role_stats.json")
_lock = threading.Lock()

_SAFE_ROLE_RE = re.compile(r"[^A-Za-z0-9_-]+")
_MAX_ROLE_LEN = 40


def safe_role(role: object) -> str | None:
    """Return a prompt-safe role key for routing memory, or None.

    Swarm roles are model-controlled.  Role stats are persisted across runs and
    later rendered into the orchestrator brief, so only compact identifier-like
    strings may enter this store.  Non-identifier runs are collapsed to hyphens
    and capped in length to avoid carrying prompt text across sessions.
    """
    if not isinstance(role, str):
        return None
    cleaned = _SAFE_ROLE_RE.sub("-", role.strip()).strip("-_").lower()
    if not cleaned:
        return None
    return cleaned[:_MAX_ROLE_LEN].rstrip("-_") or None


# Separator between the department tag and the role in a scoped stat key.
# "::" never appears in domain pack names (TOML stems) or role strings.
_SCOPE_SEP = "::"


def _safe_key(key: object) -> str | None:
    """Sanitize a possibly department-scoped stat key, preserving the scope.

    A scoped key is ``<domain>::<role>``; sanitize each segment with
    ``safe_role`` so model-controlled text can never enter the persisted store,
    while keeping the ``::`` separator intact so department lookups still work.
    """
    if not isinstance(key, str):
        return None
    if _SCOPE_SEP in key:
        domain, _, role = key.partition(_SCOPE_SEP)
        domain_key, role_key = safe_role(domain), safe_role(role)
        if domain_key is None or role_key is None:
            return None
        return f"{domain_key}{_SCOPE_SEP}{role_key}"
    return safe_role(key)


@dataclass
class RoleStat:
    runs: int = 0
    credit_sum: float = 0.0
    last: float = 0.0

    @property
    def avg_credit(self) -> float:
        return self.credit_sum / self.runs if self.runs else 0.0


def _resolve(path: Path | None) -> Path:
    if path is not None:
        return path
    return _tenant_path("role_stats.json", DEFAULT_PATH)


def _tenant_path(name: str, legacy):
    """Item-30 isolation: with an ACTIVE tenant, this store lives under the
    tenant's data dir (one tenant's learned memory can never feed another's
    runs); single-tenant resolution keeps the legacy location unchanged."""
    try:
        from .paths import current_tenant, data_dir
        if current_tenant():
            return data_dir(*name.split("/"))
    except Exception:  # pragma: no cover -- isolation never blocks resolution
        pass
    return legacy



def _load(path: Path) -> dict[str, RoleStat]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    out: dict[str, RoleStat] = {}
    if not isinstance(raw, dict):
        return {}
    for role, entry in raw.items():
        role_key = _safe_key(role)
        if role_key is None or not isinstance(entry, dict):
            continue
        try:
            st = RoleStat(
                runs=int(entry.get("runs", 0)),
                credit_sum=float(entry.get("credit_sum", 0.0)),
                last=float(entry.get("last", 0.0)),
            )
        except (TypeError, ValueError):
            continue
        if role_key in out:
            prev = out[role_key]
            prev.runs += st.runs
            prev.credit_sum += st.credit_sum
            prev.last = max(prev.last, st.last)
        else:
            out[role_key] = st
    return out


def _save(stats: dict[str, RoleStat], path: Path) -> None:
    # Atomic temp+replace: a bare write_text truncates in place, so a concurrent
    # _load() reader sees a half-written file -> its JSONDecodeError is swallowed
    # as an empty store and all accumulated routing credit is silently discarded.
    from .file_lock import atomic_write_text
    atomic_write_text(path, json.dumps({k: asdict(v) for k, v in stats.items()}))


def record(role: str, credit: float, path: Path | None = None, *,
           domain: str | None = None) -> None:
    """Accumulate one (role, marginal-credit) observation. Fail-safe no-op.

    With ``domain`` set, the observation lands in BOTH the global role entry
    and the department-scoped ``<domain>::<role>`` entry. Role and domain
    strings are model-controlled, so each is sanitized via ``safe_role`` before
    it enters the persisted store.
    """
    role_key = safe_role(role)
    if role_key is None:
        return
    path = _resolve(path)
    keys = [role_key]
    if domain:
        domain_key = safe_role(domain)
        if domain_key:
            keys.append(f"{domain_key}{_SCOPE_SEP}{role_key}")
    # In-process lock + cross-process flock: this is a per-fan-out hot path hit
    # from multiple concurrent processes; without the flock two writers both
    # load the same store and the second save clobbers the first's credit.
    from .file_lock import cross_process_lock
    with _lock, cross_process_lock(path):
        try:
            stats = _load(path)
            for key in keys:
                st = stats.get(key) or RoleStat()
                st.runs += 1
                st.credit_sum += float(credit)
                st.last = time.time()
                stats[key] = st
            _save(stats, path)
        except OSError as e:  # pragma: no cover -- stats never block a run
            log.debug("role_stats record failed: %s", e)


def record_credit(credit_by_name: dict[str, float], name_to_role: dict[str, str],
                  path: Path | None = None, *, domain: str | None = None) -> None:
    """Record a whole fan-out's credit, mapping agent names to their roles."""
    if not credit_by_name:
        return
    for name, c in credit_by_name.items():
        role = name_to_role.get(name)
        if role:
            record(role, c, path=path, domain=domain)


def top_roles(k: int = 5, *, min_runs: int = 2, path: Path | None = None,
              domain: str | None = None) -> list[tuple[str, float]]:
    """Roles ranked by average credit (only those with >= ``min_runs`` samples).

    With ``domain`` set, only that department's scoped entries are ranked
    (keys are returned with the scope stripped); otherwise only global ones.
    """
    stats = _load(_resolve(path))
    # Keys are stored under safe_role(domain) (see record); sanitize the lookup
    # the same way so a domain needing normalization still matches its entries.
    domain_key = safe_role(domain) if domain else None
    prefix = f"{domain_key}{_SCOPE_SEP}" if domain_key else None
    ranked = []
    for key, st in stats.items():
        if st.runs < min_runs:
            continue
        if prefix is not None:
            if not key.startswith(prefix):
                continue
            ranked.append((key[len(prefix):], st.avg_credit))
        elif _SCOPE_SEP not in key:
            ranked.append((key, st.avg_credit))
    ranked.sort(key=lambda x: -x[1])
    return ranked[: max(1, k)]


def guidance(path: Path | None = None, *, domain: str | None = None) -> str | None:
    """A one-line brief addendum nudging toward high-credit roles, or None.

    Only fires when CSCA is enabled and there is enough history to be useful.
    A domain run prefers its own department's track record and falls back to
    the global signal when the department hasn't seen enough swarms yet.
    """
    try:
        from . import credit
        if not credit.enabled():
            return None
    except Exception:  # pragma: no cover
        return None
    if domain:
        top = top_roles(3, path=path, domain=domain)
        helpful = [r for r, c in top if c > 0]
        if helpful:
            return (
                f"Routing memory ({domain}): these roles have contributed most "
                "on this department's past swarms — prefer them where they "
                f"fit: {', '.join(helpful)}."
            )
    top = top_roles(3, path=path)
    helpful = [r for r, c in top if c > 0]
    if not helpful:
        return None
    return (
        "Routing memory: these roles have contributed most on past swarms — "
        f"prefer them where they fit: {', '.join(helpful)}."
    )


__all__ = [
    "RoleStat",
    "safe_role",
    "record",
    "record_credit",
    "top_roles",
    "guidance",
    "DEFAULT_PATH",
]
