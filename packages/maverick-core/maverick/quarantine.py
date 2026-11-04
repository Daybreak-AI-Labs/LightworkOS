"""Run-scoped agent quarantine -- the containment half of agent compartments.

The threat ledger (``maverick_shield.compartment``) is the *immunity* half: it
shares one agent's caught signature so the rest of the swarm bounces the same
attack (Rung 0). This module is the *containment* half (Rung 1): when an agent
shows signs of actual compromise -- a critical-severity shield block, or
repeated blocks -- it is "sealed off like a submarine door." A sealed agent:

  * runs no further tools (its calls are refused in ``Agent._run_tool``), and
  * has its blackboard posts withheld from siblings and the orchestrator (see
    ``Blackboard.render``), so a poisoned finding it already posted can't steer
    the rest of the swarm.

Run-scoped, in-memory, and OFF unless ``[safety] compartments`` is enabled. The
trigger is deliberately conservative: most shield blocks are deflected probes,
not compromise, so a single sub-critical block only immunizes (Rung 0) -- it
does NOT seal the agent. Promotion to a seal is a privileged step taken here
(driven from the agent's own chokepoint), never by an agent broadcasting about
its peers. Fail-open: a bug in here must never crash the agent loop.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# Seal an agent once it has tripped the shield this many times in a run, even
# below critical severity: a repeat offender is stuck in attacker-controlled
# territory, not deflecting a one-off probe.
_STRIKE_SEAL_THRESHOLD = 2

# Escalate to a SECTOR seal (Rung 2) once this many distinct agents in one
# domain have been sealed -- multiple compromised agents in a compartment is a
# coordinated/structural threat, not an isolated probe.
_DOMAIN_SEAL_THRESHOLD = 2


@dataclass
class QuarantineRegistry:
    """Run-scoped, swarm-shared record of sealed agents (compartment Rung 1)."""

    _sealed: dict[str, str] = field(default_factory=dict)   # agent -> reason
    _strikes: dict[str, int] = field(default_factory=dict)  # agent -> block count
    _sealed_domains: dict[str, str] = field(default_factory=dict)  # domain -> reason
    _agent_domain: dict[str, str] = field(default_factory=dict)    # agent -> domain
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def seal(self, agent: str, reason: str) -> None:
        with self._lock:
            self._sealed.setdefault(agent, reason)

    def is_sealed(self, agent: str) -> bool:
        """True if the agent is sealed directly OR its domain (sector) is sealed."""
        with self._lock:
            if agent in self._sealed:
                return True
            dom = self._agent_domain.get(agent)
            return dom is not None and dom in self._sealed_domains

    def reason(self, agent: str) -> str | None:
        with self._lock:
            if agent in self._sealed:
                return self._sealed[agent]
            dom = self._agent_domain.get(agent)
            if dom is not None and dom in self._sealed_domains:
                return f"sector '{dom}': {self._sealed_domains[dom]}"
            return None

    def record_strike(self, agent: str) -> int:
        """Count a shield block against ``agent``; return its running total."""
        with self._lock:
            n = self._strikes.get(agent, 0) + 1
            self._strikes[agent] = n
            return n

    def register_agent(self, agent: str, domain: str | None) -> None:
        """Record an agent's domain so a sector seal can reach it. Idempotent."""
        if not domain:
            return
        with self._lock:
            self._agent_domain[agent] = domain

    def is_domain_sealed(self, domain: str) -> bool:
        with self._lock:
            return domain in self._sealed_domains

    def seal_domain(self, domain: str, reason: str) -> None:
        """Seal a whole sector (Rung 2): every agent in ``domain`` -- current and
        future -- is refused, until explicitly unsealed."""
        with self._lock:
            self._sealed_domains.setdefault(domain, reason)

    def maybe_seal_domain(self, agent: str, reason: str) -> str | None:
        """Escalate to a sector seal when an agent's domain has accumulated
        ``_DOMAIN_SEAL_THRESHOLD`` sealed agents. Returns the domain if sealed."""
        with self._lock:
            domain = self._agent_domain.get(agent)
            if not domain or domain in self._sealed_domains:
                return None
            sealed_in_domain = sum(
                1 for a in self._sealed if self._agent_domain.get(a) == domain
            )
            if sealed_in_domain >= _DOMAIN_SEAL_THRESHOLD:
                self._sealed_domains[domain] = f"sector seal: {reason}"
                return domain
            return None

    def unseal_agent(self, agent: str) -> None:
        with self._lock:
            self._sealed.pop(agent, None)

    def unseal_domain(self, domain: str) -> None:
        with self._lock:
            self._sealed_domains.pop(domain, None)

    @property
    def sealed_agents(self) -> list[str]:
        with self._lock:
            return list(self._sealed)

    @property
    def sealed_domains(self) -> list[str]:
        with self._lock:
            return list(self._sealed_domains)

    def status(self) -> dict:
        """Operator snapshot of containment state for this run."""
        with self._lock:
            return {
                "sealed_agents": list(self._sealed),
                "sealed_domains": list(self._sealed_domains),
                "agents_tracked": len(self._agent_domain),
            }


def triage_block(
    registry: QuarantineRegistry, agent: str, severity: str, reason: str
) -> bool:
    """Decide whether a shield block should SEAL the agent (compartment Rung 1).

    Conservative: seal on a critical-severity block, or once the agent is a
    repeat offender (>= threshold blocks this run). Lower-severity one-off
    blocks only immunize (Rung 0). Returns True iff the agent was sealed.
    Fail-open -- never raises into the caller.
    """
    try:
        strikes = registry.record_strike(agent)
        if severity == "critical" or strikes >= _STRIKE_SEAL_THRESHOLD:
            registry.seal(agent, f"{reason} (severity={severity}, strikes={strikes})")
            log.warning("compartment: sealed agent %s after block: %s", agent, reason)
            sector = registry.maybe_seal_domain(agent, reason)
            if sector:
                log.warning(
                    "compartment: SECTOR seal on domain %s (multiple agents "
                    "compromised)", sector,
                )
            return True
    except Exception:  # pragma: no cover -- containment must never break the loop
        pass
    return False


def compartment_status(quarantine, shield=None) -> dict:
    """A run's compartment snapshot: what's sealed and how many threat
    signatures have been immunized. Safe with ``None`` args (feature off)."""
    out = {"enabled": quarantine is not None, "sealed_agents": [],
           "sealed_domains": [], "immunized": 0}
    if quarantine is not None:
        try:
            s = quarantine.status()
            out["sealed_agents"] = s.get("sealed_agents", [])
            out["sealed_domains"] = s.get("sealed_domains", [])
        except Exception:  # pragma: no cover -- observability must never raise
            pass
    ledger = getattr(shield, "ledger", None)
    if ledger is not None:
        try:
            out["immunized"] = len(ledger)
        except Exception:  # pragma: no cover
            pass
    return out


def format_compartment_status(status: dict) -> str:
    """One-line human summary for the blackboard / CLI / dashboard."""
    if not status.get("enabled"):
        return "compartments: off"
    parts = [f"{status.get('immunized', 0)} threat(s) immunized"]
    if status.get("sealed_domains"):
        parts.append("sealed sectors: " + ", ".join(status["sealed_domains"]))
    if status.get("sealed_agents"):
        parts.append(f"{len(status['sealed_agents'])} agent(s) sealed")
    return "compartments: " + "; ".join(parts)
