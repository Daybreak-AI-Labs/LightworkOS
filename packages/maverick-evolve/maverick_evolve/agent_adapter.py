"""Live agent factory: turn an evolved config into a real Lightwork run.

This is the bridge that makes config-evolution operate on *real* runs instead of
a synthetic landscape. An evolved config (knob dict from ``config_space``) is
turned into a runnable agent that executes a goal and returns its answer, so the
eval harness can score it.

**Why a subprocess.** Some knobs (notably ``MAVERICK_MAX_SWARM_FANOUT``) are read
at module-import time, so they cannot be changed per-candidate inside one live
process. Each candidate therefore runs in a fresh ``maverick start`` subprocess
with the config applied via a temp ``MAVERICK_CONFIG_OVERLAY`` file + env
vars -- clean import, full isolation, no in-process config-mutation hazards.

Dependency-injected: ``make_agent_factory(run_one=...)`` takes the function that
actually runs one goal, so the whole evolve→eval→config wiring is testable with a
fake ``run_one`` (no model, no tokens). ``subprocess_run_one`` is the real
default; ``evolve_live`` ties it to ``evolve_continuous``.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path

from .adopt import _toml_value as _toml_scalar
from .eval_harness import EvalCase
from .loop import evolve_continuous

log = logging.getLogger(__name__)

# run_one(prompt, config) -> answer string (async).
RunOne = Callable[[str, dict], Awaitable[str]]


def env_for(config: dict) -> dict[str, str]:
    """Map knobs that are read from the ENVIRONMENT to MAVERICK_* vars.

    Only the import-time / env-read knobs go here; section knobs go in the
    config overlay (``overlay_for``). Unknown knobs are ignored.
    """
    from .config_space import clamp_config
    # Clamp at the sink: a loaded/hand-edited archive config can carry an
    # out-of-bounds value that never passed through mutate's clamp, and
    # max_swarm_fanout is a kernel safety cap -- it must not be exceeded.
    config = clamp_config(config)
    env: dict[str, str] = {}
    if "max_swarm_fanout" in config:
        env["MAVERICK_MAX_SWARM_FANOUT"] = str(int(config["max_swarm_fanout"]))
    if "verifier_confidence" in config:
        env["MAVERICK_VERIFIER_CONFIDENCE"] = str(float(config["verifier_confidence"]))
    return env


def overlay_for(config: dict) -> dict:
    """Map section knobs to a config.toml overlay (also enabling the features
    so the evolved values actually take effect)."""
    from .config_space import clamp_config
    config = clamp_config(config)  # sink clamp -- see env_for
    overlay: dict = {}
    if "adaptive_compute.low_uncertainty" in config:
        overlay["adaptive_compute"] = {
            "enable": True,
            "low_uncertainty": float(config["adaptive_compute.low_uncertainty"]),
        }
    if "search.n" in config:
        overlay["search"] = {"enable": True, "n": int(config["search.n"])}
    if "autonomy.disagreement_high" in config:
        overlay["autonomy"] = {
            "enable": True,
            "disagreement_high": float(config["autonomy.disagreement_high"]),
        }
    return overlay


def render_overlay_toml(config: dict) -> str:
    """Render the config overlay as TOML text (one ``[section]`` per knob group)."""
    lines: list[str] = []
    for section, kv in overlay_for(config).items():
        lines.append(f"[{section}]")
        for k, v in kv.items():
            lines.append(f"{k} = {_toml_scalar(v)}")
        lines.append("")
    return "\n".join(lines)


def write_overlay(config: dict, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(render_overlay_toml(config), encoding="utf-8")
    return p


_DONE_MARKER = "DONE.\n\n"


def _extract_answer(stdout: str) -> str:
    """Pull the agent's result out of the ``maverick start`` stdout envelope.

    stdout is ``goal #N created: <title>\\n\\n`` + the orchestrator result,
    itself ``DONE.\\n\\n<result>\\n\\n[<budget summary>]``. Scoring the whole
    envelope leaked the prompt (echoed verbatim in the ``<title>`` line) into
    substring scorers, so a wrong answer whose case reference appeared in the
    prompt scored 1.0, and the rehearsal grader's ``Stopped``/``ERROR`` prefix
    check never fired (the envelope starts with ``goal #N created``). Return
    only ``<result>``.

    Raises ``ValueError`` when no ``DONE.`` marker is present (a blocked/errored
    run printed something else) so the caller scores it a failure, not an
    answer.
    """
    idx = stdout.rfind(_DONE_MARKER)
    if idx < 0:
        raise ValueError("no DONE marker in run output")
    body = stdout[idx + len(_DONE_MARKER):]
    # Strip the trailing "\n\n[<budget summary>]" block the orchestrator appends
    # (rpartition from the right so a "[...]" inside the result is left alone).
    head, sep, tail = body.rpartition("\n\n[")
    if sep and tail.rstrip().endswith("]"):
        body = head
    return body.strip()


def subprocess_run_one(
    prompt: str,
    config: dict,
    *,
    workdir: str | None = None,
    timeout: float = 900.0,
    python: str | None = None,
) -> str:
    """Run one goal in a fresh ``maverick start`` subprocess under ``config``.

    Writes a temp config overlay, sets ``MAVERICK_CONFIG_OVERLAY`` + env knobs,
    runs the goal, and returns the agent's result extracted from the CLI
    envelope (see :func:`_extract_answer`) -- NOT the raw stdout, which prefixes
    a ``goal #N created: <title>`` line that echoes the prompt and would leak
    into substring scorers. Raises ``RuntimeError`` on a timeout, non-zero exit,
    or output with no parseable result, so the eval harness scores those 0.0
    instead of scoring garbage. Process isolation guarantees import-time knobs
    (fan-out) take effect. Requires a configured provider/API key in the
    environment to actually produce answers.
    """
    python = python or sys.executable
    with tempfile.TemporaryDirectory() as td:
        overlay = write_overlay(config, Path(td) / "config.toml")
        env = {**os.environ, **env_for(config), "MAVERICK_CONFIG_OVERLAY": str(overlay)}
        try:
            proc = subprocess.run(  # noqa: S603 -- launching our own CLI, not a tool shell
                [python, "-m", "maverick.cli", "start", prompt],
                env=env, capture_output=True, text=True, timeout=timeout, cwd=workdir,
            )
        except subprocess.TimeoutExpired as e:
            # A timed-out run produced no valid answer; raise so the eval
            # harness scores it as a failure (0.0) rather than treating an
            # empty string as a genuine answer.
            raise RuntimeError(f"run timed out after {timeout}s") from e
        if proc.returncode != 0:
            # A crashed run is a failure, NOT an empty answer. Raise so the
            # caller (eval_harness) scores 0.0 instead of scoring garbage.
            stderr = (proc.stderr or "").strip()[-500:]
            raise RuntimeError(
                f"run exited with code {proc.returncode}: {stderr}"
            )
        try:
            return _extract_answer(proc.stdout or "")
        except ValueError as e:
            # returncode 0 but no parseable result envelope (e.g. a run blocked
            # before the orchestrator returned): a failure, not an answer.
            raise RuntimeError(f"run produced no answer: {e}") from None


def make_agent_factory(run_one: RunOne | None = None, **run_kwargs):
    """Build an ``agent_factory(config) -> async agent(prompt) -> str``.

    ``run_one`` runs one goal under a config and returns the answer; defaults to
    the real subprocess runner. Inject a fake ``run_one`` to test the full
    evolve→eval wiring without a model.
    """
    if run_one is None:
        async def _default(prompt: str, config: dict) -> str:
            return await asyncio.to_thread(
                subprocess_run_one, prompt, config, **run_kwargs,
            )
        run_one = _default

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            return await run_one(prompt, dict(config))
        return agent

    return factory


async def evolve_live(
    seed_config: dict,
    cases: list[EvalCase],
    *,
    run_one: RunOne | None = None,
    **kwargs,
):
    """Convenience: ``evolve_continuous`` against real runs (subprocess by default).

    Forwards ``rounds``/``generations_per_round``/``archive_path``/``space``/etc.
    to :func:`maverick_evolve.loop.evolve_continuous`.
    """
    factory = make_agent_factory(run_one)
    return await evolve_continuous(seed_config, cases, factory, **kwargs)


__all__ = [
    "env_for",
    "overlay_for",
    "render_overlay_toml",
    "write_overlay",
    "subprocess_run_one",
    "make_agent_factory",
    "evolve_live",
]
