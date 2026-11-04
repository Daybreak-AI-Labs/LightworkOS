"""Live tau2-bench solver: a Lightwork agent <-> user-simulator conversation.

``eval_tau2.py`` is a stateful tool domain (a retail DB) graded on the final
state AND the required tool actions. Unlike a one-shot task, tau2-bench is
DUAL-CONTROL: the agent must converse with a (simulated) customer who holds the
scenario and reveals details on request. This is the live seam beside the
harness's no-op stub -- a real agent driving the domain tools in a
tool-calling loop while talking to a real user-simulator LLM, until the
customer's goal is resolved.

Injected like any solver, so it is validated for FREE with scripted FakeLLMs for
BOTH the agent and the user (``test_tau2_solver.py``) and runs live by swapping
the factories. Roles are kept straight by maintaining two message lists: from
the agent's view the customer is the ``user``; from the customer-sim's view the
agent is the ``user``.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

AGENT_SYSTEM = (
    "You are a retail customer-support agent. Resolve the customer's request by "
    "calling the available tools to look up and modify orders and users. Ask the "
    "customer for any detail you need (e.g. an order id) -- never invent ids. When "
    "the request is fully resolved, send a brief confirmation to the customer "
    "WITHOUT calling a tool."
)
USER_SYSTEM = (
    "You are a customer contacting retail support. Your situation:\n{scenario}\n\n"
    "Speak naturally as the customer, ONE short message at a time. Provide details "
    "(like an order id) only when the agent asks for them. You are the customer, "
    "not the agent -- never call tools or narrate actions. When the agent has fully "
    "resolved your request, reply with EXACTLY '###DONE###' and nothing else."
)
_DONE = "###DONE###"
_KICKOFF = "You are now connected to a support agent. Send your first message."


def _tool_specs(tools: dict[str, Callable]) -> list[dict]:
    """Anthropic-style tool specs from each callable's signature (string params;
    a parameter with no default is required)."""
    specs: list[dict] = []
    for name, fn in tools.items():
        props: dict = {}
        required: list[str] = []
        for pname, param in inspect.signature(fn).parameters.items():
            props[pname] = {"type": "string", "description": f"the {pname}"}
            if param.default is inspect.Parameter.empty:
                required.append(pname)
        doc = (inspect.getdoc(fn) or f"{name} tool").strip().splitlines()[0]
        specs.append({
            "name": name, "description": doc,
            "input_schema": {"type": "object", "properties": props, "required": required},
        })
    return specs


def _text(resp: Any) -> str:
    return (getattr(resp, "text", "") or "").strip()


def make_tau2_solver(
    *,
    max_turns: int = 8,
    max_steps_per_turn: int = 10,
    max_dollars: float = 2.0,
    max_wall_seconds: float = 600.0,
    max_tokens: int = 1024,
    agent_llm_factory: Callable[[], Any] | None = None,
    user_llm_factory: Callable[[], Any] | None = None,
) -> Callable[[Any, dict], None]:
    """Build a ``Tau2Solver`` that runs an agent<->user-simulator conversation over
    the domain tools. The factories build the two LLMs (default ``LLM()``); tests
    pass scripted FakeLLMs. A shared ``Budget`` plus the turn/step caps bound the
    per-task cost; any LLM/budget error ends the conversation so ``verify`` grades
    whatever was done."""
    from maverick.budget import Budget

    def _mk(factory):
        if factory is not None:
            return factory()
        from maverick.llm import LLM
        return LLM()

    def _agent_reply(agent_llm, budget, specs, tools, agent_msgs) -> str:
        """Run the agent's tool-loop for one turn; return its text reply (the
        message it sends back to the customer)."""
        for _ in range(max_steps_per_turn):
            try:
                resp = agent_llm.complete(
                    system=AGENT_SYSTEM, messages=agent_msgs, tools=specs,
                    budget=budget, max_tokens=max_tokens,
                )
            except Exception:
                return ""
            calls = list(getattr(resp, "tool_calls", None) or [])
            if not calls:
                reply = _text(resp)
                if reply:
                    agent_msgs.append({"role": "assistant", "content": reply})
                return reply
            assistant: list[dict] = []
            if _text(resp):
                assistant.append({"type": "text", "text": _text(resp)})
            for tc in calls:
                assistant.append(
                    {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.input}
                )
            agent_msgs.append({"role": "assistant", "content": assistant})
            results: list[dict] = []
            for tc in calls:
                fn = tools.get(tc.name)
                try:
                    out = fn(**(tc.input or {})) if fn else f"ERROR: no such tool {tc.name!r}"
                except Exception as e:
                    out = f"ERROR: {type(e).__name__}: {e}"
                results.append({
                    "type": "tool_result", "tool_use_id": tc.id,
                    "content": "" if out is None else str(out),
                })
            agent_msgs.append({"role": "user", "content": results})
        return ""  # ran out of steps without a text reply

    def _user_says(user_llm, budget, user_sys, user_msgs) -> str:
        try:
            resp = user_llm.complete(
                system=user_sys, messages=user_msgs, budget=budget, max_tokens=max_tokens,
            )
        except Exception:
            return _DONE
        return _text(resp) or _DONE

    def solve(task: Any, tools: dict) -> None:
        agent_llm = _mk(agent_llm_factory)
        user_llm = _mk(user_llm_factory)
        budget = Budget(max_dollars=max_dollars, max_wall_seconds=max_wall_seconds)
        specs = _tool_specs(tools)
        user_sys = USER_SYSTEM.format(scenario=str(getattr(task, "prompt", "")))
        agent_msgs: list[dict] = []
        user_msgs: list[dict] = [{"role": "user", "content": _KICKOFF}]
        for _ in range(max_turns):
            user_text = _user_says(user_llm, budget, user_sys, user_msgs)
            if user_text.strip() == _DONE:
                return
            user_msgs.append({"role": "assistant", "content": user_text})  # the customer's turn
            agent_msgs.append({"role": "user", "content": user_text})       # customer -> agent
            reply = _agent_reply(agent_llm, budget, specs, tools, agent_msgs)
            if not reply:
                return  # the agent produced nothing actionable
            user_msgs.append({"role": "user", "content": reply})            # agent -> customer

    return solve


def dry_run_tau2_solver(task: Any, tools: dict) -> None:
    """No-op solver: structure smoke (every task with requirements scores 0)."""
