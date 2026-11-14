"""The ``learn_capability`` tool: close a capability gap mid-run.

Bound to the calling agent (like the spawn tools) so it can mutate the
LIVE tool registry — a capability acquired here is in the tool catalog
the model sees on its NEXT turn, no restart required.

Ops:
  - search          : find existing skills / MCP servers / plugins in the
                      catalog that match a need, plus already-loaded tools.
  - acquire_skill   : install a catalog skill by name (hash-verified) and
                      return its steps so they're usable immediately.
  - add_mcp_server  : unavailable until catalog publishers can be authenticated.
  - create_tool     : GENERATE a Python tool from a spec, validate it, and
                      register it live (full-autonomy; gated by settings).
  - find_api        : discover an API's OpenAPI spec (probe a base_url or
                      web-search) and surface its operations, ready to drive
                      via the built-in ``openapi_runner`` tool.

Gated entirely by ``self_learning.enabled()``; the kernel never registers
this tool otherwise.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from . import Tool

if TYPE_CHECKING:
    from ..agent import Agent


def _fmt_candidates(cands: list) -> str:
    if not cands:
        return "(no catalog matches)"
    lines = []
    for c in cands:
        summary = f" — {c.summary}" if c.summary else ""
        lines.append(f"  [{c.kind}] {c.name} (score {c.score:.2f}){summary}")
    return "\n".join(lines)


def _op_search(agent: Agent, self_learning, need: str) -> str:
    if not need:
        return "ERROR: 'need' is required for op=search"
    cands = self_learning.search_capabilities(need)
    local = sorted(
        t.name for t in agent.tools.all()
        if any(w in t.name.lower() or w in (t.description or "").lower()
               for w in need.lower().split())
    )[:8]
    return (
        f"Catalog matches for {need!r}:\n{_fmt_candidates(cands)}\n\n"
        f"Already-loaded tools that may fit: {', '.join(local) or '(none)'}\n\n"
        "Next: acquire_skill <name> for a [skill], or create_tool to build a new one. "
        "Catalog MCP acquisition is unavailable until publisher authentication exists."
    )


def _op_acquire_skill(agent: Agent, bb, self_learning, args: dict, need: str) -> str:
    name = (args.get("name") or "").strip()
    if not name:
        return "ERROR: 'name' (catalog skill name) is required"
    try:
        body = self_learning.acquire_skill(name, need=need)
    except Exception as e:
        return f"ERROR: could not install skill {name!r}: {e}"
    bb.post(agent.name, "observation", f"learned skill: {name}")
    return (
        f"Installed skill {name!r}. Use these steps now:\n\n{body}"
    )


async def _op_add_mcp_server(agent: Agent, ctx, bb, self_learning, args: dict, need: str) -> str:
    return (
        "ERROR: catalog MCP acquisition is unavailable until publisher authentication "
        "is implemented. An operator can independently review and configure the server."
    )


async def _op_create_tool(agent: Agent, ctx, bb, self_learning, st, args: dict, need: str) -> str:
    if not st.get("create_tools", True):
        return "ERROR: tool creation is disabled ([self_learning] create_tools=false)"
    name = (args.get("name") or "").strip()
    spec = (args.get("spec") or need).strip()
    if not name or not spec:
        return "ERROR: 'name' and 'spec' (what the tool should do) are required"
    from ..llm import model_for_role
    try:
        resp = await ctx.llm.complete_async(
            system=self_learning.TOOL_AUTHOR_SYSTEM,
            messages=[{"role": "user", "content": (
                f"Build a tool named {name!r}.\nIt should: {spec}"
            )}],
            budget=ctx.budget,
            max_tokens=2048,
            model=model_for_role("coder"),
        )
    except Exception as e:
        return f"ERROR: tool generation call failed: {e}"
    try:
        tool = self_learning.write_generated_tool(
            name, resp.text or "", need=need or spec,
            sandbox=getattr(ctx, "sandbox", None),
        )
    except Exception as e:
        return f"ERROR: generated tool was rejected: {e}"
    agent.tools.register(tool)
    bb.post(agent.name, "observation", f"created tool: {tool.name}")
    return (
        f"Created and registered tool {tool.name!r}. It is available "
        f"now and will persist for future runs.\nDescription: {tool.description}"
    )


async def _op_find_api(agent: Agent, bb, self_learning, args: dict, need: str) -> str:
    base_url = (args.get("base_url") or "").strip()
    spec_url = None
    if base_url:
        # The probe issues GETs to a model-chosen host, so the network
        # posture and egress policy apply as they do to http_fetch.
        from urllib.parse import urlparse
        host = urlparse(base_url if "://" in base_url else f"https://{base_url}").hostname or ""
        try:
            from ..tenant.egress import egress_allowed
            allowed = egress_allowed("learn_capability", host)
        except Exception as e:
            return f"ERROR: egress policy could not be evaluated ({type(e).__name__}); not probing {base_url!r}."
        if not allowed:
            return f"ERROR: egress policy blocks probing {host!r} for an API spec."
        spec_url = self_learning.probe_openapi_spec(base_url)
    # Route nested tool calls through the agent's _run_tool chokepoint
    # (shield + capability + governance + hooks), not the bare registry
    # -- otherwise an agent granted `learn` could drive web_search /
    # openapi_runner ungoverned. unframe_tool_output recovers the raw
    # result (a denied/blocked call returns its notice, handled below).
    from ..agent import unframe_tool_output
    if not spec_url and any(t.name == "web_search" for t in agent.tools.all()):
        try:
            hits = unframe_tool_output(await agent._run_tool(
                "web_search",
                {"query": f"{need or base_url} OpenAPI specification json"},
            ))
        except Exception:
            hits = ""
        spec_url = self_learning.discover_openapi_spec(search_text=hits or "")
    if not spec_url:
        return (
            "Could not auto-discover an OpenAPI spec"
            + (" (enable the web_search tool to let me search for one)"
               if not any(t.name == "web_search" for t in agent.tools.all())
               else "")
            + ".\nIf you know the service's base URL, retry with "
            "base_url=<https://host>. Or call any REST API yourself via "
            "the `openapi_runner` tool once you have a spec URL:\n"
            "  openapi_runner op=list_ops spec=<spec-url>\n"
            "  openapi_runner op=call spec=<spec-url> op_id=<id> "
            "params={...} headers={...}\n"
            f"Need: {need or '(unspecified)'}"
        )
    self_learning.record(need or base_url, "api", spec_url, source=spec_url)
    bb.post(agent.name, "observation", f"found API spec: {spec_url}")
    ops_preview = ""
    if any(t.name == "openapi_runner" for t in agent.tools.all()):
        try:
            ops_preview = unframe_tool_output(await agent._run_tool(
                "openapi_runner", {"op": "list_ops", "spec": spec_url},
            ))
        except Exception:
            ops_preview = ""
    msg = f"Found an OpenAPI spec for {need or base_url!r}:\n  {spec_url}\n\n"
    if ops_preview and not ops_preview.startswith("ERROR"):
        msg += f"Operations:\n{ops_preview}\n\n"
    msg += (
        f"Call it with the openapi_runner tool: op=call spec={spec_url} "
        "op_id=<id> params={...} headers={...} (headers for auth)."
    )
    return msg


async def _dispatch_learn_op(agent: Agent, ctx, args: dict) -> str:
    from .. import self_learning

    op = (args.get("op") or "").strip()
    need = (args.get("need") or "").strip()
    st = self_learning.settings()
    bb = ctx.blackboard

    if op == "search":
        return _op_search(agent, self_learning, need)
    if op == "acquire_skill":
        return _op_acquire_skill(agent, bb, self_learning, args, need)
    if op == "add_mcp_server":
        return await _op_add_mcp_server(agent, ctx, bb, self_learning, args, need)
    if op == "create_tool":
        return await _op_create_tool(agent, ctx, bb, self_learning, st, args, need)
    if op == "find_api":
        return await _op_find_api(agent, bb, self_learning, args, need)

    return (
        "ERROR: unknown op. Use one of: search, acquire_skill, "
        "create_tool, find_api, add_mcp_server"
    )


def learn_capability(agent: Agent) -> Tool:
    ctx = agent.ctx

    async def fn(args: dict) -> str:
        return await _dispatch_learn_op(agent, ctx, args)

    return Tool(
        name="learn_capability",
        description=(
            "Acquire a NEW capability when you lack the skill/tool/integration "
            "to do the task. op=search to find existing skills; "
            "op=acquire_skill to install one; op=create_tool to generate a new "
            "tool from a description (persists for future runs); op=find_api to "
            "discover an API's OpenAPI spec (pass base_url or let it web-search) "
            "and drive it via openapi_runner. Catalog MCP acquisition is "
            "unavailable until publisher authentication exists. Prefer search first."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "op": {
                    "type": "string",
                    "enum": [
                        "search", "acquire_skill", "create_tool", "find_api",
                        "add_mcp_server",
                    ],
                },
                "need": {
                    "type": "string",
                    "description": "The capability gap in plain language.",
                },
                "name": {
                    "type": "string",
                    "description": "Catalog skill name (acquire_skill), catalog "
                                   "mcp server name (add_mcp_server), or id for "
                                   "the new generated tool.",
                },
                "spec": {
                    "type": "string",
                    "description": "create_tool: detailed description of what the "
                                   "tool should do and its inputs/outputs.",
                },
                "base_url": {
                    "type": "string",
                    "description": "find_api: the service's base URL (e.g. "
                                   "https://api.example.com) to probe for an "
                                   "OpenAPI spec. Optional — omit to web-search.",
                },
            },
            "required": ["op"],
        },
        fn=fn,
    )
