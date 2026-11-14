"""OpenAI provider client.

Implements the same complete()/complete_async() interface as
AnthropicClient, by translating Anthropic-format messages and tools
into OpenAI's chat format and converting the response back.

Used directly for OpenAI; subclassed by OpenRouter and Ollama, which
are OpenAI-compatible at different base_urls.

Translation rules:
  - tool_result.content may be a list of blocks; extract `text` from each
  - max_completion_tokens for gpt-4o / o1 / o3 (max_tokens deprecated)
  - finish_reason mapped to Anthropic stop_reason vocabulary
  - empty assistant turns emit content="" not None (OpenAI rejects null)
  - tool_result turns: the CALLER must supply a result for each tool_call_id;
    this translator does NOT synthesize stub tool responses
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
from collections.abc import Callable
from typing import Any

from ..budget import Budget, UsageAccountingError
from ..llm import LLMResponse, ToolCall
from ..retry import async_physical_attempt, async_retry, sync_physical_attempt, sync_retry
from ..secrets import scrub
from .conversation import ContentPart, ConversationMessage, PartKind

log = logging.getLogger(__name__)

# OpenAI Chat Completions hard limit on the `tools` array. Requests with more
# are rejected with a 400 ("Invalid 'tools': array too long"). Overridable for
# providers/gateways with a different ceiling.
def _max_tools_setting() -> int:
    """``[models] openai_max_tools`` read at startup (env ``MAVERICK_OPENAI_MAX_TOOLS`` wins)."""
    from ..env_setting import env_or_config_int

    return max(1, env_or_config_int("MAVERICK_OPENAI_MAX_TOOLS", "models", "openai_max_tools", 128))


_OPENAI_MAX_TOOLS = _max_tools_setting()


# Models that require max_completion_tokens instead of max_tokens.
_MODELS_WANTING_MAX_COMPLETION_TOKENS = (
    "gpt-4o", "gpt-4.1", "o1", "o3", "o4", "gpt-5",
)

# Every GPT generation from 5 on rejects ``max_tokens`` with a 400
# ("Unsupported parameter ... Use 'max_completion_tokens' instead"), so match
# the generation number rather than listing each release: a new family
# (gpt-6-astra, gpt-6.1-sol, ...) must not break every call on day one.
_GPT_GENERATION = re.compile(r"gpt-(\d+)")
_FIRST_MAX_COMPLETION_GPT = 5

# Models with OpenAI automatic prompt caching (gpt-4.1 / o-series / gpt-5).
# The read side already credits usage.prompt_tokens_details.cached_tokens;
# these get the write-side cache-friendly ordering below.
_MODELS_WITH_AUTO_PROMPT_CACHE = (
    "gpt-4.1", "o1", "o3", "o4", "gpt-5",
)

# OpenAI's automatic prompt cache only engages when the stable prefix is
# at least ~1024 tokens. Below this it's a no-op, so the reordering work
# isn't worth doing. Heuristic estimate: 4 chars/token (matches the
# Anthropic provider's estimator).
_MIN_AUTO_CACHE_TOKENS = 1024

# Map OpenAI finish_reason to Anthropic stop_reason vocab.
_FINISH_REASON_MAP = {
    "stop":         "end_turn",
    "tool_calls":   "tool_use",
    "length":       "max_tokens",
    "content_filter": "refusal",
    "function_call": "tool_use",
}


def _strict_usage_count(v: object, field: str, *, missing_ok: bool = False) -> int:
    """Convert provider-reported usage to a non-negative int.

    OpenAI-compatible calls are paid before we see ``usage``. If the gateway
    reports malformed accounting data, do not silently record a zero-cost call:
    fail closed so the agent stops instead of bypassing spend limits. The
    error is a :class:`UsageAccountingError` (a provider fault), never a
    cap breach.
    Optional cache fields may pass ``missing_ok=True`` to treat ``None`` as 0.
    """
    if v is None:
        if missing_ok:
            return 0
        raise UsageAccountingError(f"invalid OpenAI usage.{field}: missing token count")
    try:
        if isinstance(v, bool):
            raise ValueError("boolean")
        if isinstance(v, float) and not math.isfinite(v):
            raise ValueError("non-finite")
        n = int(v)
        if not isinstance(v, (str, bytes)) and v != n:
            raise ValueError("fractional")
    except (TypeError, ValueError, OverflowError) as exc:
        raise UsageAccountingError(f"invalid OpenAI usage.{field}: {v!r}") from exc
    if n < 0:
        raise UsageAccountingError(f"invalid OpenAI usage.{field}: negative token count {n}")
    return n


def _extract_tool_result_text(content: Any) -> str:
    """Anthropic's tool_result.content can be a string OR a list of blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content) if content is not None else ""


def _image_block_to_openai_part(block: dict) -> dict:
    """Translate an Anthropic image content block to an OpenAI
    ``image_url`` content part.

    Anthropic images carry ``source`` as either ``{"type": "base64",
    "media_type": ..., "data": ...}`` or ``{"type": "url", "url": ...}``.
    OpenAI's vision format takes a single ``url`` either way -- a data URI
    for base64, the URL verbatim otherwise. An unrecognized/missing source
    fails closed to an empty data URL rather than raising, matching this
    translator's existing tolerance for malformed blocks (the request will
    surface as an ordinary provider-side image error, not a crash here).
    """
    source = block.get("source")
    if isinstance(source, dict):
        if source.get("type") == "url" and source.get("url"):
            return {"type": "image_url", "image_url": {"url": source["url"]}}
        if source.get("type") == "base64" and source.get("data"):
            media_type = source.get("media_type") or "application/octet-stream"
            return {
                "type": "image_url",
                "image_url": {"url": f"data:{media_type};base64,{source['data']}"},
            }
    return {"type": "image_url", "image_url": {"url": ""}}


def _translate_user_blocks(content: list) -> tuple[list[dict], dict | None]:
    """Split one Anthropic user turn's content blocks into OpenAI ``tool``
    messages plus a single trailing ``user`` message (or ``None`` if the
    turn carried no text/image content at all).

    An Anthropic image/document block must not fall into the ``else``
    branch below and get ``str()``-stringified into plain text -- the model
    would see a Python dict repr containing the raw base64 payload as prompt
    text, not an actual image. content_parts holds OpenAI
    content-part dicts (text and image_url) so a real image reaches the
    model as an image; collapsed back to a plain string when the turn has
    no image (the common case), to keep that path's output byte-for-byte
    unchanged. A document block has no OpenAI-family equivalent (no inline
    file content type) and is rejected rather than silently mangled.
    """
    tool_msgs: list[dict] = []
    content_parts: list[dict] = []
    for block in content:
        if not isinstance(block, dict):
            content_parts.append({"type": "text", "text": str(block)})
            continue
        bt = block.get("type")
        if bt == "tool_result":
            tool_msgs.append({
                "role": "tool",
                "tool_call_id": block.get("tool_use_id", ""),
                "content": _extract_tool_result_text(block.get("content")),
            })
        elif bt == "text":
            content_parts.append({"type": "text", "text": block.get("text", "")})
        elif bt == "image":
            content_parts.append(_image_block_to_openai_part(block))
        elif bt == "document":
            raise RuntimeError(
                "OpenAI-family providers do not accept inline document "
                "blocks (no equivalent to Anthropic's document content "
                "type); route file input through the provider's own "
                "file-upload API instead."
            )
        else:
            content_parts.append({"type": "text", "text": str(block)})
    if not content_parts:
        return tool_msgs, None
    if any(p["type"] != "text" for p in content_parts):
        return tool_msgs, {"role": "user", "content": content_parts}
    return tool_msgs, {
        "role": "user",
        "content": "\n".join(p["text"] for p in content_parts),
    }


def _openai_import_error_message(e: ImportError) -> str:
    """Explain a failed ``from openai import ...`` without misdiagnosing it.

    A bare ``except ImportError`` also catches a missing *transitive*
    dependency (e.g. openai -> httpx -> idna): ModuleNotFoundError subclasses
    ImportError. Reporting "openai SDK not installed" then sends the user to
    ``python -m pip install -e './packages/maverick-core[openai]'``, which won't help because openai
    IS installed. Use find_spec to tell the two cases apart -- it locates the
    package without executing its (failing) ``__init__``.
    """
    import importlib.util
    try:
        present = importlib.util.find_spec("openai") is not None
    except Exception:
        present = False
    if not present:
        return "openai SDK not installed. Run: python -m pip install -e './packages/maverick-core[openai]'"
    return (
        f"the openai SDK is installed but failed to import ({e}); a dependency "
        "is likely missing or broken. Try: pip install --upgrade "
        "'maverick-agent[openai]'"
    )


class OpenAIClient:
    DEFAULT_MODEL = "gpt-4o"
    # Pricing qualifier prepended to the model id when recording budget spend.
    # Provider subclasses set theirs ("vllm:" etc.) so pricing can preserve
    # provider context while still resolving known table ids after stripping
    # the prefix. Empty for the hosted OpenAI provider.
    PRICE_MODEL_PREFIX = ""
    # Whether a missing ``usage`` block must abort the turn. True for paid hosted
    # providers (OpenAI/Azure/DeepSeek/…) where we cannot let an untracked call
    # bypass the budget. Self-hosted subclasses (ollama/vllm/tgi) override False:
    # their ids price at $0, and many local OpenAI-compatible servers (llama.cpp,
    # LM Studio, older vLLM) omit ``usage`` on non-streaming completions, so
    # aborting there breaks a free, correct run for no benefit.
    USAGE_REQUIRED = True
    # Cache-read billing multiplier: cached input tokens are billed at this
    # fraction of the full input rate. OpenAI/o-series/gpt-5 auto-cache reads
    # discount ~0.5x (vs Anthropic's 0.1x budget default). Provider subclasses
    # whose cache discount differs override this so a cache hit on DeepSeek /
    # Gemini isn't over-billed at OpenAI's shallower rate.
    CACHE_READ_MULT = 0.5

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        allow_openai_env_fallback: bool = True,
        default_headers: dict | None = None,
        environment=None,
    ):
        try:
            import openai
            from openai import AsyncOpenAI, OpenAI
        except ImportError as e:
            raise ImportError(_openai_import_error_message(e)) from e
        env = os.environ if environment is None else environment
        key = api_key
        if key is None and allow_openai_env_fallback:
            key = env.get("OPENAI_API_KEY")
        # Strip whitespace: a trailing newline (`echo $KEY > file`) or stray
        # spaces otherwise 401 every call. Covers every OpenAI-compatible
        # provider (openrouter/deepseek/ollama/moonshot/xai/tgi/vllm), which
        # all pass their key through here. Matches AnthropicClient.
        if key is not None:
            key = key.strip() or None
        if key is None and (not allow_openai_env_fallback or environment is not None):
            raise RuntimeError(
                "OpenAI-compatible provider requires a non-empty API key; "
                "refusing to fall back to OPENAI_API_KEY for this base_url."
            )
        from .base import sdk_http_timeout
        kw: dict = {"api_key": key, "base_url": base_url}
        # OpenAI organisation and project ids identify an OpenAI account; the
        # OpenAI-compatible subclasses talk to other vendors, which must not
        # receive them.
        openai_account = type(self) is OpenAIClient
        org = env.get("OPENAI_ORG_ID") if openai_account else None
        project = env.get("OPENAI_PROJECT_ID") if openai_account else None
        if environment is not None:
            # Explicit empty optional values prevent SDK-level live env fallback.
            kw.update(
                base_url=base_url or env.get("OPENAI_BASE_URL") or "https://api.openai.com/v1",
                organization=org or "",
                project=project or "",
            )
        # Data-residency / ZDR control: operator-set `[providers.<name>]
        # default_headers` are attached to every request so a compliance gateway
        # can enforce region pinning / no-retention headers. Empty -> none.
        if default_headers:
            kw["default_headers"] = dict(default_headers)
        timeout = sdk_http_timeout(openai, environment=environment)
        if timeout is not None:
            kw["timeout"] = timeout
        # Lightwork's bounded retry layer is the sole retry authority. Leaving
        # the SDK default enabled multiplies each governed attempt underneath
        # budgets, egress denials, and audit accounting.
        self._sync = OpenAI(max_retries=0, **kw)
        self._async = AsyncOpenAI(max_retries=0, **kw)
        if environment is not None or not openai_account:
            # Empty construction sentinels block SDK env fallback, then restore
            # absent metadata so no new empty headers are sent to any endpoint.
            # A subclass built from the live environment clears what the SDK
            # read from OPENAI_ORG_ID / OPENAI_PROJECT_ID the same way.
            for client in (self._sync, self._async):
                if client is not None:
                    client.organization = org or None
                    client.project = project or None
        # Expose the resolved endpoint for introspection (doctor / logs) and so
        # the OpenAI-compatible subclasses (vllm / tgi / bedrock /
        # openai_compatible) and their tests can read where they're actually
        # pointed. ``None`` means the OpenAI SDK's own default base_url.
        self.base_url = base_url

    @staticmethod
    def _wants_max_completion(model: str) -> bool:
        if any(model.startswith(prefix) for prefix in _MODELS_WANTING_MAX_COMPLETION_TOKENS):
            return True
        generation = _GPT_GENERATION.match(model)
        return bool(generation) and int(generation.group(1)) >= _FIRST_MAX_COMPLETION_GPT

    @staticmethod
    def _is_reasoning_model(model: str) -> bool:
        """True for models that accept ``reasoning_effort`` (o-series, gpt-5).

        Narrower than ``_wants_max_completion``, which also covers gpt-4o/gpt-4.1
        — those want ``max_completion_tokens`` but are NOT reasoning models and
        reject ``reasoning_effort`` with a 400.
        """
        return any(model.startswith(p) for p in ("o1", "o3", "o4", "gpt-5"))

    @staticmethod
    def _reasoning_effort_for(thinking_budget: int | None) -> str | None:
        """Map an Anthropic-style ``thinking_budget`` (token count) to OpenAI's
        ``reasoning_effort`` bucket (low/medium/high) by magnitude.

        The unified LLM interface expresses extended thinking as a token budget
        (Anthropic's knob). OpenAI o-series / gpt-5 instead take a coarse
        ``reasoning_effort`` enum, so a budget passed to this provider was
        silently dropped. Bucket it: <=4k -> low, <=16k -> medium, else high.
        Returns None when no budget is requested.
        """
        if not thinking_budget or thinking_budget <= 0:
            return None
        if thinking_budget <= 4096:
            return "low"
        if thinking_budget <= 16384:
            return "medium"
        return "high"

    @staticmethod
    def _has_auto_prompt_cache(model: str) -> bool:
        return any(model.startswith(prefix) for prefix in _MODELS_WITH_AUTO_PROMPT_CACHE)

    @staticmethod
    def _cache_friendly_tools(tools: list[dict] | None) -> list[dict] | None:
        """Stable tool ordering for OpenAI's automatic prompt cache.

        OpenAI auto-caches the longest common prefix of a request (system
        + tools + leading messages). The tools array is part of that
        prefix, so a non-deterministic order silently busts the cache on
        every call. Sorting by name makes the prefix byte-identical across
        calls so the cache actually hits — same reasoning as the Anthropic
        provider's ``_cached_tools``. Coerce the key via str() so a
        malformed tool name=None doesn't blow sorted() with TypeError.
        """
        if not tools:
            return tools
        return sorted(tools, key=lambda t: str(t.get("name") or ""))

    @staticmethod
    def _to_openai_messages(
        system: str, anthropic_messages: list[dict | ConversationMessage],
    ) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for msg in anthropic_messages:
            message = msg if isinstance(msg, ConversationMessage) else ConversationMessage.from_anthropic(msg)
            role = message.role
            content = message.content

            if role == "user":
                if isinstance(content, str):
                    out.append({"role": "user", "content": content})
                elif message.content_is_parts:
                    # A `tool` message MUST immediately follow the assistant
                    # `tool_calls` it answers -- OpenAI 400s ("messages with role
                    # 'tool' must be a response to a preceding message with
                    # 'tool_calls'") if a `user` message is inserted between them.
                    # Anthropic allows text blocks interleaved with / before
                    # tool_result blocks in one user turn, so we must NOT preserve
                    # that raw order: emit ALL tool messages first (keeping their
                    # relative order so each matches its tool_call), then any
                    # supplementary text as a single trailing user message.
                    blocks = [part.to_anthropic() if isinstance(part, ContentPart) else part
                              for part in content]
                    tool_msgs, user_msg = _translate_user_blocks(blocks)
                    out.extend(tool_msgs)
                    if user_msg is not None:
                        out.append(user_msg)

            elif role == "assistant":
                if isinstance(content, str):
                    out.append({"role": "assistant", "content": content})
                elif message.content_is_parts:
                    text_parts: list[str] = []
                    tool_calls: list[dict] = []
                    for block in content:
                        if not isinstance(block, ContentPart):
                            continue
                        if block.kind is PartKind.TEXT:
                            text_parts.append(block.payload.get("text", ""))
                        elif block.kind is PartKind.TOOL_CALL:
                            tool_calls.append({
                                "id": block.payload["id"],
                                "type": "function",
                                "function": {
                                    "name": block.payload["name"],
                                    "arguments": json.dumps(block.payload.get("input", {})),
                                },
                            })
                        # thinking blocks are dropped (OpenAI has no equivalent)
                    msg_out: dict[str, Any] = {"role": "assistant"}
                    # Empty content must be "" (OpenAI rejects null when no tool_calls).
                    msg_out["content"] = "\n".join(text_parts) if text_parts else ""
                    if tool_calls:
                        msg_out["tool_calls"] = tool_calls
                        # Stub missing tool_result responses by walking the next user msg.
                        # Caller is responsible for providing them; we don't synthesize here.
                    # Skip purely-empty assistant turns (no text AND no tool_calls).
                    if msg_out["content"] or tool_calls:
                        out.append(msg_out)
        return out

    @staticmethod
    def _to_openai_tools(anthropic_tools: list[dict] | None) -> list[dict] | None:
        if not anthropic_tools:
            return None
        out = []
        for t in anthropic_tools:
            fn: dict[str, Any] = {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object"}),
            }
            if t.get("strict"):
                # Anthropic strict tool use -> OpenAI strict function
                # calling (schema-validated arguments). Only when the tool
                # opted in, so the translated catalog is otherwise unchanged.
                fn["strict"] = True
            out.append({"type": "function", "function": fn})
        return out

    @staticmethod
    def _to_openai_tool_choice(tool_choice: dict | None) -> tuple[Any, bool]:
        """Anthropic ``tool_choice`` -> ``(openai tool_choice, parallel_tool_calls_off)``.

        ``auto``->"auto", ``any``->"required", ``tool``->the named function,
        ``none``->"none"; ``disable_parallel_tool_use`` maps to
        ``parallel_tool_calls: false``.
        """
        from .base import normalize_tool_choice

        choice = normalize_tool_choice(tool_choice)
        if choice is None:
            return None, False
        kind = choice["type"]
        mapped: Any
        if kind == "tool":
            mapped = {"type": "function", "function": {"name": choice["name"]}}
        else:
            mapped = {"auto": "auto", "any": "required", "none": "none"}[kind]
        return mapped, bool(choice.get("disable_parallel_tool_use"))

    @classmethod
    def _from_response(
        cls,
        resp: Any,
        budget: Budget | None,
        model: str | None = None,
        price_model_prefix: str = "",
        usage_required: bool = True,
    ) -> LLMResponse:
        # Record usage first: the call is paid even when its content cannot
        # be parsed below, and a parse error must not skip the charge. A reply
        # with neither choices nor usage keeps the failover-eligible
        # "no choices" error below instead of the accounting error.
        no_choices = not getattr(resp, "choices", None)
        if budget is not None and not (no_choices and not getattr(resp, "usage", None)):
            usage = getattr(resp, "usage", None)
            if not usage and usage_required:
                raise UsageAccountingError(
                    "OpenAI response missing token usage; cannot enforce budget"
                )
            if not usage:
                # Self-hosted server omitted usage (see USAGE_REQUIRED). Its ids
                # price at $0, so there is nothing to enforce: the getattr chain
                # below reads 0/0 and records a $0, zero-token call (which keeps
                # the call counted) instead of aborting the turn.
                log.debug("%s omitted token usage; recording $0 self-hosted call",
                          price_model_prefix.rstrip(":") or "provider")
            # Extract cached-token counts where the provider reports
            # them. Vendors expose this on the usage object under
            # different field names; we try the known shapes and fall
            # back to 0:
            #   - OpenAI:   usage.prompt_tokens_details.cached_tokens
            #   - DeepSeek: usage.prompt_cache_hit_tokens (and _miss_tokens)
            #   - Gemini OpenAI-compat: prompt_tokens_details.cached_tokens
            # When a cached count is reported, the BILLABLE prompt
            # tokens (full rate) is prompt_tokens - cached_tokens.
            cache_read_tok = 0
            details = getattr(usage, "prompt_tokens_details", None)
            if details is not None:
                cache_read_tok = _strict_usage_count(
                    getattr(details, "cached_tokens", 0),
                    "prompt_tokens_details.cached_tokens",
                    missing_ok=True,
                )
            if cache_read_tok == 0:
                cache_read_tok = _strict_usage_count(
                    getattr(usage, "prompt_cache_hit_tokens", 0),
                    "prompt_cache_hit_tokens",
                    missing_ok=True,
                )
            # These counts drive hard spend limits. A flaky gateway returning
            # NaN/Inf/garbage has already billed the upstream call; accepting
            # that as zero would fail open and let later calls bypass budget
            # checks. Fail closed instead.
            default_count = None if usage_required else 0
            full_in = _strict_usage_count(
                getattr(usage, "prompt_tokens", default_count), "prompt_tokens",
            )
            billable_in = max(full_in - cache_read_tok, 0)
            # Bill cache reads at the provider's real discount, not Anthropic's
            # 0.1x budget default. OpenAI/o-series/gpt-5 auto-cache reads are
            # ~0.5x; DeepSeek (~0.1x) and Gemini (~0.25x implicit cache) are
            # steeper and override CACHE_READ_MULT so their hits aren't
            # over-billed at OpenAI's shallower rate.
            budget.record_tokens(
                billable_in,
                _strict_usage_count(
                    getattr(usage, "completion_tokens", default_count), "completion_tokens",
                ),
                model=(price_model_prefix + model) if model else model,
                cache_read_tok=cache_read_tok,
                cache_read_mult=cls.CACHE_READ_MULT,
            )
        if no_choices:
            # Some OpenAI-compatible gateways (and OpenAI/Azure content-filter)
            # return an empty ``choices`` list on an upstream/filter error. An
            # unguarded ``resp.choices[0]`` would raise a cryptic IndexError that
            # propagates out of Agent.run(); surface a clear, actionable message.
            raise RuntimeError(
                "OpenAI-compatible provider returned no choices "
                "(empty response — content filter or upstream gateway error)"
            )
        choice = resp.choices[0]
        text = choice.message.content or ""
        # DeepSeek reasoner and Gemini-thinking (via the OpenAI-compat shim)
        # return the chain-of-thought in a separate reasoning_content field,
        # never in content. Hard-coding thinking=None discarded it entirely.
        thinking = getattr(choice.message, "reasoning_content", None) or None
        tool_calls: list[ToolCall] = []
        if getattr(choice.message, "tool_calls", None):
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, AttributeError, TypeError):
                    args = None
                if not isinstance(args, dict):
                    # Truncated (length-capped), malformed or non-object tool
                    # arguments from a weak model behind vllm/tgi/openrouter.
                    # Running the tool with {} silently can do the wrong thing,
                    # so surface it rather than swallowing it without a trace.
                    args = {}
                    log.warning(
                        "tool call %r had unparseable arguments; running with {} "
                        "(raw=%.200r)",
                        scrub(str(getattr(tc.function, "name", "?") or "?")),
                        scrub(str(getattr(tc.function, "arguments", None) or "")),
                    )
                tool_calls.append(ToolCall(
                    id=tc.id, name=tc.function.name, input=args,
                ))
        # Map finish_reason to Anthropic stop_reason vocab so consumers that
        # check Anthropic values (e.g., 'tool_use', 'end_turn') branch correctly.
        raw_reason = choice.finish_reason or "stop"
        stop_reason = _FINISH_REASON_MAP.get(raw_reason, raw_reason)
        return LLMResponse(
            text=text,
            thinking=thinking,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw=resp,
        )

    def _build_kwargs(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None,
        max_tokens: int,
        model: str | None,
        thinking_budget: int | None = None,
        tool_choice: dict | None = None,
    ) -> dict[str, Any]:
        chosen_model = model or self.DEFAULT_MODEL
        # Write-side prompt-cache friendliness for gpt-4.1 / o-series / gpt-5,
        # which auto-cache the longest common prefix (>= ~1024 tokens) of a
        # request. The stable prefix (system + tools schema) must lead and be
        # byte-identical across calls for the cache to hit; the volatile user
        # turn already trails since _to_openai_messages keeps system first and
        # appends history in order. The one source of cache-busting we control
        # is tool ordering, so sort it to a stable order. Skipped when the
        # prefix is too small to cache (heuristic 4 chars/token estimate) or
        # the model has no auto-cache, to keep behaviour unchanged elsewhere.
        sys_tok = len(system or "") // 4
        tools_tok = sum(len(str(t)) for t in (tools or [])) // 4
        # The cache-friendly tool sort is applied AFTER the 128-tool cap below,
        # on the surviving tools. Sorting before the cap would let tool NAME
        # order (not registration order) choose which 128 survive, silently
        # dropping core/orchestration tools in favour of alphabetically-early
        # MCP tools. See the post-cap stable sort next to the cap.
        kwargs: dict[str, Any] = {
            "model": chosen_model,
            "messages": self._to_openai_messages(system, messages),
        }
        # max_tokens vs max_completion_tokens (latter for gpt-4o/o1/o3/gpt-5+)
        if self._wants_max_completion(chosen_model):
            kwargs["max_completion_tokens"] = max_tokens
        else:
            kwargs["max_tokens"] = max_tokens
        # Map a requested thinking budget to reasoning_effort, but ONLY for
        # actual reasoning models (o-series / gpt-5). gpt-4o/gpt-4.1 also want
        # max_completion_tokens yet reject reasoning_effort with a 400, so this
        # uses the narrower _is_reasoning_model gate.
        if self._is_reasoning_model(chosen_model):
            effort = self._reasoning_effort_for(thinking_budget)
            if effort is not None:
                kwargs["reasoning_effort"] = effort
        oai_tools = self._to_openai_tools(tools)
        mapped_choice, no_parallel = self._to_openai_tool_choice(tool_choice) if oai_tools else (None, False)
        if oai_tools and len(oai_tools) > _OPENAI_MAX_TOOLS:
            # OpenAI's Chat Completions API hard-caps `tools` at 128 and 400s the
            # whole request otherwise ("array too long"). A goal that assembles
            # more would fail entirely. Agent catalogs route overflow through
            # find_tools before reaching this boundary; this last-resort cap is
            # for direct provider callers. An explicitly selected function
            # takes precedence over the last retained tool.
            log.warning(
                "openai: %d tools exceed the API's %d-tool limit; sending the "
                "first %d, retaining any explicitly selected function. "
                "The caller must route overflow through tool discovery.",
                len(oai_tools), _OPENAI_MAX_TOOLS, _OPENAI_MAX_TOOLS,
            )
            retained = oai_tools[:_OPENAI_MAX_TOOLS]
            if isinstance(mapped_choice, dict):
                forced_name = mapped_choice["function"]["name"]
                forced = next(
                    (item for item in oai_tools if item["function"]["name"] == forced_name),
                    None,
                )
                if forced is not None and forced not in retained:
                    retained[-1] = forced
            oai_tools = retained
        if (
            oai_tools
            and self._has_auto_prompt_cache(chosen_model)
            and sys_tok + tools_tok >= _MIN_AUTO_CACHE_TOKENS
        ):
            # Stable, byte-identical tool prefix for the auto prompt cache,
            # applied to the already-capped survivors so ordering never decides
            # WHICH tools survive. The name is nested under "function" after
            # conversion (t["name"] is None here and would collapse the sort).
            oai_tools = sorted(
                oai_tools,
                key=lambda t: str((t.get("function") or {}).get("name") or ""),
            )
        if oai_tools:
            kwargs["tools"] = oai_tools
            # Forced / restricted tool selection and serialised calls.
            if mapped_choice is not None:
                kwargs["tool_choice"] = mapped_choice
            if no_parallel:
                kwargs["parallel_tool_calls"] = False
        return kwargs

    @staticmethod
    def _disable_rejected_tool_reasoning(kwargs: dict[str, Any], exc: Exception) -> bool:
        """Apply the provider's explicit compatibility remedy once, after a 400.

        Reasoning support is model-specific. Forcing ``none`` before every
        tool call breaks older reasoning models and discards requested effort.
        Only honor the precise rejection that explicitly offers ``none``;
        unrelated validation, authentication and transport errors propagate.
        """
        if (
            getattr(exc, "status_code", None) != 400
            or not kwargs.get("tools")
            or kwargs.get("reasoning_effort") == "none"
        ):
            return False
        from openai import BadRequestError

        if not isinstance(exc, BadRequestError):
            return False
        # SDK message text embeds a repr of the response body, which escapes
        # quotes when a model name and the remedy use different quote styles.
        # Inspect the structured provider message before that formatting.
        body = getattr(exc, "body", None)
        message = body.get("message") if isinstance(body, dict) else None
        if not isinstance(message, str):
            message = str(exc.message)
        message = message.lower()
        if (
            "function tools with reasoning_effort are not supported" not in message
            or not any(value in message for value in ("'none'", '"none"'))
        ):
            return False
        log.warning("openai: provider requires reasoning_effort=none with function tools; retrying once")
        kwargs["reasoning_effort"] = "none"
        return True

    def complete(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        on_delta: Callable[[str], None] | None = None,
        tool_choice: dict | None = None,
    ) -> LLMResponse:
        # on_delta accepted for Provider-protocol parity; this client doesn't
        # stream token deltas (the Anthropic client does). Ignored, not error.
        # tool_choice is passed only when set so subclass _build_kwargs
        # overrides with the older signature keep working.
        kwargs = self._build_kwargs(
            system, messages, tools, max_tokens, model, thinking_budget,
            **({"tool_choice": tool_choice} if tool_choice else {}),
        )
        def request():
            try:
                return sync_physical_attempt(lambda: self._sync.chat.completions.create(**kwargs))
            except Exception as exc:
                if not self._disable_rejected_tool_reasoning(kwargs, exc):
                    raise
                return sync_physical_attempt(lambda: self._sync.chat.completions.create(**kwargs))

        resp = sync_retry(request, observe_attempts=False)
        # Meter under the id the caller admitted. A subclass may send another
        # wire id (Ollama's promoted adapter), which the facade would refuse.
        return self._from_response(
            resp, budget, model=model or kwargs.get("model"),
            price_model_prefix=self.PRICE_MODEL_PREFIX,
            usage_required=self.USAGE_REQUIRED,
        )

    async def complete_async(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        tool_choice: dict | None = None,
    ) -> LLMResponse:
        kwargs = self._build_kwargs(
            system, messages, tools, max_tokens, model, thinking_budget,
            **({"tool_choice": tool_choice} if tool_choice else {}),
        )
        async def request():
            try:
                return await async_physical_attempt(lambda: self._async.chat.completions.create(**kwargs))
            except Exception as exc:
                if not self._disable_rejected_tool_reasoning(kwargs, exc):
                    raise
                return await async_physical_attempt(lambda: self._async.chat.completions.create(**kwargs))

        resp = await async_retry(request, observe_attempts=False)
        # Meter under the id the caller admitted. A subclass may send another
        # wire id (Ollama's promoted adapter), which the facade would refuse.
        return self._from_response(
            resp, budget, model=model or kwargs.get("model"),
            price_model_prefix=self.PRICE_MODEL_PREFIX,
            usage_required=self.USAGE_REQUIRED,
        )
