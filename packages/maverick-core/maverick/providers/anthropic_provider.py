"""Anthropic provider client.

Full implementation: prompt caching on system prompt + tool catalog
(ephemeral cache control), extended thinking on demand, streaming with
progress callbacks, sync + async client.

This is the canonical client; other providers translate to/from its
format.
"""
from __future__ import annotations

import logging
import math
import os
from collections.abc import Callable
from typing import Any

import anthropic

from ..budget import Budget, UsageAccountingError
from ..llm import MODEL_OPUS, MODEL_OPUS_FAST, LLMResponse, ToolCall
from ..retry import async_retry, sync_retry
from .anthropic_limits import (
    _adaptive_max_tokens_floor as _adaptive_max_tokens_floor,
)
from .anthropic_limits import _is_opus_adaptive, effective_max_tokens
from .conversation import ConversationMessage, anthropic_messages

# Fast mode is a real
# Anthropic API feature (Claude Opus 5 / Opus 4.8 only, research preview),
# but it needs a specific wire shape -- the beta messages endpoint, this
# beta flag, and a top-level `speed="fast"` parameter -- none of which
# MODEL_OPUS_FAST ("claude-opus-4-8-fast") got: the phantom id was sent
# verbatim as `model`, which the API has never recognized.
_FAST_MODE_BETA = "fast-mode-2026-02-01"

log = logging.getLogger(__name__)
# Module-level flag so we only emit the low-cache warning once per process.
_LOW_CACHE_WARNING_EMITTED: dict[str, bool] = {}


def _default_cache_ttl() -> str:
    """Benchmark mode defaults to 5m TTL (no cross-instance
    reuse), interactive mode keeps 1h (multi-turn within a single
    long-running goal benefits from longer cache life).

    Explicit MAVERICK_ANTHROPIC_CACHE_TTL always wins.
    """
    from ..env_setting import env_or_config

    explicit = env_or_config("MAVERICK_ANTHROPIC_CACHE_TTL", "cache", "anthropic_ttl")
    if explicit:
        return explicit
    coding = os.environ.get("MAVERICK_CODING_MODE", "").lower() in ("1", "true", "yes")
    if coding:
        return "5m"
    return "1h"


def _ephemeral(obj: dict) -> dict:
    # The API's default cache TTL is 5m. For agent workloads -- where system
    # prompts and tool catalogs are reused across many turns inside a single
    # goal -- 5m is too short and
    # forces ~20% extra spend on re-creates. Explicitly set 1h on every
    # cache control block so we get the discount we expect.
    # In coding-mode (SWE-bench style), default to 5m since
    # there is no cross-instance reuse and the 25% cache-write surcharge
    # on a 1h TTL is wasted.
    #
    # Minimum cacheable prompt size (see _min_cache_tokens): the cumulative
    # prompt up to AND INCLUDING the cache breakpoint must reach the model's
    # minimum or the breakpoint is silently ignored (no API error, no cache
    # write, no cache read on subsequent calls). The minimum varies by model
    # family -- 512 to 4,096 tokens -- so whether Lightwork's system prompt
    # (~1,085 tokens) and tool catalog (~716 tokens) actually cache depends
    # on which model is active; the messages breakpoint delivers caching
    # regardless once history grows past the threshold. We mark system +
    # tools with cache_control unconditionally — it's harmless if a given
    # model's block is too small, and starts working once the prompt (or a
    # switch to a lower-minimum model) crosses the threshold.
    ttl = _default_cache_ttl()
    return {**obj, "cache_control": {"type": "ephemeral", "ttl": ttl}}


# Cacheable-block minimums per Anthropic model family, verified against
# https://platform.claude.com/docs/en/build-with-claude/prompt-caching
# ("Cache limitations"). Used to warn / no-op cache_control (and to skip
# prewarm()) when the prompt is too small to actually get cached.
_MIN_CACHE_TOKENS_512 = 512
_MIN_CACHE_TOKENS_1024 = 1024
_MIN_CACHE_TOKENS_2048 = 2048
_MIN_CACHE_TOKENS_4096 = 4096


def _min_cache_tokens(model_id: str) -> int:
    """Minimum cumulative prompt tokens (up to + including breakpoint)
    required for prompt caching to actually take effect, per
    https://platform.claude.com/docs/en/build-with-claude/prompt-caching.

    The prior table put every 4.5+/4.6+ model at the 4,096 minimum that
    actually only applies to Opus 4.5/4.6 (and Haiku 4.5) -- which meant
    the current defaults, Opus 4.8 and Sonnet 4.6 (both really 1,024),
    were wrongly gated at 4,096: prewarm() silently no-op'd for prompts
    that would in fact have cached, and the debug log claimed the
    breakpoint would be ignored when it would not. 1,024 tokens is the
    documented minimum for most models (Opus 4.8, Sonnet 5, Sonnet 4.6,
    Sonnet 4.5, and the retired Opus 4.1/4/Sonnet 4, plus every Claude 3.x
    model) and is this function's default; only the families below need a
    different value.
    """
    if model_id.startswith("claude-opus-4-6") or model_id.startswith("claude-opus-4-5"):
        return _MIN_CACHE_TOKENS_4096
    if model_id.startswith("claude-haiku-4-5"):
        return _MIN_CACHE_TOKENS_4096
    if model_id.startswith("claude-opus-4-7"):
        return _MIN_CACHE_TOKENS_2048
    if model_id.startswith(("claude-opus-5", "claude-fable-5", "claude-mythos-5")):
        return _MIN_CACHE_TOKENS_512
    return _MIN_CACHE_TOKENS_1024


def _cached_system(text: str) -> list[dict]:
    return [_ephemeral({"type": "text", "text": text})]


def _cached_tools(tools: list[dict]) -> list[dict]:
    if not tools:
        return tools
    # Sort tools by name BEFORE sending so the
    # tool catalog is byte-identical across calls — Anthropic's prompt
    # cache key includes the tools[] block, and a non-deterministic
    # order silently busts the cache write. Stable order = predictable
    # cache hits = 30-50% input cost reduction over the run.
    # Coerce key via str() so a malformed tool with
    # name=None or non-string doesn't blow sorted() with TypeError.
    out = [dict(t) for t in sorted(
        tools, key=lambda t: str(t.get("name") or ""),
    )]
    out[-1] = _ephemeral(out[-1])
    return out


def _strip_message_cache_control(messages: list[dict]) -> list[dict]:
    """Remove any pre-existing ``cache_control`` from message content blocks.

    Re-sent history can carry ``cache_control`` marks from earlier turns (a
    previously-marked breakpoint replayed in the next request). Left in place
    they stack with the fresh system + tools + messages breakpoints and can
    exceed Anthropic's hard limit of **4 cache breakpoints** -- a 400 on long
    trajectories. Stripping first guarantees the messages array contributes at
    most the single breakpoint we add below.
    """
    out: list[dict] = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, list) and any(
            isinstance(b, dict) and "cache_control" in b for b in content
        ):
            blocks = [
                {k: v for k, v in b.items() if k != "cache_control"}
                if isinstance(b, dict) else b
                for b in content
            ]
            out.append({**m, "content": blocks})
        else:
            out.append(m)
    return out


# A single agentic turn can append many tool_use/tool_result blocks. Anthropic
# walks back at most 20 content blocks from a breakpoint to find a prior cache
# entry, so on a long turn the next request's breakpoint can fall outside the
# window and silently miss. When the history is long we add a SECOND, earlier
# breakpoint within the window so the chain stays warm. System(1)+tools(1)+2
# message marks = 4, exactly the hard breakpoint limit.
#
# All three thresholds are counted in CONTENT BLOCKS, the unit the lookback
# actually uses — the old >=24-MESSAGE trigger missed block-heavy histories (a
# few fan-out turns with many parallel tool_results blow past 20 blocks well
# under 24 messages), leaving the chain cold exactly when tool output is
# biggest and each turn re-wrote the full prefix.
_LONG_HISTORY_BLOCKS = 16
_SECONDARY_MIN_GAP_BLOCKS = 4
_SECONDARY_MAX_GAP_BLOCKS = 16


def _content_block_count(msg: dict) -> int:
    """Content blocks one message contributes (str content counts as one)."""
    c = msg.get("content")
    return len(c) if isinstance(c, list) else 1


def _msg_cache_ttl() -> str:
    """TTL for the MESSAGE-tier breakpoints (system/tools keep
    ``_default_cache_ttl``). The message breakpoint re-anchors to a new
    position every turn, so its write surcharge is paid per turn — and the
    re-read lands seconds later on the next turn. 5m (1.25x write) covers
    that; 1h (2x write) buys nothing unless turns stall. An explicit
    operator TTL (either env) still wins."""
    from ..env_setting import env_or_config

    explicit = (os.environ.get("MAVERICK_ANTHROPIC_MSG_CACHE_TTL")
                or os.environ.get("MAVERICK_ANTHROPIC_CACHE_TTL")
                or env_or_config("MAVERICK_ANTHROPIC_MSG_CACHE_TTL", "cache",
                                 "anthropic_message_ttl")
                or env_or_config("MAVERICK_ANTHROPIC_CACHE_TTL", "cache", "anthropic_ttl"))
    return explicit or "5m"


def _mark_user_message(msg: dict) -> dict:
    """Return a copy of ``msg`` with cache_control on its last content block."""
    cc = {"type": "ephemeral", "ttl": _msg_cache_ttl()}
    content = msg.get("content")
    if isinstance(content, str):
        return {**msg, "content": [{"type": "text", "text": content, "cache_control": cc}]}
    if isinstance(content, list) and content:
        new_blocks = [dict(b) for b in content]
        new_blocks[-1] = {**new_blocks[-1], "cache_control": cc}
        return {**msg, "content": new_blocks}
    return msg


def _forced_tool_choice_unsupported(model_id: str) -> bool:
    """Models on which ``tool_choice`` ``any``/``tool`` return a 400
    (forced-tool-use-not-supported): Claude Fable and Mythos 5.1 and 5.2,
    Opus 5.5 and Sonnet 5.5 per the tool-use and migration docs.
    ``auto``/``none`` still work there; strict tool use is the documented
    substitute for schema-valid inputs."""
    return model_id.startswith((
        "claude-fable-5-1", "claude-mythos-5-1",
        "claude-fable-5-2", "claude-mythos-5-2",
        "claude-opus-5-5", "claude-sonnet-5-5",
    ))


def _append_user_text(messages: list[dict], text: str) -> list[dict]:
    """A copy of ``messages`` with ``text`` appended as a trailing text block
    on the last user message (the volatile turn, never the cached prefix).
    Leaves ``messages`` untouched when there is no user message to extend."""
    for idx in range(len(messages) - 1, -1, -1):
        if messages[idx].get("role") != "user":
            continue
        content = messages[idx].get("content")
        if isinstance(content, str):
            blocks: list = [{"type": "text", "text": content}] if content else []
        elif isinstance(content, list):
            blocks = list(content)
        else:
            return messages
        blocks.append({"type": "text", "text": text})
        out = list(messages)
        out[idx] = {**messages[idx], "content": blocks}
        return out
    return messages


def _apply_tool_choice(
    kwargs: dict[str, Any],
    tool_choice: dict | None,
    model_id: str,
) -> None:
    """Translate a normalized ``tool_choice`` onto an Anthropic request.

    A forced choice (``any``/``tool``) is clamped to ``auto`` where the API
    rejects it -- Fable/Mythos 5.1 and 5.2, Opus 5.5, Sonnet 5.5, or manual
    extended thinking (``thinking.type == "enabled"``) -- and the intent is carried as an
    instruction on the last user message instead, which the docs name as the
    supported alternative. ``disable_parallel_tool_use`` survives the clamp.
    """
    from .base import normalize_tool_choice

    choice = normalize_tool_choice(tool_choice)
    if choice is None or not kwargs.get("tools"):
        return
    manual_thinking = (kwargs.get("thinking") or {}).get("type") == "enabled"
    if choice["type"] in ("any", "tool") and (
        _forced_tool_choice_unsupported(model_id) or manual_thinking
    ):
        wanted = choice.get("name")
        instruction = (
            f"Respond by calling the `{wanted}` tool." if wanted
            else "Respond by calling one of the available tools."
        )
        log.info(
            "tool_choice %s not supported for %s (%s); sending auto with an "
            "instruction instead", choice["type"], model_id,
            "manual thinking" if manual_thinking else "model",
        )
        kwargs["messages"] = _append_user_text(kwargs["messages"], instruction)
        choice = {"type": "auto", **(
            {"disable_parallel_tool_use": True}
            if choice.get("disable_parallel_tool_use") else {}
        )}
    kwargs["tool_choice"] = choice


def _add_messages_cache_breakpoint(messages: list[dict]) -> list[dict]:
    """Mark the most recent stable user/tool_result message(s) for caching.

    Anthropic prompt caching caches everything up to AND including the
    marked breakpoint. The system prompt + tools are already cached; the
    remaining breakpoint slots are best spent on the most recent stable turn so
    multi-turn agent loops (which re-send the entire history every step) get
    cache reads instead of writes for the message body (40-55% input cost cut on
    long tool-use trajectories). On a long history we add a second, earlier
    breakpoint so the 20-block lookback never strands the chain.
    """
    if not messages or len(messages) < 2:
        return messages
    # Drop any cache_control carried in from prior turns so the messages array
    # contributes only the breakpoints we add (system + tools + <=2 <= 4 limit).
    messages = _strip_message_cache_control(messages)
    # Primary: the most recent user message that's NOT the final one (the final
    # user message changes every turn -- caching it would write a fresh entry
    # every call, the OPPOSITE of what we want).
    target_idx = None
    for i in range(len(messages) - 2, -1, -1):
        if messages[i].get("role") == "user":
            target_idx = i
            break
    if target_idx is None:
        return messages
    new_messages = list(messages)
    new_messages[target_idx] = _mark_user_message(new_messages[target_idx])

    # Secondary breakpoint for long histories: an earlier user message inside
    # the lookback window, so a single long turn can't push the chain out of
    # it. Counted in blocks (the lookback's unit): pick the closest user
    # message >= MIN_GAP blocks behind the primary, giving up past MAX_GAP.
    total_blocks = sum(_content_block_count(m) for m in messages)
    if total_blocks >= _LONG_HISTORY_BLOCKS:
        gap = _content_block_count(messages[target_idx])
        for i in range(target_idx - 1, -1, -1):
            if gap > _SECONDARY_MAX_GAP_BLOCKS:
                break
            if (gap >= _SECONDARY_MIN_GAP_BLOCKS
                    and new_messages[i].get("role") == "user"):
                new_messages[i] = _mark_user_message(new_messages[i])
                break
            gap += _content_block_count(messages[i])
    return new_messages


class AnthropicClient:
    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 default_headers: dict | None = None, *, environment=None):
        # Strip whitespace.
        # `export ANTHROPIC_API_KEY=$(cat key.txt)` is a common source of
        # trailing newline; without strip, every API call 401s and the
        # operator sees "API outage" instead of the real "key has
        # whitespace" issue.
        env = os.environ if environment is None else environment
        key = (api_key or env.get("ANTHROPIC_API_KEY") or "").strip() or None
        from .base import sdk_http_timeout
        kw: dict = {"api_key": key}
        if environment is not None:
            token = env.get("ANTHROPIC_AUTH_TOKEN", "")
            if not key and not token:
                raise RuntimeError("Anthropic requires a credential in the admitted provider configuration")
            kw.update(
                api_key=key or "", auth_token=token,
                base_url=base_url or env.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com",
            )
        # Thread an explicit `[providers.anthropic] base_url` into the SDK so a
        # configured endpoint (proxy / gateway) is honored. ``None`` leaves the
        # SDK's own default base_url (mirrors how OpenAIClient handles base_url).
        if base_url:
            kw["base_url"] = base_url
        # Data-residency / ZDR control: operator-set `[providers.anthropic]
        # default_headers` are attached to every request, so a compliance
        # gateway can enforce region pinning / zero-data-retention headers
        # (e.g. {"anthropic-region": "eu"}). Empty by default -> no extra headers.
        if default_headers:
            kw["default_headers"] = dict(default_headers)
        timeout = sdk_http_timeout(anthropic, environment=environment)
        if timeout is not None:
            kw["timeout"] = timeout
        self.client = anthropic.Anthropic(max_retries=0, **kw)
        self.aclient = anthropic.AsyncAnthropic(max_retries=0, **kw)

    def _build_request(
        self,
        system: str,
        messages: list[dict | ConversationMessage],
        tools: list[dict] | None,
        max_tokens: int,
        thinking_budget: int | None,
        model: str | None,
        effort: str | None = None,
        tool_choice: dict | None = None,
    ) -> dict[str, Any]:
        messages = anthropic_messages(messages)
        # Fast mode: MODEL_OPUS_FAST is a catalog-only id, never sent
        # to the API. Substitute the real model NOW so every prefix check
        # below (adaptive-thinking gating, cache minimums, etc.) sees the
        # actual "claude-opus-4-8" and behaves identically to a plain Opus
        # request; the fast-mode-specific kwargs are layered on at the end.
        want_fast = model == MODEL_OPUS_FAST
        if want_fast:
            model = MODEL_OPUS

        # Cache the most recent stable user message so repeated
        # tool-use turns hit the cache for the history (40-55% input
        # token cost cut on long trajectories). Toggle via env var so
        # the dashboard can A/B it.
        from ..env_setting import env_or_config

        if env_or_config("MAVERICK_CACHE_MESSAGES", "cache", "messages", "1") != "0":
            messages_out = _add_messages_cache_breakpoint(messages)
        else:
            messages_out = messages

        kwargs: dict[str, Any] = {
            "model": model or self.DEFAULT_MODEL,
            "system": _cached_system(system),
            "messages": messages_out,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = _cached_tools(tools)

        # Note (at DEBUG, once per model) when system+tools is
        # below the min-cache threshold. The cache_control markers are silently
        # ignored in that case — we still set them so caching kicks in if/when
        # the prompt grows. Kept at debug, not warning: the consumer CLI installs
        # no log handler, so a WARNING bleeds straight onto the terminal in the
        # middle of a normal `chat` / `start` run. Operators who want it can
        # raise the log level (e.g. MAVERICK_DEBUG=1).
        model_for_min = kwargs["model"] or ""
        min_tokens = _min_cache_tokens(model_for_min)
        if not _LOW_CACHE_WARNING_EMITTED.get(model_for_min):
            # Heuristic token estimate: 4 chars/token.
            sys_tok = len(system or "") // 4
            tools_tok = (
                sum(len(str(t)) for t in (tools or [])) // 4
            )
            if sys_tok + tools_tok < min_tokens:
                log.debug(
                    "prompt cache no-op: system+tools=%d tok (~%d sys + ~%d tools) "
                    "< %d-token min for %s. cache_control on system/tools "
                    "is ignored; only the messages breakpoint will cache "
                    "once history grows past %d tokens. Expand the system "
                    "prompt or tool descriptions to unlock system/tool caching.",
                    sys_tok + tools_tok, sys_tok, tools_tok,
                    min_tokens, model_for_min, min_tokens,
                )
                _LOW_CACHE_WARNING_EMITTED[model_for_min] = True
        # Thinking + interleaved-thinking handling per Anthropic's docs
        # (platform.claude.com/docs/.../adaptive-thinking):
        #
        #   - Opus 4.7:  ONLY adaptive mode accepted. Manual
        #                `thinking={"type":"enabled"}` returns 400.
        #                Interleaved thinking is automatic — no header.
        #   - Opus 4.6 / Sonnet 4.6 / Haiku 4.5: interleaved is automatic
        #                in adaptive mode; the beta header is deprecated
        #                and ignored.
        #   - Sonnet 4.5 / Opus 4.5 and older: the
        #                `interleaved-thinking-2025-05-14` header is
        #                still required to get interleaved behavior.
        #
        # An earlier commit set the beta header unconditionally
        # for any "claude-opus-/claude-sonnet-4" prefix — that breaks
        # against Opus 4.7 (400) and is wasted noise on 4.6.
        model_id = (model or self.DEFAULT_MODEL) or ""
        # Opus 4.7 AND 4.8 (the current default, incl. its `-fast` variant)
        # only accept adaptive thinking; manual `enabled` returns 400.
        # Gating on 4-7 alone left the default model on the `enabled` path.
        is_opus_47 = _is_opus_adaptive(model_id)
        is_modern_4x = (
            model_id.startswith("claude-opus-4-6")
            or model_id.startswith("claude-opus-4-7")
            or model_id.startswith("claude-opus-4-8")
            or model_id.startswith("claude-sonnet-4-6")
            or model_id.startswith("claude-haiku-4-5")
        )
        legacy_thinking_header_required = (
            model_id.startswith("claude-opus-4-5")
            or model_id.startswith("claude-sonnet-4-5")
        )

        if thinking_budget and thinking_budget > 0:
            kwargs["max_tokens"] = effective_max_tokens(
                model_id, max_tokens, thinking_budget)
            if is_opus_47:
                # Opus 4.7 rejects explicit "enabled"; only "adaptive"
                # is supported. Drop budget_tokens — adaptive auto-sizes.
                kwargs["thinking"] = {"type": "adaptive"}
            else:
                kwargs["thinking"] = {
                    "type": "enabled", "budget_tokens": thinking_budget,
                }

        # Beta header gating — only set on legacy models that still need it.
        if legacy_thinking_header_required and "thinking" in kwargs:
            extra_headers = kwargs.get("extra_headers", {})
            beta = extra_headers.get("anthropic-beta", "")
            betas = [b.strip() for b in beta.split(",") if b.strip()]
            if "interleaved-thinking-2025-05-14" not in betas:
                betas.append("interleaved-thinking-2025-05-14")
            extra_headers["anthropic-beta"] = ",".join(betas)
            kwargs["extra_headers"] = extra_headers
        # For 4.6 and 4.7 models, interleaved is automatic in adaptive
        # mode — no header needed. Note: even WITHOUT thinking_budget,
        # callers may want adaptive default on Opus 4.7. Surface that:
        if is_opus_47 and "thinking" not in kwargs:
            # Opus 4.7 with no explicit thinking spec: let the model
            # decide via adaptive. This matches the docs' "adaptive is
            # the only supported mode" guidance.
            kwargs["thinking"] = {"type": "adaptive"}
            # Adaptive thinking
            # can spend the entire `max_tokens` budget on thinking and
            # leave nothing for the tool_use / text output, producing
            # an empty response. Bump headroom for adaptive runs — but
            # bounded: this fires for every role that did NOT ask to
            # think (thinking_budget=None), so the floor is the default
            # worst-case output spend of the whole fleet.
            kwargs["max_tokens"] = effective_max_tokens(model_id, max_tokens)
        _ = is_modern_4x  # documented above; kept for future logic
        # Orchestrator best-of-N sets a per-attempt sampling temperature to
        # force candidate diversity. It is read from a ContextVar (per goal
        # task, race-free across concurrent goals); MAVERICK_TEMPERATURE remains
        # honoured as a process-wide fallback for manual/CLI use.
        # Thinking models reject explicit temperature (400). Gate on whether
        # `thinking` actually ended up in the request -- not on thinking_budget,
        # which misses the adaptive-thinking auto-injected for Opus 4.7/4.8 just
        # above (that path set thinking_budget=None yet still sends thinking, so
        # the old gate let temperature through and the API 400'd).
        from .base import sampling_temperature
        temp = sampling_temperature()
        if temp is None:
            from ..env_setting import env_or_config

            raw = env_or_config("MAVERICK_TEMPERATURE", "agent", "temperature")
            if raw:
                try:
                    temp = float(raw)
                except ValueError:
                    temp = None
        if temp is not None and "thinking" not in kwargs:
            kwargs["temperature"] = temp

        # Per-role reasoning effort (output_config.effort) — the biggest
        # cost/latency lever on Opus 4.7/4.8. Caller usually resolves it via
        # maverick.effort.effort_for_role, but provider failover can carry a
        # primary model's effort to a lower-ceiling fallback. Defence-in-depth:
        # validate and re-clamp for the actual model so a stray effort never 400s.
        if effort:
            from ..effort import effort_for_model
            model_effort = effort_for_model(effort, model_id)
            if model_effort:
                oc = kwargs.get("output_config")
                if isinstance(oc, dict):
                    oc["effort"] = model_effort
                else:
                    kwargs["output_config"] = {"effort": model_effort}

        # Forced / restricted tool selection, after thinking is settled
        # (a manual-thinking request cannot force a tool).
        _apply_tool_choice(kwargs, tool_choice, model_id)

        if want_fast:
            # `speed` is a top-level request field the API only validates on
            # the beta messages endpoint; complete/complete_async route this
            # request there when they see it.
            kwargs["speed"] = "fast"
            kwargs["betas"] = [_FAST_MODE_BETA]
        return kwargs

    def _parse_response(
        self,
        resp: Any,
        budget: Budget | None,
        model: str | None = None,
    ) -> LLMResponse:
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        # Preserve PER-BLOCK
        # signatures. With Opus 4.7 interleaved thinking, a single
        # turn can emit multiple thinking blocks, each with its own
        # signature derived from that block's text. Concatenating
        # text but keeping only the first signature broke the
        # second turn (Anthropic rejects the assistant message
        # because the signature doesn't match the text).
        thinking_blocks: list[tuple[str, str | None]] = []
        # Capture blocks in their ORIGINAL order. Anthropic rejects a
        # rearranged thinking-block sequence ("the latest assistant
        # message ... cannot be modified"), which a bucket-by-type
        # reconstruction would produce on interleaved Opus 4.7 turns
        # (thinking between tool_use). We replay these verbatim.
        content_blocks: list[dict] = []
        for block in resp.content:
            t = getattr(block, "type", None)
            if t == "text":
                text_parts.append(block.text)
                content_blocks.append({"type": "text", "text": block.text})
            elif t == "thinking":
                text = getattr(block, "thinking", "")
                sig = getattr(block, "signature", None)
                thinking_parts.append(text)
                thinking_blocks.append((text, sig))
                tb: dict = {"type": "thinking", "thinking": text}
                if sig:
                    tb["signature"] = sig
                content_blocks.append(tb)
            elif t == "redacted_thinking":
                # Opaque, signature-bearing block. The old loop dropped
                # these entirely, which also breaks the "must match the
                # original response" contract — echo it back unchanged.
                data = getattr(block, "data", None)
                rb: dict = {"type": "redacted_thinking"}
                if data is not None:
                    rb["data"] = data
                content_blocks.append(rb)
            elif t == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, input=dict(block.input)))
                content_blocks.append({
                    "type": "tool_use", "id": block.id,
                    "name": block.name, "input": dict(block.input),
                })

        # Nullsafe usage parsing.
        # If resp.usage itself is None (streaming refusal), getattr
        # chains through 0 defaults. Coerce all values via int() inside
        # a try block to catch non-int truthy values (string "100" from
        # a mock, Decimal from a future SDK schema). A NaN or infinite count
        # is refused: the call is already paid, and reading it as 0 would
        # let it pass the spend caps unrecorded.
        usage = getattr(resp, "usage", None)

        def _safe_int(value, default=0) -> int:
            if isinstance(value, float) and not math.isfinite(value):
                raise UsageAccountingError(
                    f"invalid Anthropic usage: non-finite token count {value!r}"
                )
            try:
                return int(value) if value is not None else default
            except (TypeError, ValueError):
                return default

        cache_creation = _safe_int(getattr(usage, "cache_creation_input_tokens", 0))
        cache_read = _safe_int(getattr(usage, "cache_read_input_tokens", 0))
        in_tok = _safe_int(getattr(usage, "input_tokens", 0))
        out_tok = _safe_int(getattr(usage, "output_tokens", 0))
        # The system/tools breakpoint writes at _default_cache_ttl()
        # (1h in interactive mode) while the messages breakpoint writes at
        # _msg_cache_ttl() (5m) -- a single call can write BOTH tiers at
        # once. Anthropic reports the real per-tier split as
        # usage.cache_creation.{ephemeral_5m,ephemeral_1h}_input_tokens when
        # present; billing the combined total at one multiplier overcharges
        # (or undercharges) whichever tier isn't the one that TTL matches.
        cache_creation_detail = getattr(usage, "cache_creation", None)
        cache_write_5m = _safe_int(getattr(cache_creation_detail, "ephemeral_5m_input_tokens", 0))
        cache_write_1h = _safe_int(getattr(cache_creation_detail, "ephemeral_1h_input_tokens", 0))

        if budget is not None:
            # ``usage.input_tokens`` is non-cached input only. Cache reads
            # and writes are billed separately at different rates.
            budget.record_tokens(
                in_tok, out_tok,
                model=model,
                cache_read_tok=cache_read,
                cache_write_tok=cache_creation,
                # Pass TTL so write surcharge math matches the
                # actual breakpoint TTL (5m vs 1h) when the per-tier split
                # below isn't available (older SDK, or a single-tier write).
                cache_write_ttl=_default_cache_ttl(),
                cache_write_5m_tok=cache_write_5m,
                cache_write_1h_tok=cache_write_1h,
            )

        # Prometheus token + cache-effectiveness metrics (no-op unless the
        # exporter is on). Records billed tokens by direction and the three
        # prompt-cache buckets so a `cache_read / (cache_read + input)` hit-rate
        # panel makes a silent cache invalidator visible as a metric, not just a
        # cost bump. Fail-soft: metrics never break a turn.
        try:
            from ..observability import record_metric as _rm
            _m = model or self.DEFAULT_MODEL or "default"
            _lbl = {"provider": "anthropic", "model": _m}
            if in_tok:
                _rm("llm_tokens", in_tok, labels={**_lbl, "direction": "input"})
            if out_tok:
                _rm("llm_tokens", out_tok, labels={**_lbl, "direction": "output"})
            if cache_read:
                _rm("llm_cache_tokens", cache_read, labels={**_lbl, "kind": "read"})
            if cache_creation:
                _rm("llm_cache_tokens", cache_creation, labels={**_lbl, "kind": "creation"})
            if in_tok:
                _rm("llm_cache_tokens", in_tok, labels={**_lbl, "kind": "uncached"})
        except Exception:  # pragma: no cover -- metrics never break a turn
            pass

        # Per-turn observability — log model + cache stats so operators
        # can verify caching is actually engaging on real API calls.
        # Gated on MAVERICK_LOG_TURNS to keep production logs quiet.
        # Print direct to stderr so it survives default-level logging
        # filters (log.info doesn't print by default).
        if os.environ.get("MAVERICK_LOG_TURNS"):
            import sys as _sys
            _sys.stderr.write(
                f"llm_turn model={model or 'default'} "
                f"in={in_tok} out={out_tok} "
                f"cache_read={cache_read} cache_write={cache_creation} "
                f"stop={resp.stop_reason}\n"
            )
            _sys.stderr.flush()

        return LLMResponse(
            text="\n".join(text_parts).strip(),
            thinking="\n".join(thinking_parts).strip() or None,
            thinking_blocks=thinking_blocks,
            thinking_signature=(
                thinking_blocks[0][1] if thinking_blocks else None
            ),
            content_blocks=content_blocks,
            tool_calls=tool_calls,
            stop_reason=resp.stop_reason,
            cache_creation_tokens=cache_creation,
            cache_read_tokens=cache_read,
            raw=resp,
        )

    def complete(
        self,
        system: str,
        messages: list[dict | ConversationMessage],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        on_delta: Callable[[str], None] | None = None,
        effort: str | None = None,
        tool_choice: dict | None = None,
    ) -> LLMResponse:
        kwargs = self._build_request(
            system, messages, tools, max_tokens, thinking_budget, model, effort,
            tool_choice=tool_choice)
        # Fast mode is beta-endpoint-only: `speed` is only a validated
        # field on client.beta.messages.*. Bill against the CALLER's model id
        # ("claude-opus-4-8-fast", the correctly-priced rate-card SKU), not
        # kwargs["model"] (the real wire id _build_request substituted) --
        # but only for the fast-mode case; the non-fast default (model=None
        # -> DEFAULT_MODEL) still needs kwargs["model"] for the resolved id.
        is_fast = kwargs.get("speed") == "fast"
        endpoint = self.client.beta.messages if is_fast else self.client.messages
        billing_model = model if is_fast else kwargs.get("model")
        if on_delta is None:
            resp = sync_retry(lambda: endpoint.create(**kwargs))
            return self._parse_response(resp, budget, model=billing_model)

        # Wrapping the streaming path in sync_retry
        # would replay every on_delta callback after a mid-stream
        # failure, so consumers see duplicate prefixes. Streaming is
        # called from interactive paths (CLI --stream, dashboard chat);
        # surface the error directly and let the caller retry the
        # higher-level request without partial output.
        with endpoint.stream(**kwargs) as stream:
            for event in stream.text_stream:
                on_delta(event)
            final = stream.get_final_message()
        return self._parse_response(final, budget, model=billing_model)

    async def complete_async(
        self,
        system: str,
        messages: list[dict | ConversationMessage],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        effort: str | None = None,
        tool_choice: dict | None = None,
        on_delta: Callable[[str], None] | None = None,
    ) -> LLMResponse:
        kwargs = self._build_request(
            system, messages, tools, max_tokens, thinking_budget, model, effort,
            tool_choice=tool_choice)
        is_fast = kwargs.get("speed") == "fast"
        endpoint = self.aclient.beta.messages if is_fast else self.aclient.messages
        billing_model = model if is_fast else kwargs.get("model")
        if on_delta is None:
            resp = await async_retry(lambda: endpoint.create(**kwargs))
            return self._parse_response(resp, budget, model=billing_model)
        # Streaming mirrors complete(): no retry wrapper, so a mid-stream
        # failure never replays deltas the caller has already shown.
        async with endpoint.stream(**kwargs) as stream:
            async for text in stream.text_stream:
                on_delta(text)
            final = await stream.get_final_message()
        return self._parse_response(final, budget, model=billing_model)

    def prewarm(
        self,
        system: str,
        tools: list[dict] | None = None,
        model: str | None = None,
        *,
        budget: Budget | None = None,
    ) -> bool:
        """Pre-warm the prompt cache with a ``max_tokens=0`` prefill.

        Writes the cache at the system + tools breakpoint and returns
        immediately (``content: []``, no output tokens billed), so the *first*
        real turn reads the cache instead of paying the cold-write latency.
        Built without ``_build_request`` on purpose: ``max_tokens=0`` rejects
        ``thinking``/``output_config``/``tool_choice``, and toggling thinking
        leaves the system+tools cache intact (it only invalidates the messages
        tier), so a thinking-free warm still serves a thinking-enabled real call.
        Never raises into the caller; returns whether the warm was sent."""
        # Minimum-size gate: below the model's cacheable-prefix minimum the
        # breakpoint is silently ignored, so the warm call would bill its
        # full input at list price and write NOTHING — cost with zero
        # benefit. chars/4 mirrors the preflight heuristic.
        mid = model or self.DEFAULT_MODEL
        est_tokens = (len(system or "")
                      + sum(len(str(t)) for t in tools or [])) / 4
        min_tokens = _min_cache_tokens(mid)
        if est_tokens < min_tokens:
            log.debug(
                "prompt-cache prewarm skipped: est %d tokens < %d minimum "
                "for %s (nothing would be cached)",
                est_tokens, min_tokens, mid)
            return False
        try:
            kwargs: dict[str, Any] = {
                "model": model or self.DEFAULT_MODEL,
                "system": _cached_system(system),
                "max_tokens": 0,
                # Placeholder turn (any non-whitespace string); the breakpoint is
                # on system/tools, so this message is read during prefill but not
                # cached and never answered.
                "messages": [{"role": "user", "content": "warmup"}],
            }
            if tools:
                kwargs["tools"] = _cached_tools(tools)
            from ..retry import sync_physical_attempt

            resp = sync_physical_attempt(lambda: self.client.messages.create(**kwargs))
            if budget is not None:
                self._parse_response(resp, budget, model=kwargs.get("model"))
            return True
        except Exception:  # pragma: no cover -- prewarm is best-effort
            log.debug("prompt-cache prewarm skipped", exc_info=True)
            return False

