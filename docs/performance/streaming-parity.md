# Provider streaming support

Every provider adapter in `packages/maverick-core/maverick/providers/` exposes a
synchronous `complete()` and an asynchronous `complete_async()` that take
Anthropic-format messages and tools and return an `LLMResponse`. Token streaming
is delivered through an optional `on_delta(text)` callback. This page lists what
each adapter implements and what the `LLM` dispatcher (`maverick/llm.py`)
forwards to it.

| Provider | Adapter | `complete()` | `complete_async()` | Adapter streams to `on_delta` | Streams through the `LLM` dispatcher |
|---|---|:-:|:-:|---|:-:|
| `anthropic` | `AnthropicClient` | Yes | Yes | Yes, sync and async (`messages.stream`) | Yes |
| `bedrock` | `BedrockClient` (Anthropic adapter on Bedrock) | Yes | Yes | Yes, inherited from `AnthropicClient` | No |
| `vertex` | `VertexClient` (Anthropic adapter on Vertex AI) | Yes | Yes | Yes, inherited from `AnthropicClient` | No |
| `openai` | `OpenAIClient` | Yes | Yes | No (see below) | No |
| `azure` | `AzureOpenAIClient` (OpenAI adapter) | Yes | Yes | No | No |
| `openrouter` | `OpenRouterClient` (OpenAI adapter) | Yes | Yes | No | No |
| `gemini` | `GeminiClient` (OpenAI adapter, Gemini's OpenAI-compatible endpoint) | Yes | Yes | No | No |
| `moonshot` | `MoonshotClient` (OpenAI adapter) | Yes | Yes | No | No |
| `deepseek` | `DeepSeekClient` (OpenAI adapter) | Yes | Yes | No | No |
| `xai` | `XaiClient` (OpenAI adapter) | Yes | Yes | No | No |
| `ollama` | `OllamaClient` (OpenAI adapter) | Yes | Yes | No | No |
| `tgi` | `TGIClient` (OpenAI adapter) | Yes | Yes | No | No |
| `vllm` | `VLLMClient` (OpenAI adapter) | Yes | Yes | No | No |
| `openai_compatible` | `OpenAICompatibleClient` (OpenAI adapter) | Yes | Yes | No | No |
| `codex_cli` | `CodexCLIClient` (runs `codex exec`) | Yes, runs the async path | Yes | No; `on_delta` is accepted and discarded | No |

The OpenAI adapter and every adapter built on it send a buffered
`chat.completions.create` request. `complete()` accepts `on_delta` for interface
compatibility and ignores it; `complete_async()` has no `on_delta` parameter.
The answer arrives in one piece when the call completes.

## How the dispatcher streams

- `LLM.complete()` and `LLM.complete_async()` forward `on_delta` only when the
  provider is `anthropic`. Every other provider, including `bedrock` and
  `vertex`, receives a buffered call (`test_llm_forwards_on_delta_only_to_anthropic`
  in `packages/maverick-core/tests/test_answer_streaming.py`).
- The Anthropic streaming path is not wrapped in the retry helper. A mid-stream
  failure is raised to the caller rather than replaying deltas the caller has
  already shown. Calls without `on_delta` use the normal retry path.
- A streaming call is never hedged, so a backup request cannot write a second
  copy of the answer into the same callback. On failover, a callback that has a
  `reset()` method is reset before the next model's attempt, so a failed
  attempt's partial text is not joined to the next answer.

## Chat answer previews

The root agent of a conversational run passes `on_delta` to the model and
mirrors the text into the goal's result, which the dashboard streams to the
page; secrets are held back until they can be redacted. Previews are on by
default; set `[chat] stream_answers = false` or `MAVERICK_STREAM_ANSWERS=0` to
turn them off. With a provider that does not stream, the answer appears when
the call completes.

## Cached-token accounting

Cached input tokens are billed at each provider's cache-read rate whether or not
the call streams. The OpenAI adapter reads
`usage.prompt_tokens_details.cached_tokens`, falling back to DeepSeek's
`prompt_cache_hit_tokens`, and bills cached tokens at the adapter's
`CACHE_READ_MULT`: 0.5 by default, 0.1 for `deepseek` and 0.25 for `gemini`.
The Anthropic adapter records `cache_read_input_tokens` and
`cache_creation_input_tokens` from the response usage.

## Not implemented

- Token streaming for the OpenAI adapter family and for `codex_cli`.
- Forwarding `on_delta` from the dispatcher to `bedrock` and `vertex`, whose
  adapters already support it.
