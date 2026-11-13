"""The codec token probe -- does the learned shorthand save model tokens?

`maverick codebook` reports how many *bytes* the learned shorthand saves. What
matters for cost is *model tokens*, and bytes and tokens do not move together: a
BPE tokenizer encodes common English phrases efficiently, while the codec
replaces them with rare sentinels (``⟦0⟧``) that may tokenize into *more* tokens
than the words they stand for. So a corpus that is 40% smaller in bytes can be
break-even -- or *worse* -- in tokens.

This module measures the truth directly: tokens of the plain English an agent
would emit today vs. tokens of the same messages once compressed. If the encoded
form isn't smaller in tokens, there is no token saving, and the codec is at best
a bytes/bandwidth/audit feature.

There are two regimes, and the probe reports both so the decision is honest:

    READ-DECODED  -- the model reads plain English (codec only shrinks what's
                     stored/shipped between agents). Token cost UNCHANGED; the
                     token delta here is always ~0. Value is bytes only.
    READ-CODED    -- the model reads the compressed form. Per-message tokens
                     change by ``token_savings_pct`` -- BUT the model must carry
                     the codebook in context to understand the codes, a one-time
                     ``codebook_token_cost`` that has to be amortized across
                     messages before the swap pays for itself.

Pure + dependency-free: the token counter is injected, so the core needs no
tokenizer at all. Adapters for tiktoken (a free local BPE proxy) and the
Anthropic counting API live alongside; tests use a trivial stub.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .emergent_protocol import Codebook, encode

# A token counter maps text -> token count. Injected so the core is tokenizer-agnostic.
Counter = Callable[[str], int]


@dataclass(frozen=True)
class TokenDelta:
    """Tokens (and bytes) of a corpus before vs after codec compression."""

    n_messages: int
    original_tokens: int       # plain English -- what the model emits today
    encoded_tokens: int        # compressed form -- if agents spoke the shorthand
    original_bytes: int
    encoded_bytes: int
    codebook_tokens: int       # one-time cost to carry the codebook in context

    @property
    def token_ratio(self) -> float:
        """encoded / original tokens. <1 saves tokens; >=1 means the codec costs more."""
        return (self.encoded_tokens / self.original_tokens) if self.original_tokens else 1.0

    @property
    def byte_ratio(self) -> float:
        return (self.encoded_bytes / self.original_bytes) if self.original_bytes else 1.0

    @property
    def token_savings_pct(self) -> float:
        """Percent of tokens saved per message (negative == the codec is *worse*)."""
        return (1.0 - self.token_ratio) * 100.0

    @property
    def byte_savings_pct(self) -> float:
        return (1.0 - self.byte_ratio) * 100.0

    @property
    def pays_off(self) -> bool:
        """The token thesis holds only if the compressed corpus is smaller in TOKENS."""
        return self.encoded_tokens < self.original_tokens

    @property
    def breakeven_messages(self) -> float:
        """READ-CODED regime: how many messages must reuse the codebook before the
        per-message token savings repay the one-time in-context codebook cost.
        ``inf`` when there is no per-message saving to repay it with."""
        saved_per_msg = (self.original_tokens - self.encoded_tokens) / self.n_messages \
            if self.n_messages else 0.0
        if saved_per_msg <= 0:
            return float("inf")
        return self.codebook_tokens / saved_per_msg

    def to_dict(self) -> dict:
        return {
            "n_messages": self.n_messages,
            "original_tokens": self.original_tokens,
            "encoded_tokens": self.encoded_tokens,
            "token_savings_pct": round(self.token_savings_pct, 2),
            "original_bytes": self.original_bytes,
            "encoded_bytes": self.encoded_bytes,
            "byte_savings_pct": round(self.byte_savings_pct, 2),
            "codebook_tokens": self.codebook_tokens,
            "breakeven_messages": self.breakeven_messages,
            "pays_off": self.pays_off,
        }


def codebook_token_cost(codebook: Codebook, *, count_tokens: Counter) -> int:
    """Tokens to express the codebook as an in-context preamble (the READ-CODED
    price of admission: the model can't act on codes it can't translate)."""
    if not codebook.forward:
        return 0
    preamble = "\n".join(f"{code}={phrase}" for phrase, code in codebook.forward.items())
    return count_tokens(preamble)


def measure(messages: Iterable[str], codebook: Codebook, *,
            count_tokens: Counter) -> TokenDelta:
    """Measure token + byte deltas of compressing ``messages`` with ``codebook``.

    For each message we count tokens of the plain English (what the model sees
    today) against tokens of its encoded form (sentinels in place of repeated
    phrases). The aggregate ``pays_off`` is the whole question: did frontier
    tokens actually fall, or did the rare sentinels cost more than they saved?
    """
    msgs = [str(m) for m in messages]
    orig_tok = enc_tok = orig_b = enc_b = 0
    for m in msgs:
        e = encode(m, codebook)
        orig_tok += count_tokens(m)
        enc_tok += count_tokens(e)
        # UTF-8 bytes, not characters: a sentinel is 3 characters and 7 bytes.
        orig_b += len(m.encode("utf-8", "replace"))
        enc_b += len(e.encode("utf-8", "replace"))
    return TokenDelta(
        n_messages=len(msgs),
        original_tokens=orig_tok, encoded_tokens=enc_tok,
        original_bytes=orig_b, encoded_bytes=enc_b,
        codebook_tokens=codebook_token_cost(codebook, count_tokens=count_tokens),
    )


def tiktoken_counter(encoding: str = "cl100k_base") -> Counter:
    """A free, local BPE token counter (OpenAI's tiktoken). Not Anthropic's exact
    vocabulary, but a faithful proxy for the question that matters here -- whether
    rare sentinel codes tokenize worse than the common English they replace
    (true of every BPE tokenizer trained on natural text). The default
    vocabulary and tokenizer dependency ship with Lightwork and
    requires neither a cache download nor a post-installation package change."""
    if encoding == "cl100k_base":
        from .local_token_counter import counter

        return counter()
    import tiktoken

    enc = tiktoken.get_encoding(encoding)
    return lambda text: len(enc.encode(text))


def anthropic_counting_available(model: str) -> bool:
    """Read direct-connection eligibility without constructing SDK clients."""
    from urllib.parse import urlsplit

    from . import config
    from .llm import LLM, _parse_spec, require_model_allowed

    provider, _ = _parse_spec(model)
    if provider != "anthropic" or config.config_source_errors(include_tenant=True):
        return False
    require_model_allowed(model)
    connection = LLM(model=model)._provider_client_config(provider)
    location = urlsplit(connection.base_url or "https://api.anthropic.com")
    return bool((connection.api_key or connection.environment_dict().get("ANTHROPIC_AUTH_TOKEN"))
                and location.scheme == "https" and location.hostname == "api.anthropic.com"
                and location.port in (None, 443) and location.path in ("", "/"))


def anthropic_counter(model: str, *, official_only: bool = False,
                      before_count: Callable[[], None] | None = None) -> Counter:
    """Use the configured Anthropic counting connection, not ambient SDK defaults.

    Counts are provider estimates, not a receipt for generated-message billing.
    A connection or workspace change refuses the remaining measurement. The
    optional dashboard guard also checks current learning and account authority.
    """
    from urllib.parse import urlsplit

    from . import config
    from .llm import LLM, MODEL_OPUS, MODEL_OPUS_FAST, _parse_spec, require_model_allowed

    provider, model_id = _parse_spec(model)
    if provider != "anthropic":
        raise ValueError("Provider counting requires an Anthropic model. Use the local estimate instead.")
    require_model_allowed(model)
    if config.config_source_errors(include_tenant=True):
        raise RuntimeError("The current AI connection settings could not be read. No messages were sent.")
    llm = LLM(model=model)
    adapter, original_route = llm._dispatch_client(provider)
    if official_only:
        location = urlsplit(str(adapter.client.base_url))
        if (location.scheme != "https" or location.hostname != "api.anthropic.com"
                or location.port not in (None, 443) or location.path not in ("", "/")):
            raise ValueError("This connection uses a gateway. Use the local estimate; its counting service is not qualified.")
    if model_id == MODEL_OPUS_FAST:
        model_id = MODEL_OPUS
    counts: OrderedDict[str, int] = OrderedDict()

    def _count(text: str) -> int:
        if before_count is not None:
            before_count()
        require_model_allowed(model)
        if config.config_source_errors(include_tenant=True):
            raise RuntimeError("The current AI connection settings could not be read. No further messages were sent.")
        current, route = llm._dispatch_client(provider)
        if route != original_route:
            raise RuntimeError("The AI connection or workspace changed. No further messages were sent; review a new measurement.")
        if text in counts:
            counts.move_to_end(text)
            return counts[text]
        response = current.client.messages.count_tokens(
            model=model_id, messages=[{"role": "user", "content": text or " "}])
        value = response.input_tokens
        if type(value) is not int or value < 0:
            raise ValueError("The provider did not return a valid token count.")
        if len(text) <= 16000:
            counts[text] = value
            if len(counts) > 256:
                counts.popitem(last=False)
        return value

    return _count


def resolve_counter(*, encoding: str = "cl100k_base", model: str | None = None,
                    official_only: bool = False,
                    before_count: Callable[[], None] | None = None) -> Counter:
    """Pick a token counter: the Anthropic API when a ``model`` is given (exact),
    else the local tiktoken proxy. Raises a helpful error if neither is available."""
    if model:
        return anthropic_counter(model, official_only=official_only, before_count=before_count)
    try:
        return tiktoken_counter(encoding)
    except Exception as exc:  # pragma: no cover -- environment-dependent
        raise RuntimeError(
            "no token counter available: `pip install tiktoken` for a free local "
            "proxy, or pass a --model (with ANTHROPIC_API_KEY set) for the exact count"
        ) from exc


__all__ = [
    "TokenDelta", "Counter", "measure", "codebook_token_cost",
    "tiktoken_counter", "anthropic_counter", "anthropic_counting_available", "resolve_counter",
]
