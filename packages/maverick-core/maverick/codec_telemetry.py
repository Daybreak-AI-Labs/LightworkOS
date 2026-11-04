"""Live codec telemetry -- what the token-aware codec saves on REAL traffic.

The probe (``codec_probe``) measured the codec on a synthetic corpus. This records
the same deltas on the *actual* coordination stream as the swarm runs, so the
+27.9% from the bench can be confirmed (or corrected) against production. It is a
process-local, thread-safe accumulator: the blackboard hands it each rendered
coordination block and its compressed form; we tally bytes (always available) and
tokens (only when a real tokenizer has been registered, so core stays
dependency-free).

Pure measurement -- nothing here changes what an agent sees. OFF by default: the
blackboard only calls in when ``emergent_tokens.enabled()`` and a codebook exists.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

# Optional, process-wide token counter. None -> tokens are not measured (bytes
# still are). The operator registers one (e.g. tiktoken) where a tokenizer exists.
_counter: Callable[[str], int] | None = None
_counter_lock = threading.Lock()


def set_token_counter(counter: Callable[[str], int] | None) -> None:
    """Register (or clear) the tokenizer used for live token measurement."""
    global _counter
    with _counter_lock:
        _counter = counter


def _count(text: str) -> int | None:
    with _counter_lock:
        c = _counter
    if c is None:
        return None
    try:
        return c(text)
    except Exception:  # pragma: no cover -- a flaky tokenizer never blocks a post
        return None


@dataclass
class CodecStats:
    """Running totals of original vs compressed coordination renders."""

    n_blocks: int = 0
    original_bytes: int = 0
    encoded_bytes: int = 0
    original_tokens: int = 0     # only accrues while a token counter is registered
    encoded_tokens: int = 0
    token_blocks: int = 0        # blocks that contributed token measurements

    @property
    def byte_savings_pct(self) -> float:
        return (1.0 - self.encoded_bytes / self.original_bytes) * 100.0 \
            if self.original_bytes else 0.0

    @property
    def token_savings_pct(self) -> float:
        return (1.0 - self.encoded_tokens / self.original_tokens) * 100.0 \
            if self.original_tokens else 0.0

    def to_dict(self) -> dict:
        return {
            "n_blocks": self.n_blocks,
            "original_bytes": self.original_bytes,
            "encoded_bytes": self.encoded_bytes,
            "byte_savings_pct": round(self.byte_savings_pct, 2),
            "token_blocks": self.token_blocks,
            "original_tokens": self.original_tokens,
            "encoded_tokens": self.encoded_tokens,
            "token_savings_pct": round(self.token_savings_pct, 2),
            "tokens_measured": self.token_blocks > 0,
        }


_stats = CodecStats()
_stats_lock = threading.Lock()


def record(original: str, encoded: str) -> None:
    """Tally one rendered coordination block and its compressed form. Cheap: bytes
    are ``len``; tokens only when a counter is registered."""
    ot = _count(original)
    et = _count(encoded)
    with _stats_lock:
        _stats.n_blocks += 1
        _stats.original_bytes += len(original)
        _stats.encoded_bytes += len(encoded)
        if ot is not None and et is not None:
            _stats.original_tokens += ot
            _stats.encoded_tokens += et
            _stats.token_blocks += 1


def snapshot() -> CodecStats:
    with _stats_lock:
        return CodecStats(**vars(_stats))


def reset() -> None:
    global _stats
    with _stats_lock:
        _stats = CodecStats()


__all__ = ["CodecStats", "set_token_counter", "record", "snapshot", "reset"]
