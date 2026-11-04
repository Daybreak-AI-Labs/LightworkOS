"""Offline BPE estimates using the reviewed, packaged cl100k_base vocabulary.

This counts ordinary customer text, including literal special-token markers.
It neither sends that text anywhere nor uses tiktoken's downloading registry.
The result is a local estimate, not a provider's billable token count.
Encoding metadata is adapted from OpenAI tiktoken under its MIT license;
the original notice and vocabulary provenance are packaged beside the data.
"""
from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from functools import lru_cache
from importlib.resources import files

_VOCABULARY_SHA256 = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"  # pragma: allowlist secret -- public digest of the bundled vocabulary
_PATTERN = (
    r"'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+"
    r"| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|\s*[\r\n]|\s+(?!\S)|\s"
)


@lru_cache(maxsize=1)
def _encoding():
    from tiktoken import Encoding

    resource = files("maverick").joinpath("data", "tokenizer", "cl100k_base.tiktoken")
    with resource.open("rb") as source:
        vocabulary = source.read(2_000_001)
    if len(vocabulary) > 2_000_000 or hashlib.sha256(vocabulary).hexdigest() != _VOCABULARY_SHA256:
        raise RuntimeError("The packaged local token counter could not be verified.")
    ranks = {}
    for line in vocabulary.splitlines():
        token, rank = line.split()
        ranks[base64.b64decode(token, validate=True)] = int(rank)
    return Encoding(
        name="cl100k_base", pat_str=_PATTERN, mergeable_ranks=ranks,
        special_tokens={
            "<|endoftext|>": 100257, "<|fim_prefix|>": 100258,
            "<|fim_middle|>": 100259, "<|fim_suffix|>": 100260,
            "<|endofprompt|>": 100276,
        },
    )


def count_tokens(text: str) -> int:
    """Estimate tokens without interpreting reserved-looking text as commands."""
    return len(_encoding().encode_ordinary(text))


def counter() -> Callable[[str], int]:
    """Verify the packaged vocabulary before admitting a local measurement."""
    _encoding()
    return count_tokens
