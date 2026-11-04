"""Constant-time equality for text that may come from outside the process.

``hmac.compare_digest`` raises ``TypeError`` for a ``str`` holding any
non-ASCII character. Where one side is a request field, a header, a chat
message or a file another user can edit, that turned a crafted value into a
crash (a 500 on the dashboard) instead of the refusal a wrong ASCII value gets.
"""

from __future__ import annotations

import hmac


def text_equals(supplied: str, expected: str) -> bool:
    """Compare two strings in constant time, whatever characters they hold.

    Compares the UTF-8 bytes; ``surrogatepass`` keeps a lone surrogate
    distinct from every real character instead of raising."""
    return hmac.compare_digest(supplied.encode("utf-8", "surrogatepass"),
                               expected.encode("utf-8", "surrogatepass"))
