"""Channel rich-formatting helpers (Slack mrkdwn + Discord chunking).

Pure functions -- no platform SDK needed.
"""
from __future__ import annotations

from maverick_channels.formatting import (
    DISCORD_LIMIT,
    split_for_discord,
    to_slack_mrkdwn,
)


def test_slack_bold_and_links_and_headings():
    assert to_slack_mrkdwn("**bold**") == "*bold*"
    assert to_slack_mrkdwn("__also bold__") == "*also bold*"
    assert to_slack_mrkdwn("[docs](https://x.io/y)") == "<https://x.io/y|docs>"
    assert to_slack_mrkdwn("## Heading") == "*Heading*"


def test_slack_link_conversion_handles_malformed_many_open_brackets():
    text = "[" * 20_000 + "(https://example.com/path)"
    assert to_slack_mrkdwn(text) == text

def test_slack_preserves_code_fences():
    src = "see **this**\n```\nx = a ** b  # not bold\n```\nand **that**"
    out = to_slack_mrkdwn(src)
    # Bold converted outside the fence...
    assert "see *this*" in out
    assert "and *that*" in out
    # ...but the code body (including the `**`) is untouched.
    assert "x = a ** b  # not bold" in out


def test_slack_empty_passthrough():
    assert to_slack_mrkdwn("") == ""


def test_slack_escapes_broadcast_mentions():
    # Literal <!channel>/<!here>/<!everyone>/<@U..> in agent text must be
    # neutralised so a prompt-injected reply cannot mass-ping the channel.
    assert to_slack_mrkdwn("<!channel> meeting now") == "&lt;!channel&gt; meeting now"
    assert to_slack_mrkdwn("<!here> ping") == "&lt;!here&gt; ping"
    assert to_slack_mrkdwn("<!everyone> alert") == "&lt;!everyone&gt; alert"
    assert to_slack_mrkdwn("<@U999> escalate") == "&lt;@U999&gt; escalate"


def test_slack_escapes_reserved_chars():
    assert to_slack_mrkdwn("A & B < C > D") == "A &amp; B &lt; C &gt; D"


def test_slack_escapes_injected_link_syntax():
    # A literal <url|label> in user text must not become a live Slack link.
    assert (
        to_slack_mrkdwn("<https://evil.test|click>")
        == "&lt;https://evil.test|click&gt;"
    )


def test_slack_real_link_still_renders():
    # The links this function itself emits stay live, and a query-string
    # ampersand inside the URL is escaped (valid for Slack) rather than left raw.
    assert to_slack_mrkdwn("[docs](https://x.io/y)") == "<https://x.io/y|docs>"
    assert (
        to_slack_mrkdwn("[q](https://x.io/y?a=1&b=2)")
        == "<https://x.io/y?a=1&amp;b=2|q>"
    )


def test_slack_escapes_reserved_chars_even_inside_code_fences():
    # Control chars (& < >) are escaped across the ENTIRE reply, including
    # inside fences -- Slack honours these escapes in code, and escaping must
    # not depend on fence balance (see odd-fence regression below). Structural
    # rewrites (bold) still skip the code body.
    src = "before <!channel>\n```\n<not a ping> & x\n```\nafter <@U1>"
    out = to_slack_mrkdwn(src)
    assert "before &lt;!channel&gt;" in out
    assert "after &lt;@U1&gt;" in out
    assert "&lt;not a ping&gt; &amp; x" in out


def test_slack_escapes_broadcast_after_unbalanced_code_fence():
    # An odd number of ``` fences (e.g. an opened-but-unclosed code block, very
    # common in real replies and trivially prompt-injectable) must NOT leave the
    # trailing segment unescaped. Regression: the old split-on-fence logic only
    # escaped even-indexed segments, so everything after the last fence reached
    # Slack live and re-enabled <!channel>/<@U..> broadcasts.
    src = "Here is the code:\n```python\nprint(1)\n... <!channel> please respond"
    out = to_slack_mrkdwn(src)
    assert "<!channel>" not in out
    assert "&lt;!channel&gt;" in out

    # Same for an injected live-link span after a stray fence.
    out2 = to_slack_mrkdwn("```\n<https://evil.test|click>")
    assert "<https://evil.test|click>" not in out2
    assert "&lt;https://evil.test|click&gt;" in out2


def test_discord_short_message_single_chunk():
    assert split_for_discord("hello") == ["hello"]
    assert split_for_discord("") == [""]


def test_discord_splits_long_message_under_limit():
    text = "\n".join(f"line {i}" for i in range(1000))  # well over 2000 chars
    chunks = split_for_discord(text)
    assert len(chunks) > 1
    assert all(len(c) <= DISCORD_LIMIT for c in chunks)
    # No content lost.
    assert "".join(chunks) == text


def test_discord_hard_splits_a_single_oversized_line():
    line = "x" * (DISCORD_LIMIT * 2 + 5)
    chunks = split_for_discord(line)
    assert all(len(c) <= DISCORD_LIMIT for c in chunks)
    assert "".join(chunks) == line
