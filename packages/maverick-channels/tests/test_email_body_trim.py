"""Email ingestion must not carry quoted history, signatures, or raw HTML
into the goal text.

Regression target: _extract_body returned the whole text/plain payload
verbatim — on a reply thread every message re-carried the entire quoted
history (`On ... wrote:` blocks) plus the signature, and a single-part
text/html message arrived as raw markup (tags/CSS are 3-10x the visible
text). The trim is per-message and lexical; an all-quote body falls back to
the original so a reply consisting only of quoted text is never dropped.
"""
from __future__ import annotations

from email.message import EmailMessage

from maverick_channels.email import EmailChannel, _strip_html, _trim_reply_noise


class TestTrimReplyNoise:
    def test_plain_message_untouched(self):
        body = "Please update the Q3 forecast.\nThanks!"
        assert _trim_reply_noise(body) == body

    def test_on_wrote_marker_cuts_quoted_history(self):
        body = (
            "Sounds good, ship it.\n\n"
            "On Mon, Jul 6, 2026 at 9:00 AM Alice <a@x.com> wrote:\n"
            "> huge quoted history\n> more history\n"
        )
        out = _trim_reply_noise(body)
        assert "ship it" in out
        assert "huge quoted history" not in out

    def test_original_message_divider_cuts(self):
        body = "New answer.\n-----Original Message-----\nFrom: bob\nold text"
        out = _trim_reply_noise(body)
        assert out == "New answer."

    def test_signature_block_dropped(self):
        body = "The report is attached.\n-- \nJane Doe\nVP, Example Corp\n555-1234"
        out = _trim_reply_noise(body)
        assert "report is attached" in out
        assert "VP, Example Corp" not in out

    def test_trailing_quote_run_dropped_interleaved_kept(self):
        body = (
            "> did you check the logs?\n"
            "Yes - clean.\n"
            "> and the deploy?\n"
            "Rolled back.\n"
            "> quoted tail line one\n"
            "> quoted tail line two\n"
        )
        out = _trim_reply_noise(body)
        assert "Yes - clean." in out and "Rolled back." in out
        assert "quoted tail line two" not in out
        # interleaved quote context above an answer is preserved
        assert "did you check the logs?" in out

    def test_all_quote_body_falls_back_to_original(self):
        body = "> only quoted content\n> nothing new"
        assert _trim_reply_noise(body) == body


class TestHtmlStripping:
    def test_strip_html_removes_markup_and_style(self):
        html = (
            "<html><head><style>body{color:red}</style></head>"
            "<body><p>Invoice <b>attached</b>.</p><script>x()</script></body></html>"
        )
        out = _strip_html(html)
        assert "Invoice" in out and "attached" in out
        assert "<" not in out and "color:red" not in out and "x()" not in out

    def test_strip_html_handles_unclosed_raw_text_tags_quickly(self):
        html = "<script>" * 5000 + "visible"
        out = _strip_html(html)
        assert out == ""

    def test_strip_html_keeps_similar_non_raw_text_tags(self):
        html = "<scripture>Keep this</scripture><stylex>and this</stylex>"
        out = _strip_html(html)
        assert "Keep this" in out and "and this" in out

    def test_singlepart_html_message_stripped(self):
        ch = EmailChannel.__new__(EmailChannel)
        msg = EmailMessage()
        msg.add_header("Content-Type", "text/html")
        msg.set_payload("<div><p>Approve the PO</p></div>", charset="utf-8")
        out = ch._extract_body(msg)
        assert "Approve the PO" in out
        assert "<div>" not in out

    def test_multipart_prefers_plain(self):
        ch = EmailChannel.__new__(EmailChannel)
        msg = EmailMessage()
        msg.set_content("plain wins")
        msg.add_alternative("<p>html loses</p>", subtype="html")
        assert "plain wins" in ch._extract_body(msg)

    def test_multipart_html_only_falls_back_to_stripped_html(self):
        ch = EmailChannel.__new__(EmailChannel)
        msg = EmailMessage()
        msg.add_alternative("<p>only html here</p>", subtype="html")
        out = ch._extract_body(msg)
        assert "only html here" in out and "<p>" not in out


class TestReviewRegressions:
    def test_bottom_posted_answer_survives_marker(self):
        # The real answer sits BELOW the attribution + quote block; the
        # marker cut must be skipped so the swarm sees the actual reply.
        body = (
            "Thanks for the summary.\n"
            "On Mon, Jul 6, 2026 at 9:00 AM Alice <a@x.com> wrote:\n"
            "> can you approve the Q3 budget?\n"
            "Approved - go ahead with vendor B.\n"
        )
        out = _trim_reply_noise(body)
        assert "Approved - go ahead with vendor B." in out

    def test_top_posted_reply_still_trimmed(self):
        body = (
            "Ship it.\n"
            "On Mon, Jul 6, 2026 at 9:00 AM Alice <a@x.com> wrote:\n"
            "> long quoted history\n> more\n"
        )
        out = _trim_reply_noise(body)
        assert out == "Ship it."

    def test_bare_dashdash_divider_is_not_a_signature(self):
        # RFC 3676 delimiter is dash-dash-SPACE; a bare -- is a common prose
        # divider and everything below it is real content.
        body = "Here's the plan:\n--\nStep 1\nStep 2"
        out = _trim_reply_noise(body)
        assert "Step 2" in out

    def test_outlook_divider_still_cuts_unquoted_copy(self):
        body = "New answer.\n-----Original Message-----\nFrom: bob\nold text"
        assert _trim_reply_noise(body) == "New answer."

    def test_long_attribution_line_matched(self):
        attribution = ("On Mon, Jul 6, 2026 at 9:00 AM " + "Alice Example "
                       "<alice.example@corp.example.com>, " * 4 + "wrote:")
        assert len(attribution) < 320
        body = "Done.\n" + attribution + "\n> quoted\n"
        assert _trim_reply_noise(body) == "Done."
