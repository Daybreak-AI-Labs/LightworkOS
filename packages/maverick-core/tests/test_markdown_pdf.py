"""Markdown to a printable PDF with no external program (maverick.markdown_pdf)."""
from __future__ import annotations

import re
import shutil
import subprocess
import zlib

import pytest
from maverick.markdown_pdf import MAX_PAGES, UnwritablePdf, _words, pdf_from_markdown

_CHECKLIST = """# Weekly Cafe Cleaning Checklist

Keep it **posted by the sink**. Costs (about $40) are shared.

## Daily
- [ ] Wipe down counters & tables
- [x] Empty trash
  - [ ] Move the bins first

## Weekly
1. Descale the espresso machine

| Area | Task |
|---|---|
| Kitchen | Degrease hood filters |

```
1 tbsp bleach per gallon
```

Notes: café “quotes” and a ✓.
"""


def _streams(pdf: bytes) -> str:
    return "\n".join(zlib.decompress(m.group(1)).decode("latin-1")
                     for m in re.finditer(rb"stream\n(.*?)\nendstream", pdf, re.DOTALL))


def test_the_file_is_a_valid_pdf_with_a_correct_cross_reference_table():
    pdf = pdf_from_markdown(_CHECKLIST)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    start = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n", 1)[0])
    assert pdf[start:start + 4] == b"xref"
    count = int(pdf[start:].split(b"\n")[1].split()[1])
    offsets = [int(line[:10]) for line in pdf[start:].split(b"\n")[3:2 + count]]
    for number, offset in enumerate(offsets, 1):
        assert pdf[offset:].startswith(b"%d 0 obj" % number)
    assert b"/Title (Weekly Cafe Cleaning Checklist)" in pdf


def test_text_layout_boxes_and_encoding():
    text = _streams(pdf_from_markdown(_CHECKLIST))
    for word in ("(Wipe)", "(Descale)", "(Degrease)", "(Kitchen)", "(Page 1 of 1)"):
        assert word in text, word
    assert text.count(" re S") == 3  # three checklist boxes, one ticked
    assert "/F2" in text and "/F3" in text  # bold and code fonts are used
    assert "(caf\\351)" in text and "(\\223quotes\\224)" in text  # Windows-1252, octal-escaped
    assert "\\(about" in text  # parentheses are escaped in PDF strings


def test_bold_punctuation_stays_attached():
    words = _words("keep it **posted by the sink**. Then (**bold**) end")
    assert [w for w, _ in words][6:11] == ["\x00.", "Then", "(", "\x00bold", "\x00)"]


def test_long_text_breaks_onto_more_pages_and_limits_hold():
    pdf = pdf_from_markdown("\n".join(f"- Line {n} of a long checklist" for n in range(200)))
    assert b"/Count 5" in pdf or b"/Count 6" in pdf
    with pytest.raises(UnwritablePdf):
        pdf_from_markdown("  \n")
    with pytest.raises(UnwritablePdf):
        pdf_from_markdown("\n".join(f"- line {n}" for n in range(MAX_PAGES * 60)))


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="poppler is not installed")
def test_poppler_reads_the_text_back(tmp_path):
    (tmp_path / "c.pdf").write_bytes(pdf_from_markdown(_CHECKLIST))
    text = subprocess.run(["pdftotext", "-layout", str(tmp_path / "c.pdf"), "-"], capture_output=True, text=True,
                          check=True).stdout
    assert "Keep it posted by the sink. Costs (about $40) are shared." in text
    assert "1. Descale the espresso machine" in text and "café “quotes”" in text


def test_a_column_sized_to_its_widest_word_keeps_that_word_whole():
    # Live: an invoice's "Hours" header broke into "Hour" and "s".
    text = _streams(pdf_from_markdown("| Description | Hours | Rate |\n|---|---|---|\n| Design work | 10 | $120 |\n"))
    assert "(Hours)" in text and "(Hour)" not in text


def test_a_short_column_beside_long_ones_keeps_its_words_whole():
    # Live: a POS comparison's first column was squeezed so thin that
    # "System", "Square" and "Clover" broke as "Sys"/"tem" and "Squ"/"are".
    long = "Square's pricing page says there are no monthly subscription costs on the free plan " * 2
    table = ("| System | Monthly software cost | Upfront hardware | Takeaway |\n|---|---|---|---|\n"
             f"| Square | $0/mo on Square Free, more on paid plans | About $49-$149 | {long} |\n"
             f"| Clover | Quote-based, varies by reseller | About $799 | {long} |\n")
    text = _streams(pdf_from_markdown(table))
    for word in ("(System)", "(Square)", "(Clover)"):
        assert word in text, word
    assert "(Sys)" not in text and "(Squ)" not in text


def test_escaped_punctuation_is_written_without_its_backslash():
    # Live: an answer wrote "\$8,400"; Markdown shows "$8,400", and the PDF
    # showed the backslash.
    streams = _streams(pdf_from_markdown("# \\$ Quote\n\nTotal: \\$8,400 at 7.5\\% \\*not bold\\*\n\n"
                                         "| Item | Cost |\n|---|---|\n| A | \\$5.00 |\n"))
    assert "$8,400" in streams and "7.5%" in streams and "*not" in streams and "$5.00" in streams
    assert "\\\\$" not in streams and "\\\\%" not in streams
