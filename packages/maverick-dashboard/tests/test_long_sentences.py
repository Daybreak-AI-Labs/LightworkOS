"""Copy people read stays in short sentences.

Every sentence on a dashboard page, and every sentence in the browser
scripts' copy, is at most 25 words. Long sentences were split, so this is a
ratchet at zero: a new one fails here with the file and the sentence.

Template text is read with Jinja expressions replaced by one word and Jinja
blocks treated as breaks (each branch is its own text). Script and style
blocks are skipped, and script strings that look like code are skipped too.
A sentence split by an inline tag (a link or bold text) is read as two parts,
so this undercounts slightly; it never counts code as copy.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
MAX_WORDS = 25
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z“\"(])")
_WORD = re.compile(r"[A-Za-z0-9’'-]+")
_BREAK = "␞"
_CODE = re.compile(r"[;{}=<>|&]|\$\{|\(\)")
_JS_STRING = re.compile(r"'((?:[^'\\\n]|\\.){20,})'|\"((?:[^\"\\\n]|\\.){20,})\"")


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def _template_text(raw: str):
    raw = re.sub(r"\{#.*?#\}", " ", raw, flags=re.DOTALL)
    raw = re.sub(r"<(script|style)\b[^>]*>", r"<\1>", raw)
    raw = re.sub(r"\{%.*?%\}", _BREAK, raw, flags=re.DOTALL)
    raw = re.sub(r"\{\{.*?\}\}", " X ", raw, flags=re.DOTALL)
    parser = _Text()
    parser.feed(raw)
    for part in parser.parts:
        for chunk in part.split(_BREAK):
            text = " ".join(chunk.split())
            if text:
                yield text


def _script_text(raw: str):
    for match in _JS_STRING.finditer(raw):
        text = match.group(1) or match.group(2)
        if not _CODE.search(text) and re.search(r"[a-z] [a-z]", text):
            yield text


def _copy():
    for path in sorted((PACKAGE / "templates").glob("*.html")):
        for text in _template_text(path.read_text(encoding="utf-8")):
            yield path.name, text
    for path in sorted((PACKAGE / "static").glob("lightwork-*.js")):
        for text in _script_text(path.read_text(encoding="utf-8")):
            yield path.name, text


def long_sentences() -> list[tuple[str, str]]:
    found = set()
    for name, text in _copy():
        for sentence in _SENTENCE.split(text):
            if len(_WORD.findall(sentence)) > MAX_WORDS:
                found.add((name, sentence))
    return sorted(found)


def test_the_counter_finds_a_long_sentence_and_ignores_code():
    long = "word " * 26
    page = f"<p>{long.strip()}.</p><script>var a = '{long}';</script>{{% if x %}}Short one.{{% endif %}}"
    assert [len(_WORD.findall(s)) for s in _template_text(page)] == [26, 2]
    assert list(_script_text("x = 'a; b {c} and more and more words here';")) == []


def test_no_sentence_on_a_page_is_longer_than_25_words():
    found = long_sentences()
    assert not found, "Split these into sentences of 25 words or fewer:\n" + "\n".join(
        f"{name}: {sentence}" for name, sentence in found)
