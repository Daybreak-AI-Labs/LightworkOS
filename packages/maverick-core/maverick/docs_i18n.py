"""Docs machine-translation pipeline.

The human-translated languages live in ``docs/i18n/<lang>/`` (es, ja, de,
fr, pt-BR, ko, ru, it, hi — see ``docs/i18n/README.md``). This module is
the pipeline for the *tail*: machine-translate a doc into additional
languages with the operator's configured model, under hard quality gates —
the output is only ever written when it verifiably preserves the document's
structure and the protected glossary. Running it needs an LLM key, so the
translation run itself is an operator act; ``--check`` (staleness report)
is fully offline.

Mechanics:

* a doc splits into preserve/translate segments — fenced code blocks are
  preserved byte-identical, prose is translated per segment;
* the glossary (product names, CLI verbs, env vars) must survive
  translation untouched — violations fail the gate, nothing is written;
* every output carries a header recording the source file + content hash,
  so :func:`status` can report which translations went stale when the
  English source moved;
* the model resolves by role (``translator``) via the user's config —
  nothing here names a model.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

# Terms that must come through translation byte-identical. Deliberately
# conservative: identifiers and proper nouns only, never common words.
GLOSSARY: tuple[str, ...] = (
    "Maverick", "Lightwork", "maverick", "MAVERICK_", "config.toml", "pip install",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
)

_HEADER_RX = re.compile(
    r"<!--\s*source:\s*(?P<src>\S+)\s+sha256:(?P<digest>[0-9a-f]{64})\s+"
    r"machine-translated\s*-->")

_FENCE_RX = re.compile(r"^(```|~~~)")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def split_segments(text: str) -> list[tuple[str, str]]:
    """Split markdown into ``[("keep"|"translate", chunk)]``.

    Fenced code blocks (including their fence lines) are ``keep``; runs of
    everything else are ``translate``. Chunks concatenate back to the
    original text exactly.
    """
    segments: list[tuple[str, str]] = []
    buf: list[str] = []
    mode = "translate"

    def flush() -> None:
        if buf:
            segments.append((mode, "".join(buf)))
            buf.clear()

    for line in text.splitlines(keepends=True):
        if _FENCE_RX.match(line):
            if mode == "translate":
                flush()
                mode = "keep"
                buf.append(line)
            else:
                buf.append(line)
                flush()
                mode = "translate"
        else:
            buf.append(line)
    flush()
    return segments


def fence_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if _FENCE_RX.match(line))


def verify_translation(source: str, translated: str,
                       glossary: tuple[str, ...] = GLOSSARY) -> list[str]:
    """The quality gate: structural + glossary invariants. Returns the list
    of violations (empty = pass). Nothing is written unless this passes."""
    problems: list[str] = []
    if not translated.strip():
        problems.append("empty translation")
        return problems
    if fence_count(translated) != fence_count(source):
        problems.append(
            f"code-fence count changed: {fence_count(source)} -> "
            f"{fence_count(translated)}")
    for term in glossary:
        if source.count(term) > translated.count(term):
            problems.append(f"glossary term lost: {term!r}")
    src_heads = sum(1 for line in source.splitlines() if line.startswith("#"))
    out_heads = sum(1 for line in translated.splitlines() if line.startswith("#"))
    if src_heads != out_heads:
        problems.append(f"heading count changed: {src_heads} -> {out_heads}")
    return problems


_PROMPT = (
    "Translate this technical documentation segment into {lang}. "
    "Native-quality prose using the language's standard software-docs "
    "register. NEVER translate: inline code, shell commands, file paths, "
    "environment variables, configuration keys, URLs, or product names. "
    "Preserve the markdown structure exactly. Reply with ONLY the "
    "translated segment, no commentary."
)


def translate_document(text: str, lang: str, llm) -> str:
    """Translate one markdown document via the injected ``llm`` seam.

    ``llm`` is an ``LLM``-shaped object (``complete(system, messages,
    max_tokens, model)``); the model resolves from the user's ``translator``
    role. Raises ``ValueError`` when the result fails :func:`verify_translation`
    — a failed gate must never be written out as if it were a translation.
    """
    from .llm import model_for_role
    out: list[str] = []
    for mode, chunk in split_segments(text):
        if mode == "keep" or not chunk.strip():
            out.append(chunk)
            continue
        resp = llm.complete(
            system=_PROMPT.format(lang=lang),
            messages=[{"role": "user", "content": chunk}],
            max_tokens=8192,
            model=model_for_role("translator"),
        )
        out.append(getattr(resp, "text", "") or "")
    translated = "".join(out)
    problems = verify_translation(text, translated)
    if problems:
        raise ValueError("translation failed the quality gate: "
                         + "; ".join(problems))
    return translated


def _resolve_under(base: Path, rel: str) -> Path:
    """Resolve a caller-supplied relative path under ``base``."""
    rel_path = Path(rel)
    if rel_path.is_absolute():
        raise ValueError(f"docs file must be relative to docs root: {rel!r}")
    base_resolved = base.resolve()
    candidate = (base_resolved / rel_path).resolve(strict=False)
    if not candidate.is_relative_to(base_resolved):
        raise ValueError(f"docs file escapes docs root: {rel!r}")
    return candidate


def _lang_dir(i18n_root: Path, lang: str) -> Path:
    """Return the destination directory for one safe language code."""
    lang_path = Path(lang)
    if (lang_path.is_absolute() or lang_path.name != lang
            or lang in {".", ".."}):
        raise ValueError(f"language code must be a single directory name: {lang!r}")
    i18n_resolved = i18n_root.resolve(strict=False)
    candidate = (i18n_resolved / lang_path).resolve(strict=False)
    if not candidate.is_relative_to(i18n_resolved):
        raise ValueError(f"language code escapes docs i18n root: {lang!r}")
    return candidate


def header_for(source_rel: str, source_text: str) -> str:
    return (f"<!-- source: {source_rel} sha256:{_sha256(source_text)} "
            f"machine-translated -->\n\n")


@dataclass(frozen=True)
class DocStatus:
    lang: str
    file: str
    state: str  # "current" | "stale" | "missing" | "unverified"


def status(docs_root: Path, langs: list[str],
           files: list[str]) -> list[DocStatus]:
    """Offline staleness report for machine-translated docs.

    Human translations (no machine-translated header) report
    ``unverified`` — their staleness is tracked by the git-commit header
    convention in docs/i18n/README.md, not by this pipeline.
    """
    out: list[DocStatus] = []
    i18n_root = docs_root / "i18n"
    for lang in langs:
        lang_root = _lang_dir(i18n_root, lang)
        for rel in files:
            src = _resolve_under(docs_root, rel)
            # Preserve the source subdirectory structure. Using only the
            # basename collapsed two docs with the same filename in different
            # subdirs onto one destination (one silently overwrote / shadowed
            # the other in status + run).
            dst = _resolve_under(lang_root, rel)
            if not dst.exists():
                out.append(DocStatus(lang, rel, "missing"))
                continue
            m = _HEADER_RX.search(dst.read_text(encoding="utf-8"))
            if not m:
                out.append(DocStatus(lang, rel, "unverified"))
                continue
            current = src.exists() and _sha256(
                src.read_text(encoding="utf-8")) == m.group("digest")
            out.append(DocStatus(lang, rel, "current" if current else "stale"))
    return out


def run(docs_root: Path, langs: list[str], files: list[str], llm) -> list[Path]:
    """Translate ``files`` into each lang dir; returns written paths.
    Existing *current* machine translations are skipped; human translations
    (``unverified``) are never overwritten."""
    written: list[Path] = []
    states = {(s.lang, s.file): s.state
              for s in status(docs_root, langs, files)}
    i18n_root = docs_root / "i18n"
    for lang in langs:
        lang_root = _lang_dir(i18n_root, lang)
        for rel in files:
            if states[(lang, rel)] in ("current", "unverified"):
                continue
            src = _resolve_under(docs_root, rel)
            source = src.read_text(encoding="utf-8")
            translated = translate_document(source, lang, llm)
            # Preserve the source subdirectory structure. Using only the
            # basename collapsed two docs with the same filename in different
            # subdirs onto one destination (one silently overwrote / shadowed
            # the other in status + run).
            dst = _resolve_under(lang_root, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(header_for(rel, source) + translated,
                           encoding="utf-8")
            written.append(dst)
    return written


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m maverick.docs_i18n",
        description="Machine-translate docs into additional languages "
                    "(needs a configured LLM provider; --check is offline).")
    parser.add_argument("--docs-root", default="docs")
    parser.add_argument("--langs", required=True,
                        help="comma-separated language codes, e.g. ar,tr,nl")
    parser.add_argument("--files", default="getting-started.md",
                        help="comma-separated paths relative to --docs-root")
    parser.add_argument("--check", action="store_true",
                        help="report staleness only; no model calls")
    args = parser.parse_args(argv)
    root = Path(args.docs_root)
    langs = [lang.strip() for lang in args.langs.split(",") if lang.strip()]
    files = [f.strip() for f in args.files.split(",") if f.strip()]
    if args.check:
        for s in status(root, langs, files):
            print(f"{s.lang}\t{s.file}\t{s.state}")
        return 0
    from .llm import LLM
    written = run(root, langs, files, LLM())
    for path in written:
        print(f"wrote {path}")
    if not written:
        print("nothing to do (all current or human-maintained)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
