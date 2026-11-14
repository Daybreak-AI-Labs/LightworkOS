"""Adversarial-prompt corpus release.

The red-team corpus (``redteam_corpus.jsonl``) gates CI; *releasing* it means
turning the working file into a **versioned, validated, documented artifact**
a third party can consume — with the integrity and honesty properties a
published safety corpus needs:

* :func:`validate` — every row well-formed (id unique, ``expected`` in
  {block, allow}, category present, text non-empty), so a malformed row can't
  ship.
* :func:`build_release` — the release manifest: corpus version (content-hash
  derived, so it changes iff the corpus does), row/category/expectation
  counts, a SHA-256 over the canonical content for integrity pinning, license
  + intended-use statement, and an explicit **provenance note** (hand-authored
  test fixtures; no user data — verified by running the secret/PII detectors
  over every row when the kernel is installed, refusing the release on a hit).
* ``python -m maverick_shield.corpus_release`` writes
  ``corpus-release/<version>/`` (corpus + MANIFEST.json + README.md).

Offline and deterministic.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

CORPUS_PATH = Path(__file__).with_name("redteam_corpus.jsonl")
LICENSE = "Apache-2.0"
INTENDED_USE = (
    "Evaluating prompt-injection / jailbreak / exfiltration detectors. "
    "NOT a training set for attack generation."
)


def load_rows(path: Path = CORPUS_PATH) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


def validate(rows: list[dict]) -> list[str]:
    """Release lint over corpus rows. [] == releasable."""
    problems: list[str] = []
    seen_ids: set[str] = set()
    for i, row in enumerate(rows):
        rid = row.get("id")
        if not rid:
            problems.append(f"row {i}: missing id")
        elif rid in seen_ids:
            problems.append(f"row {i}: duplicate id {rid!r}")
        else:
            seen_ids.add(rid)
        if row.get("expected") not in ("block", "allow"):
            problems.append(f"row {i}: expected must be block|allow")
        if not (row.get("text") or "").strip():
            problems.append(f"row {i}: empty text")
        if not (row.get("category") or "").strip():
            problems.append(f"row {i}: missing category")
    return problems


# PII kinds that are TECHNICAL INDICATORS intrinsic to attack fixtures (a
# reverse-shell sample needs an IP); identity PII (email/phone/ssn/...) and
# anything secret-shaped still refuse the release.
_ALLOWED_INDICATOR_KINDS = {"ipv4", "ipv6"}


def _scan_available() -> bool:
    try:
        from maverick.safety import pii_detector, secret_detector  # noqa: F401
    except ImportError:
        return False
    return True


def provenance_scan(rows: list[dict]) -> list[str]:
    """No real secrets or identity PII may ship in a released corpus.

    Uses the kernel's detectors when installed; secret-shaped content and
    identity-PII refuse the release. Technical indicators intrinsic to attack
    samples (IP addresses in a reverse-shell fixture) are allowed and
    disclosed in the manifest's provenance note. Skipped when the kernel
    isn't installed (shield-only install)."""
    try:
        from maverick.safety import pii_detector, secret_detector
    except ImportError:
        return []  # shield-only install: scan unavailable, noted in manifest
    hits: list[str] = []
    for row in rows:
        text = row.get("text") or ""
        for m in secret_detector.scan(text):
            hits.append(f"{row.get('id')}: secret-shaped content ({m.name})")
        for m in pii_detector.scan(text):
            if m.kind in _ALLOWED_INDICATOR_KINDS:
                continue
            hits.append(f"{row.get('id')}: PII-shaped content ({m.kind})")
    return hits


def _content_hash(rows: list[dict]) -> str:
    canon = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def build_release(rows: list[dict] | None = None) -> dict:
    """The release manifest (raises on a non-releasable corpus)."""
    rows = rows if rows is not None else load_rows()
    problems = validate(rows)
    if problems:
        raise ValueError("corpus not releasable: " + "; ".join(problems[:5]))
    hits = provenance_scan(rows)
    if hits:
        raise ValueError("corpus contains secret/PII-shaped rows: "
                         + "; ".join(hits[:5]))
    digest = _content_hash(rows)
    categories: dict[str, int] = {}
    expected: dict[str, int] = {}
    for row in rows:
        categories[row["category"]] = categories.get(row["category"], 0) + 1
        expected[row["expected"]] = expected.get(row["expected"], 0) + 1
    return {
        "name": "maverick-adversarial-prompt-corpus",
        "version": f"1.0.0+{digest[:12]}",
        "rows": len(rows),
        "categories": dict(sorted(categories.items())),
        "expected": dict(sorted(expected.items())),
        "sha256": digest,
        "license": LICENSE,
        "intended_use": INTENDED_USE,
        "provenance": (
            "hand-authored test fixtures; no user data; secret/PII-scanned at "
            "release (technical indicators like fixture IPs allowed and "
            "intrinsic to attack samples)"
            if _scan_available() else
            "hand-authored test fixtures; no user data; NOT secret/PII-scanned "
            "(the kernel detectors were not installed at release)"),
    }


def write_release(out_dir: Path, rows: list[dict] | None = None) -> Path:
    rows = rows if rows is not None else load_rows()
    manifest = build_release(rows)
    dest = Path(out_dir) / manifest["version"]
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "corpus.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8")
    (dest / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (dest / "README.md").write_text(
        f"# {manifest['name']} {manifest['version']}\n\n"
        f"{manifest['rows']} labeled adversarial/benign prompts for evaluating "
        "prompt-injection, jailbreak, and exfiltration detectors.\n\n"
        f"- integrity: sha256 `{manifest['sha256']}` over the canonical rows\n"
        f"- license: {manifest['license']}\n"
        f"- intended use: {manifest['intended_use']}\n"
        f"- provenance: {manifest['provenance']}\n\n"
        "Row shape: `{id, text, expected: block|allow, category}`. The "
        "`allow` rows are the false-positive floor — a detector must NOT "
        "flag them.\n", encoding="utf-8")
    return dest


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick_shield.corpus_release")
    p.add_argument("--out", default="corpus-release")
    args = p.parse_args(argv)
    try:
        dest = write_release(Path(args.out))
    except ValueError as e:
        print(f"REFUSED: {e}")
        return 1
    print(f"released: {dest}")
    return 0


__all__ = ["load_rows", "validate", "provenance_scan", "build_release",
           "write_release", "CORPUS_PATH"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
