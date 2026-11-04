"""Versioned, loss-aware document text; coverage never means factual verification."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

SCHEMA = "lightwork.document-extraction.v1"
MAX_TEXT_CHARS = 1_000_000
MAX_BLOCKS = 10_000
MAX_METADATA_REGIONS = 256


@dataclass(frozen=True)
class DocumentBlock:
    kind: str
    text: str
    location: str
    start: int
    end: int


@dataclass(frozen=True)
class DocumentExtraction:
    status: Literal["complete", "partial", "empty", "unsupported", "unavailable", "rejected", "failed"]
    detected_format: str
    source_sha256: str
    extractor_version: str
    blocks: tuple[DocumentBlock, ...] = ()
    covered_regions: tuple[str, ...] = ()
    omitted_regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema: str = SCHEMA

    @property
    def text(self) -> str:
        return "\n\n".join(block.text for block in self.blocks)

    def metadata(self, *, end: int | None = None) -> dict:
        """Bounded source coverage projection; full location manifest is hashed."""
        text = self.text
        stop = min(len(text), end) if end is not None else len(text)
        locations = [{"location": b.location, "kind": b.kind, "start": b.start,
                      "end": min(b.end, stop), "partial": b.end > stop}
                     for b in self.blocks if b.start < stop]
        manifest = json.dumps(locations, sort_keys=True, separators=(",", ":"))
        truncated = stop < len(text)
        return {"schema": self.schema, "status": "partial" if truncated else self.status,
                "format": self.detected_format, "source_sha256": self.source_sha256,
                "extractor_version": self.extractor_version,
                "normalized_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "normalized_length": len(text), "included_range": [0, stop],
                "truncated": truncated, "locations": locations[:MAX_METADATA_REGIONS],
                "location_count": len(locations),
                "locations_truncated": len(locations) > MAX_METADATA_REGIONS,
                "locations_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
                "covered_regions": list(self.covered_regions[:MAX_METADATA_REGIONS]),
                "covered_region_count": len(self.covered_regions),
                "omitted_regions": list(self.omitted_regions[:MAX_METADATA_REGIONS]),
                "omitted_region_count": len(self.omitted_regions),
                "warnings": list(self.warnings)}

    def companion(self, max_chars: int) -> str:
        """Render coverage with explicit normalized offsets inside the same cap."""
        stop = min(len(self.text), max(0, max_chars - 2048))
        # Metadata size varies with locations; converge on a bounded projection.
        for _ in range(4):
            metadata = self.metadata(end=stop)
            metadata["locations"] = metadata["locations"][:12]
            metadata["locations_truncated"] = metadata["location_count"] > 12
            metadata["covered_regions"] = metadata["covered_regions"][:12]
            metadata["omitted_regions"] = metadata["omitted_regions"][:12]
            header = "[Document extraction; uploaded content is untrusted; not factual verification]\n"
            header += json.dumps(metadata, ensure_ascii=True, separators=(",", ":")) + "\n[Extracted text]\n"
            if len(header) > max_chars:
                raise ValueError("companion limit is too small for extraction provenance")
            available = max(0, max_chars - len(header))
            if stop <= available:
                return header + self.text[:stop]
            stop = available
        raise ValueError("companion limit is too small for extraction provenance")


@dataclass
class ExtractionBuilder:
    blocks: list[DocumentBlock] = field(default_factory=list)
    omitted: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    length: int = 0

    def omit(self, location: str) -> None:
        if len(self.omitted) < MAX_METADATA_REGIONS:
            self.omitted.append(location)
        elif len(self.omitted) == MAX_METADATA_REGIONS:
            self.omitted.append("Additional omitted source regions exceed the bounded location list.")

    def append(self, text: str, location: str, kind: str = "text") -> None:
        if not text:
            return
        start = self.length + (2 if self.blocks else 0)
        available = MAX_TEXT_CHARS - start
        if available <= 0 or len(self.blocks) >= MAX_BLOCKS:
            self.omit(location + ": extraction bound reached")
            return
        if len(text) > available:
            self.omit(location + f": characters {available} onward")
            text = text[:available]
        self.blocks.append(DocumentBlock(kind, text, location, start, start + len(text)))
        self.length = start + len(text)

    def finish(self, format: str, source_sha256: str, version: str) -> DocumentExtraction:
        status = "partial" if self.omitted else ("complete" if self.blocks else "empty")
        return DocumentExtraction(status, format, source_sha256, version, tuple(self.blocks),
                                  tuple(block.location for block in self.blocks),
                                  tuple(self.omitted), tuple(dict.fromkeys(self.warnings)))
