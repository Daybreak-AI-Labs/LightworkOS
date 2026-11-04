"""Multi-modal compaction (v5): heavy media blocks become compact text stubs."""
from __future__ import annotations

import base64
import json
import struct

from maverick.compaction.multimodal import (
    _dimensions,
    _human_size,
    compact_media,
    stub_for_block,
)


def _png_bytes(w: int = 800, h: int = 600, pad: int = 200_000) -> bytes:
    head = (
        b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR"
        + struct.pack(">II", w, h)
    )
    return head + b"\x00" * pad


def _image_block(data: bytes, media_type: str = "image/png") -> dict:
    return {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": media_type,
            "data": base64.b64encode(data).decode("ascii"),
        },
    }


def _msgs_with_media(block: dict) -> list[dict]:
    return [
        {"role": "user", "content": "GOAL: review the screenshot."},
        {"role": "user", "content": [
            block,
            {"type": "text", "text": "here is the screenshot"},
        ]},
        {"role": "assistant", "content": "looked at it"},
        {"role": "user", "content": "recent question"},
        {"role": "assistant", "content": "recent answer"},
    ]


class TestSniffers:
    def test_png_dimensions(self):
        assert _dimensions(_png_bytes(1280, 800, pad=16)) == (1280, 800)

    def test_gif_dimensions(self):
        assert _dimensions(b"GIF89a" + struct.pack("<HH", 320, 200) + b"\x00" * 8) == (320, 200)

    def test_jpeg_dimensions(self):
        jpg = (
            b"\xff\xd8"                                   # SOI
            + b"\xff\xe0\x00\x10" + b"J" * 14             # APP0, length 16
            + b"\xff\xc0\x00\x11\x08"                     # SOF0, precision 8
            + struct.pack(">HH", 480, 640)                # height, width
            + b"\x03" + b"\x00" * 9
        )
        assert _dimensions(jpg) == (640, 480)

    def test_unknown_bytes_none(self):
        assert _dimensions(b"plainly not an image") is None

    def test_human_size(self):
        assert _human_size(500) == "500B"
        assert _human_size(2048) == "2.0KB"
        assert _human_size(1_300_000) == "1.2MB"


class TestStub:
    def test_deterministic_stub_has_size_type_dimensions(self):
        stub = stub_for_block(_image_block(_png_bytes(800, 600)))
        assert stub["type"] == "text"
        assert stub["text"].startswith("[image: ")
        assert "image/png" in stub["text"]
        assert "800x600" in stub["text"]
        assert "195.3KB" in stub["text"]
        assert "removed during compaction" in stub["text"]

    def test_llm_description_via_seam(self, monkeypatch, fake_llm, make_llm_response):
        monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_VISION", "testprov:tiny-vision")
        fake_llm.scripted = [make_llm_response("login page with an error toast")]
        block = _image_block(_png_bytes())
        stub = stub_for_block(block, llm=fake_llm)
        assert "described: login page with an error toast" in stub["text"]
        # The original media block went through the injected seam, with the
        # configured vision role model -- nothing hardcoded.
        assert fake_llm.calls[0]["messages"][0]["content"][0] is block
        assert fake_llm.calls[0]["model"] == "testprov:tiny-vision"

    def test_llm_failure_degrades_to_deterministic_stub(self):
        class Boom:
            def complete(self, *a, **kw):
                raise RuntimeError("vision down")

        stub = stub_for_block(_image_block(_png_bytes(800, 600)), llm=Boom())
        assert "described:" not in stub["text"]
        assert "800x600" in stub["text"]

    def test_audio_block_stubbed_with_bytes(self):
        block = {
            "type": "audio",
            "source": {
                "type": "base64",
                "media_type": "audio/wav",
                "data": base64.b64encode(b"RIFF" + b"\x00" * 4092).decode("ascii"),
            },
        }
        stub = stub_for_block(block)
        assert stub["text"].startswith("[audio: ")
        assert "audio/wav" in stub["text"]
        assert "4.0KB" in stub["text"]


class TestCompactMedia:
    def test_short_list_passes_through(self):
        msgs = [{"role": "user", "content": [_image_block(_png_bytes())]}]
        assert compact_media(msgs) == msgs

    def test_old_media_stubbed_text_and_boundaries_preserved(self):
        msgs = _msgs_with_media(_image_block(_png_bytes()))
        out = compact_media(msgs, keep_recent=2)
        assert out[0] == msgs[0]
        assert out[-2:] == msgs[-2:]
        assert len(out) == len(msgs)
        blocks = out[1]["content"]
        assert blocks[0]["type"] == "text" and "[image:" in blocks[0]["text"]
        assert blocks[1] == {"type": "text", "text": "here is the screenshot"}

    def test_recent_and_first_media_survive(self):
        img = _image_block(_png_bytes())
        msgs = [
            {"role": "user", "content": [img, {"type": "text", "text": "brief"}]},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "old turn"},
            {"role": "assistant", "content": "ok2"},
            {"role": "user", "content": [img]},  # inside keep_recent window
        ]
        out = compact_media(msgs, keep_recent=2)
        assert out[0]["content"][0] is img
        assert out[-1]["content"][0] is img

    def test_media_inside_tool_result_stubbed(self):
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": "t1",
                "content": [
                    _image_block(_png_bytes()),
                    {"type": "text", "text": "screenshot taken"},
                ],
            }]},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "recent"},
            {"role": "assistant", "content": "done"},
        ]
        out = compact_media(msgs, keep_recent=2)
        inner = out[1]["content"][0]["content"]
        assert inner[0]["type"] == "text" and "[image:" in inner[0]["text"]
        assert inner[1] == {"type": "text", "text": "screenshot taken"}

    def test_savings_measurable_and_media_fact_retained(self):
        msgs = _msgs_with_media(_image_block(_png_bytes()))
        out = compact_media(msgs, keep_recent=2)
        before = len(json.dumps(msgs))
        after = len(json.dumps(out))
        assert after < before / 50  # the base64 payload dominates; stub is tiny
        assert "[image:" in json.dumps(out)  # but the fact media existed survives

    def test_input_not_mutated(self):
        msgs = _msgs_with_media(_image_block(_png_bytes()))
        snapshot = json.dumps(msgs)
        compact_media(msgs, keep_recent=2)
        assert json.dumps(msgs) == snapshot
