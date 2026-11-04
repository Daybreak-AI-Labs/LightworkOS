"""Attachments of all kinds: audio/video/Office mimes, document-ZIP sniffing,
deployment mime knobs, and PDF document-block embedding."""
from __future__ import annotations

import io
import zipfile

import pytest
from maverick.attachments import (
    AttachmentRejected,
    content_blocks_for_goal,
    store,
)
from maverick.world_model import WorldModel


def _ooxml_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def _odf_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr("content.xml", "<office:document/>")
    return buf.getvalue()


DOCX_MIME = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)


def _clear_env(monkeypatch):
    for var in ("MAVERICK_ATTACH_EXTRA_MIME", "MAVERICK_ATTACH_ALLOW_ANY",
                "MAVERICK_ATTACH_EMBED_DOCS"):
        monkeypatch.delenv(var, raising=False)


class TestBroaderMimes:
    def test_audio_accepted(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        out = store(goal_id=1, filename="memo.mp3", mime="audio/mpeg",
                    data=b"ID3\x03fakeaudio", root=tmp_path)
        assert out.path.exists()

    def test_video_accepted(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        out = store(goal_id=1, filename="clip.mp4", mime="video/mp4",
                    data=b"\x00\x00\x00\x18ftypmp42fake", root=tmp_path)
        assert out.path.exists()

    def test_docx_accepted(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        out = store(goal_id=1, filename="report.docx", mime=DOCX_MIME,
                    data=_ooxml_bytes(), root=tmp_path)
        assert out.path.exists()

    def test_odt_accepted(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        out = store(
            goal_id=1, filename="notes.odt",
            mime="application/vnd.oasis.opendocument.text",
            data=_odf_bytes(), root=tmp_path,
        )
        assert out.path.exists()

    def test_generic_zip_mime_still_rejected(self, tmp_path, monkeypatch):
        # Even a structurally-valid OOXML payload is refused under a raw
        # archive mime: the allowlist has no application/zip.
        _clear_env(monkeypatch)
        with pytest.raises(AttachmentRejected, match="mime type not allowed"):
            store(goal_id=1, filename="stuff.zip", mime="application/zip",
                  data=_ooxml_bytes(), root=tmp_path)

    def test_plain_zip_claimed_as_docx_rejected(self, tmp_path, monkeypatch):
        # A generic archive (no [Content_Types].xml / document mimetype
        # entry) can't sneak through by claiming an Office Content-Type.
        _clear_env(monkeypatch)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("payload.bin", "x" * 64)
        with pytest.raises(AttachmentRejected, match="executable or archive"):
            store(goal_id=1, filename="fake.docx", mime=DOCX_MIME,
                  data=buf.getvalue(), root=tmp_path)

    def test_invalid_zip_bytes_claimed_as_docx_rejected(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        with pytest.raises(AttachmentRejected, match="executable or archive"):
            store(goal_id=1, filename="fake.docx", mime=DOCX_MIME,
                  data=b"PK\x03\x04" + b"\x00" * 32, root=tmp_path)

    def test_elf_still_rejected_under_any_mime(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_ATTACH_ALLOW_ANY", "1")
        elf = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 64
        with pytest.raises(AttachmentRejected, match="executable or archive"):
            store(goal_id=1, filename="evil.bin",
                  mime="application/octet-stream", data=elf, root=tmp_path)

    def test_extra_mime_env_extends_allowlist(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        with pytest.raises(AttachmentRejected, match="mime type not allowed"):
            store(goal_id=1, filename="d.bin", mime="application/x-custom",
                  data=b"data", root=tmp_path)
        monkeypatch.setenv("MAVERICK_ATTACH_EXTRA_MIME", "application/x-custom")
        out = store(goal_id=1, filename="d.bin", mime="application/x-custom",
                    data=b"data", root=tmp_path)
        assert out.path.exists()

    def test_allow_any_env_accepts_unknown_mime(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_ATTACH_ALLOW_ANY", "1")
        out = store(goal_id=1, filename="blob.bin",
                    mime="application/octet-stream", data=b"plain bytes",
                    root=tmp_path)
        assert out.path.exists()


class TestPdfDocumentBlocks:
    def _goal_with_pdf(self, tmp_path):
        wm = WorldModel(path=tmp_path / "w.db")
        gid = wm.create_goal("pdf goal", "")
        out = store(goal_id=gid, filename="spec.pdf", mime="application/pdf",
                    data=b"%PDF-1.4 fake pdf body", root=tmp_path / "attach")
        wm.add_attachment(goal_id=gid, filename=out.filename, mime=out.mime,
                          size_bytes=out.size_bytes, sha256=out.sha256,
                          path=str(out.path))
        return wm, gid

    def test_pdf_becomes_document_block_for_anthropic_model(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        wm, gid = self._goal_with_pdf(tmp_path)
        blocks = content_blocks_for_goal(wm, gid, model="claude-opus-4-8")
        assert len(blocks) == 1
        assert blocks[0]["type"] == "document"
        assert blocks[0]["source"]["media_type"] == "application/pdf"
        assert blocks[0]["source"]["data"]

    def test_pdf_skipped_without_model(self, tmp_path, monkeypatch):
        # Legacy call shape (no model): conservative, no document blocks.
        _clear_env(monkeypatch)
        wm, gid = self._goal_with_pdf(tmp_path)
        assert content_blocks_for_goal(wm, gid) == []

    def test_pdf_skipped_for_non_anthropic_model(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        wm, gid = self._goal_with_pdf(tmp_path)
        assert content_blocks_for_goal(wm, gid, model="openai:gpt-5.5") == []

    def test_pdf_skipped_when_disabled(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_ATTACH_EMBED_DOCS", "0")
        wm, gid = self._goal_with_pdf(tmp_path)
        assert content_blocks_for_goal(wm, gid, model="claude-opus-4-8") == []

    def test_images_still_embed_alongside_documents(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        wm, gid = self._goal_with_pdf(tmp_path)
        png_bytes = bytes.fromhex(
            "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4"
            "890000000A49444154789C6300010000000500010D0A2DB40000000049454E44"
            "AE426082"
        )
        out = store(goal_id=gid, filename="pixel.png", mime="image/png",
                    data=png_bytes, root=tmp_path / "attach")
        wm.add_attachment(goal_id=gid, filename=out.filename, mime=out.mime,
                          size_bytes=out.size_bytes, sha256=out.sha256,
                          path=str(out.path))
        blocks = content_blocks_for_goal(wm, gid, model="claude-opus-4-8")
        kinds = sorted(b["type"] for b in blocks)
        assert kinds == ["document", "image"]
        # Images lead so the text brief stays adjacent to the documents.
        assert blocks[0]["type"] == "image"
