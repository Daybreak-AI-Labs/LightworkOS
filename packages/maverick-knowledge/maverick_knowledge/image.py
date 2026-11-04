"""Image describers -- turn an uploaded image / process diagram into text the
knowledge layer can index.

A describer is any ``callable(path: str) -> str``. ``build_ocr_describer`` uses
the optional ``vision`` extra (pytesseract + Pillow) to OCR the text out of a
diagram. A richer vision-LLM describer (which captions the image, not just its
text) can be supplied by the caller instead -- the KnowledgeBase only needs the
callable, so the model/dependency choice stays with the operator.
"""
from __future__ import annotations

import warnings
from contextlib import contextmanager
from pathlib import Path

DEFAULT_MAX_IMAGE_PIXELS = 20_000_000
DEFAULT_MAX_IMAGE_BYTES = 20 * 1024 * 1024
DEFAULT_OCR_TIMEOUT_SECONDS = 15


@contextmanager
def _pixel_cap(Image, max_image_pixels: int):
    """Enforce Lightwork's pixel cap and turn decompression-bomb warnings into
    errors for the duration of a decode. Pillow's global MAX_IMAGE_PIXELS is
    restored afterwards."""
    previous_max_pixels = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = max_image_pixels
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            yield
    finally:
        Image.MAX_IMAGE_PIXELS = previous_max_pixels


def _validate_image(path: str, Image, max_image_pixels: int, max_image_bytes: int):
    image_path = Path(path)
    file_size = image_path.stat().st_size
    if file_size > max_image_bytes:
        raise ValueError(
            f"image is too large for OCR ({file_size} bytes > {max_image_bytes} bytes)"
        )

    # Pillow only warns for many decompression-bomb cases; fail closed and also
    # enforce Lightwork's own pixel cap before any full decode/OCR work occurs.
    with _pixel_cap(Image, max_image_pixels):
        with Image.open(image_path) as img:
            width, height = img.size
            if width <= 0 or height <= 0:
                raise ValueError("image has invalid dimensions")
            pixels = width * height
            if pixels > max_image_pixels:
                raise ValueError(
                    f"image has too many pixels for OCR ({pixels} > {max_image_pixels})"
                )
            img.verify()


def build_ocr_describer(
    *,
    max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS,
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
    ocr_timeout_seconds: int = DEFAULT_OCR_TIMEOUT_SECONDS,
):
    """An OCR describer (pytesseract + Pillow).

    Needs the ``vision`` extra from the reviewed checkout:
    ``python -m pip install -e './packages/maverick-knowledge[vision]'`` (plus
    the system ``tesseract`` binary). Returns ``callable(path) -> str``.

    Image files are bounded before decode/OCR, and Tesseract is called with a
    timeout so malformed or expensive inputs cannot hang ingestion indefinitely.
    """
    try:
        import pytesseract
        from PIL import Image
    except ModuleNotFoundError as e:
        raise RuntimeError(
            "OCR needs the 'vision' extra. From the reviewed checkout run: "
            "python -m pip install -e './packages/maverick-knowledge[vision]'"
        ) from e

    if max_image_pixels <= 0:
        raise ValueError("max_image_pixels must be positive")
    if max_image_bytes <= 0:
        raise ValueError("max_image_bytes must be positive")
    if ocr_timeout_seconds <= 0:
        raise ValueError("ocr_timeout_seconds must be positive")

    def describe(path: str) -> str:
        _validate_image(path, Image, max_image_pixels, max_image_bytes)
        # Re-open under the same pixel cap: the OCR decode is the expensive step,
        # so the bomb guard must still be in force here (not just at validation),
        # which also bounds the decode if the file was swapped after validation.
        with _pixel_cap(Image, max_image_pixels):
            with Image.open(path) as img:
                text = (
                    pytesseract.image_to_string(img, timeout=ocr_timeout_seconds) or ""
                ).strip()
        return f"[diagram/image OCR: {path}]\n{text}" if text else ""

    return describe
