"""Image describers -- turn an uploaded image / process diagram into text the
knowledge layer can index.

A describer is any ``callable(path: str) -> str``. ``build_ocr_describer`` uses
the optional ``vision`` extra (pytesseract + Pillow) to OCR the text out of a
diagram. A richer vision-LLM describer (which captions the image, not just its
text) can be supplied by the caller instead -- the KnowledgeBase only needs the
callable, so the model/dependency choice stays with the operator.
"""
from __future__ import annotations

import os
import warnings
from collections.abc import Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from threading import RLock

DEFAULT_MAX_IMAGE_PIXELS = 20_000_000
DEFAULT_MAX_IMAGE_BYTES = 20 * 1024 * 1024
DEFAULT_OCR_TIMEOUT_SECONDS = 15
# The formats ``parse.IMAGE_EXTS`` routes here. Pillow picks a decoder from the
# file's content, not its name, so without this a ``.png`` holding EPS would be
# handed to Ghostscript. Only these plugins may identify the file.
OCR_IMAGE_FORMATS = ("PNG", "JPEG", "GIF", "WEBP", "BMP", "TIFF")
_PIXEL_CAP_LOCK = RLock()


class _OneOpenMPThread(Mapping):
    """``os.environ``, read live, with ``OMP_THREAD_LIMIT=1`` unless set.

    Tesseract's OpenMP otherwise starts a thread per core; on a busy host they
    contend so badly that a tiny image ran 115 s instead of 0.4 s, far past
    the OCR timeout. Only the tesseract child sees this, not this process."""

    _KEY = "OMP_THREAD_LIMIT"

    def __getitem__(self, key):
        if key == self._KEY and key not in os.environ:
            return "1"
        return os.environ[key]

    def __iter__(self):
        yield from os.environ
        if self._KEY not in os.environ:
            yield self._KEY

    def __len__(self):
        return len(os.environ) + (self._KEY not in os.environ)


def _limit_tesseract_threads(pytesseract) -> None:
    # pytesseract has no env argument: it starts tesseract with its module's
    # ``environ`` (``os.environ``). Swap in the view above, once.
    module = getattr(pytesseract, "pytesseract", None)
    if module is not None and getattr(module, "environ", None) is os.environ:
        module.environ = _OneOpenMPThread()


def _open_allowed(Image, path):
    try:
        return Image.open(path, formats=list(OCR_IMAGE_FORMATS))
    except OSError as exc:  # PIL.UnidentifiedImageError is an OSError
        raise ValueError(
            "OCR refused the image: it is not a readable PNG, JPEG, GIF, WebP, "
            "BMP or TIFF file"
        ) from exc


@contextmanager
def _pixel_cap(Image, max_image_pixels: int):
    """Enforce Lightwork's pixel cap and turn decompression-bomb warnings into
    errors for the duration of a decode. Pillow's global MAX_IMAGE_PIXELS is
    restored afterwards."""
    with _PIXEL_CAP_LOCK:
        previous_max_pixels = Image.MAX_IMAGE_PIXELS
        Image.MAX_IMAGE_PIXELS = max_image_pixels
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                yield
        finally:
            Image.MAX_IMAGE_PIXELS = previous_max_pixels


def _check_pixels(img, max_image_pixels: int):
    width, height = img.size
    if width <= 0 or height <= 0:
        raise ValueError("image has invalid dimensions")
    pixels = width * height
    if pixels > max_image_pixels:
        raise ValueError(
            f"image has too many pixels for OCR ({pixels} > {max_image_pixels})"
        )


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
        with _open_allowed(Image, image_path) as img:
            _check_pixels(img, max_image_pixels)
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
    _limit_tesseract_threads(pytesseract)

    def describe(path: str) -> str:
        _validate_image(path, Image, max_image_pixels, max_image_bytes)
        # Re-open under the pixel cap and re-check the size: Pillow's bomb check
        # runs when the header is read, and the explicit check also covers a
        # file swapped after validation. The decode can only produce those
        # checked dimensions, so the slow OCR runs after the process-wide cap is
        # restored and its lock released; concurrent ingests are not serialized.
        with ExitStack() as stack:
            with _pixel_cap(Image, max_image_pixels):
                img = stack.enter_context(_open_allowed(Image, path))
                _check_pixels(img, max_image_pixels)
            text = (
                pytesseract.image_to_string(img, timeout=ocr_timeout_seconds) or ""
            ).strip()
        return f"[diagram/image OCR: {path}]\n{text}" if text else ""

    return describe
