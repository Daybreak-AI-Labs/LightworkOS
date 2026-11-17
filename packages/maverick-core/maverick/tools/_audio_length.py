"""Audio length read from a file, before it is sent anywhere.

A header can be wrong or faked, so it never sets a spending hold: the hold
comes from :func:`max_audio_seconds`, an upper bound from the file size. A
header length only fills in a charge when the provider reports none, and only
within that bound (``voice``). Only the formats
whose header states the length, or lets it be worked out, are read: WAV,
FLAC, MP4/M4A, Ogg (Vorbis or Opus) and MP3 (from its Xing/Info/VBRI frame,
else its bitrate). Anything else gives ``None``.
"""
from __future__ import annotations

import struct
from typing import BinaryIO

_MAX_SCAN = 1 << 20  # header search limit (1 MiB)


# The lowest practical speech bitrate (Opus's minimum, 6 kbit/s): no real
# recording of a given size plays longer than this allows.
_MIN_SPEECH_BITS_PER_SECOND = 6_000


def max_audio_seconds(size: int) -> float:
    """The longest a recording of ``size`` bytes can play, whatever it claims."""
    return max(0, size) * 8 / _MIN_SPEECH_BITS_PER_SECOND


def audio_seconds(stream: BinaryIO, size: int) -> float | None:
    """The length the header states, in seconds, or ``None`` when it does not
    say or cannot be read. Any parsing failure counts as unknown."""
    try:
        head = stream.read(64)
        stream.seek(0)
        if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
            return _wav(stream)
        if head[:4] == b"fLaC":
            return _flac(head)
        if head[4:8] == b"ftyp":
            return _mp4(stream, size)
        if head[:4] == b"OggS":
            return _ogg(stream, size)
        if head[:3] == b"ID3" or (len(head) > 1 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
            return _mp3(stream, size)
    except Exception:  # a malformed or unusual header is simply unknown
        return None
    return None


def _wav(stream: BinaryIO) -> float | None:
    import wave

    with wave.open(stream, "rb") as audio:
        rate = audio.getframerate()
        return audio.getnframes() / rate if rate else None


def _flac(head: bytes) -> float | None:
    # STREAMINFO follows the 4-byte marker and a 4-byte block header.
    info = head[8:26]
    rate = (info[10] << 12) | (info[11] << 4) | (info[12] >> 4)
    samples = ((info[13] & 0x0F) << 32) | struct.unpack(">I", info[14:18])[0]
    return samples / rate if rate and samples else None


def _mp4(stream: BinaryIO, size: int) -> float | None:
    data = stream.read(min(size, 16 * _MAX_SCAN))
    at = data.find(b"mvhd")
    if at < 4:
        return None
    version = data[at + 4]
    if version == 1:
        scale, duration = struct.unpack(">IQ", data[at + 24:at + 36])
    else:
        scale, duration = struct.unpack(">II", data[at + 16:at + 24])
    return duration / scale if scale else None


def _ogg(stream: BinaryIO, size: int) -> float | None:
    first = stream.read(min(size, _MAX_SCAN))
    if b"OpusHead" in first:
        rate = 48_000
    elif (at := first.find(b"\x01vorbis")) >= 0:
        rate = struct.unpack("<I", first[at + 12:at + 16])[0]
    else:
        return None
    stream.seek(max(0, size - 65_536))
    tail = stream.read()
    last = tail.rfind(b"OggS")
    if last < 0 or not rate:
        return None
    granule = struct.unpack("<q", tail[last + 6:last + 14])[0]
    return granule / rate if granule > 0 else None


_MP3_BITRATES = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)
_MP3_RATES = (44_100, 48_000, 32_000)


def _mp3(stream: BinaryIO, size: int) -> float | None:
    data = stream.read(min(size, _MAX_SCAN))
    start = 0
    if data[:3] == b"ID3":
        start = 10 + ((data[6] << 21) | (data[7] << 14) | (data[8] << 7) | data[9])
    frame = data[start:start + 4]
    if len(frame) < 4 or frame[0] != 0xFF or frame[1] & 0xE0 != 0xE0:
        return None
    mpeg1 = frame[1] & 0x18 == 0x18
    bitrate = _MP3_BITRATES[frame[2] >> 4] if mpeg1 else 0
    rate_index = (frame[2] >> 2) & 0x03
    if rate_index == 3:
        return None
    rate = _MP3_RATES[rate_index] if mpeg1 else _MP3_RATES[rate_index] // 2
    samples_per_frame = 1152 if mpeg1 else 576
    window = data[start:start + 200]
    for tag in (b"Xing", b"Info"):
        at = window.find(tag)
        if at >= 0 and struct.unpack(">I", window[at + 4:at + 8])[0] & 1:
            frames = struct.unpack(">I", window[at + 8:at + 12])[0]
            return frames * samples_per_frame / rate
    at = window.find(b"VBRI")
    if at >= 0:
        frames = struct.unpack(">I", window[at + 14:at + 18])[0]
        return frames * samples_per_frame / rate
    if not bitrate:
        return None
    return (size - start) * 8 / (bitrate * 1000)
