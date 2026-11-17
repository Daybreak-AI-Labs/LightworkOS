"""Parse durations like '1h30m' into seconds."""
import re

UNITS = {"h": 3600, "m": 60, "s": 1}


def parse_duration(text):
    """Seconds in ``text``, a run of <number><unit> parts."""
    parts = re.findall(r"(\d+)([hms])", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        raise ValueError(f"not a duration: {text!r}")
    return sum(int(n) * UNITS[u] for n, u in parts)
