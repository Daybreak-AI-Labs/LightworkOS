"""Measure elapsed time."""


def elapsed(start, end):
    """Seconds between two time.monotonic() readings."""
    return end - start
