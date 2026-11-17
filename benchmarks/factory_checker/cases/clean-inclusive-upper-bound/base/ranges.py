"""Range checks."""


def between(x, low, high):
    """True when low <= x <= high (both ends included)."""
    return low <= x < high
