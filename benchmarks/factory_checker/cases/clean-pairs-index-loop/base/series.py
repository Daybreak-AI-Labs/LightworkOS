"""Facts about a series of numbers."""


def increases(values):
    """How many times a value is larger than the one before it."""
    return sum(1 for a, b in zip(values, values[1:], strict=False) if b > a)
