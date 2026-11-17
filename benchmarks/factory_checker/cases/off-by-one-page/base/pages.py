"""Split a sequence of items into pages."""


def page(items, number, size):
    """Items on page ``number`` (counted from 1), ``size`` items per page."""
    if number < 1 or size < 1:
        raise ValueError("page number and size start at 1")
    start = (number - 1) * size
    return list(items[start:start + size])
