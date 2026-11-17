"""Count the lines of a file."""


def count_lines(path):
    """The number of lines in ``path``."""
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)
