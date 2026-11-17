"""Read text files line by line."""


def read_lines(path):
    """The lines of ``path`` without their newlines."""
    with open(path, encoding="utf-8") as fh:
        return [line.rstrip("\n") for line in fh]
