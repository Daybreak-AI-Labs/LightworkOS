import sys

from text import slugify

got = slugify("Hello, World!")
if got != "hello-world":
    sys.exit(f"slugify('Hello, World!') should be 'hello-world', got {got!r}")
