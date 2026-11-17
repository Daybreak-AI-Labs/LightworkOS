"""Turn titles into URL slugs."""
import re


def slugify(title):
    """Lower-case words joined by single dashes, nothing at either end."""
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
