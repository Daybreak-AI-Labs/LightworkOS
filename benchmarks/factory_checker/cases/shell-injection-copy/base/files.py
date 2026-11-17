"""Copy files."""
import shutil


def copy_file(src, dest):
    """Copy the contents of ``src`` to ``dest``."""
    shutil.copyfile(src, dest)
