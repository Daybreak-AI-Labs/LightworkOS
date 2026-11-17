"""Count the lines of a file with wc."""
import subprocess


def count_lines(path):
    """The number of lines in ``path``, counted by ``wc -l``."""
    done = subprocess.run(["wc", "-l", "--", path], capture_output=True, text=True,
                          check=True)
    return int(done.stdout.split()[0])
