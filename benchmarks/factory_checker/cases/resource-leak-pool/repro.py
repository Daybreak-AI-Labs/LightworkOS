import sys

from pool import Pool, with_conn

pool = Pool(2)


def bad(conn):
    raise ValueError("bad query")


for _ in range(3):
    try:
        with_conn(pool, bad)
    except (ValueError, RuntimeError):
        pass
if pool.available != 2:
    sys.exit(f"{2 - pool.available} connection(s) were never given back")
