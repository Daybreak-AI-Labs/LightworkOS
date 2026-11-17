import sys

from retry import retry

calls = []


def flaky():
    calls.append(1)
    if len(calls) < 3:
        raise OSError("not yet")
    return "ok"


try:
    result = retry(flaky, attempts=3, sleep=lambda _: None)
except TypeError:
    result = retry(flaky, attempts=3)
except OSError:
    sys.exit(f"retry gave up after {len(calls)} calls; 3 attempts were allowed")
if result != "ok":
    sys.exit(f"unexpected result {result!r}")
