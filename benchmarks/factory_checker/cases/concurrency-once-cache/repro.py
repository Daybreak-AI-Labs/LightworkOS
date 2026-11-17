import sys
import threading
import time

from memo import OnceCache

cache, calls = OnceCache(), []


def slow():
    calls.append(1)
    time.sleep(0.2)
    return 1


threads = [threading.Thread(target=cache.get, args=("k", slow)) for _ in range(2)]
for t in threads:
    t.start()
for t in threads:
    t.join()
if len(calls) != 1:
    sys.exit(f"the factory ran {len(calls)} times for one key")
