import sys
import threading
import time

from ledger import Ledger


class SlowLedger(Ledger):
    def _write(self, value):
        time.sleep(0.2)
        super()._write(value)


ledger = SlowLedger()
threads = [threading.Thread(target=ledger.add, args=(1,)) for _ in range(2)]
for t in threads:
    t.start()
for t in threads:
    t.join()
if ledger.balance != 2:
    sys.exit(f"two adds of 1 from two threads gave {ledger.balance}, not 2")
