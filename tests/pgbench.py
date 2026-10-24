from tests.base import *
from collections import Counter
import random

TABLES = ["pgbench_accounts", "pgbench_branches", "pgbench_tellers", "pgbench_history"]
COLUMNS = {
    "pgbench_accounts": "aid, bid, abalance, filler",
    "pgbench_branches": "bid, bbalance, filler",
    "pgbench_tellers": "tid, bid, tbalance, filler",
    "pgbench_history": "tid, bid, aid, delta",
}
TIME = 5
NUM_CLIENTS = 8
NUM_JOBS = 4
CAPTURE_DELAY_MIN = 1
CAPTURE_DELAY_MAX = 2


def snapshot():
    print("snapshot")
    return {
        t: Counter(psql(f"select {COLUMNS[t]} from {t}").splitlines()) for t in TABLES
    }


def compare(a, b):
    total = 0
    for t in TABLES:
        lost = a[t] - b[t]
        extra = b[t] - a[t]
        print(f"{t}: lost={sum(lost.values())} extra={sum(extra.values())}")
        for row in list(lost)[:5]:
            print("  lost :", repr(row))
        for row in list(extra)[:5]:
            print("  extra:", repr(row))
        total += sum(lost.values()) + sum(extra.values())
    return total


def main():
    backup()

    print("starting pgbench")
    bench = subprocess.Popen(
        [
            "pgbench",
            "-n",
            "-T",
            str(TIME),
            "-c",
            str(NUM_CLIENTS),
            "-j",
            str(NUM_JOBS),
            "-M",
            "prepared",
            "postgres",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(random.uniform(CAPTURE_DELAY_MIN, CAPTURE_DELAY_MAX))

    capture_path = start_capture()
    bench.wait()
    stop_capture()

    before = snapshot()

    lsn = get_lsn(capture_path)
    if not lsn:
        print("failed to get lsn")
        return 2

    recover(lsn)

    if replay(capture_path) != 0:
        print("replay failed")
        return 2

    after = snapshot()
    total = compare(before, after)
    print(f"total mismatches: {total}")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    main()
