import random
import re
import subprocess
import sys
import time
from collections import Counter

from tests import pitr

DATA = "./data"
PGR = "./target/debug/pgr"
TABLES = ["pgbench_accounts", "pgbench_branches", "pgbench_tellers", "pgbench_history"]
COLUMNS = {
    "pgbench_accounts": "aid, bid, abalance, filler",
    "pgbench_branches": "bid, bbalance, filler",
    "pgbench_tellers": "tid, bid, tbalance, filler",
    "pgbench_history": "tid, bid, aid, delta",
}


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def start_db():
    subprocess.run(
        ["pg_ctl", "start", "-D", DATA, "-w", "-l", "pg.log"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def stop_db():
    sh("pg_ctl", "stop", "-D", DATA, "-m", "fast", "-w", check=False)


def psql(sql):
    return sh("psql", "-X", "-A", "-t", "-d", "postgres", "-c", sql).stdout.rstrip("\n")


def wait_promoted():
    while True:
        r = sh("psql", "-X", "-A", "-t", "-d", "postgres", "-c", "select pg_is_in_recovery()", check=False)
        if r.returncode == 0 and r.stdout.strip() == "f":
            return
        time.sleep(0.5)


def snapshot():
    return {
        t: Counter(psql(f"select {COLUMNS[t]} from {t}").splitlines())
        for t in TABLES
    }

def diag():
    print("history rows:", psql("select count(*) from pgbench_history"))
    print("sum(delta):", psql("select sum(delta) from pgbench_history"))
    print("sum(abalance):", psql("select sum(abalance) from pgbench_accounts"))
    print("sum(tbalance):", psql("select sum(tbalance) from pgbench_tellers"))

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

def run_test():
    print("stopping db")
    stop_db()
    print("backup")
    pitr.backup(DATA)
    print("starting db")
    start_db()

    print("starting bench")
    bench = subprocess.Popen(
        ["pgbench", "-n", "-T", "5", "-c", "8", "-j", "4", "-M", "prepared", "postgres"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(random.uniform(1, 2))

    capture_id = int(psql("select pgr.cstart()"))
    print(f"capture id: {capture_id}")

    bench.wait()
    psql("select pgr.cstop()")
    print("capture stopped, snapshot")
    before = snapshot()
    diag()

    capture_path = f"{DATA}/captures/{capture_id}.pr"

    out = sh(PGR, "lsn", capture_path)
    m = re.search(r"OK:\s*([0-9A-Fa-f]+/[0-9A-Fa-f]+)", out.stdout + out.stderr)
    if not m:
        print("failed to get lsn:", out.stdout, out.stderr)
        return 2
    lsn = m.group(1)
    print(f"lsn: {lsn}")

    print("stopping db")
    stop_db()
    print("recovering")
    pitr.recover(DATA, lsn)
    print("starting db")
    start_db()
    wait_promoted()

    diag()

    print("replaying")
    r = subprocess.run([PGR, "replay", capture_path])
    if r.returncode != 0:
        print("replay failed")
        return 2

    print("snapshot")
    after = snapshot()
    diag()

    total = compare(before, after)
    print(f"total mismatches: {total}")
    return 0 if total == 0 else 1


if len(sys.argv) < 2:
    sys.exit("usage: run_tests.py backup|restore <lsn>|test")

cmd = sys.argv[1]

if cmd == "backup":
    pitr.backup(DATA)
elif cmd == "restore":
    subprocess.run(["pg_ctl", "stop", "-D", DATA])
    pitr.recover(DATA, sys.argv[2])
    subprocess.run(["pg_ctl", "start", "-D", DATA])
elif cmd == "test":
    sys.exit(run_test())
