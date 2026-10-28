from tests.base import *
from concurrent.futures import ThreadPoolExecutor
import random
import sys

TABLES = [
    "registry_data",
    "reference_contractors",
    "reference_types",
    "reference_exclusions",
    "reference_table_vt",
    "reference_documents",
    "reference_access_groups_vt",
    "access_registry",
    # "accumulation_register_products",
]
JAR = "./tests/bench.jar"
CLASS = "tests.roznica.TempCatalogRoznicaLike"
USER = "yami"
TIME = 6
NUM_WORKERS = 10
CAPTURE_DELAY_MIN = 1
CAPTURE_DELAY_MAX = 3


def table_hash(t):
    out = psql(
        f"select count(*), coalesce(sum(hashtextextended(x::text, 0)::numeric), 0) "
        f"from {t} x"
    )
    cnt, total = out.split("|")
    return t, (int(cnt), int(total) % (1 << 64))


def snapshot(label):
    print(f"snapshot: {label}")
    with ThreadPoolExecutor(max_workers=4) as ex:
        res = dict(ex.map(table_hash, TABLES))
    for t in TABLES:
        cnt, h = res[t]
        print(f"  {t}: count={cnt} hash={h:016x}")
    return res


def compare(a, b):
    bad = 0
    for t in TABLES:
        ok = a[t] == b[t]
        print(f"  {t}: {'ok' if ok else 'MISMATCH'}")
        if not ok:
            bad += 1
    return bad


def main():
    open("pg.log", "w").close()

    psql("select pgr.sdebug(true);")
    print("starting bench")
    bench = subprocess.Popen(
        [
            "java",
            "-cp",
            JAR,
            CLASS,
            "-h",
            "localhost",
            "-U",
            USER,
            "-w",
            str(NUM_WORKERS),
            "-t",
            str(TIME),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(random.uniform(CAPTURE_DELAY_MIN, CAPTURE_DELAY_MAX))
    # stop_capture()
    capture_path = start_capture()

    bench.wait()
    stop_capture()

    if replay(capture_path) != 0:
        print("replay failed")
        psql("select pgr.sdebug(false);")
        return 2

    psql("select pgr.sdebug(false);")

    return 0


if __name__ == "__main__":
    sys.exit(main())
