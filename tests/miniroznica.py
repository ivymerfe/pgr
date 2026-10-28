import random
import sys

from tests.base import *
from tests.sessions import compare_sessions

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
    compare_sessions()

    return 0


if __name__ == "__main__":
    sys.exit(main())
