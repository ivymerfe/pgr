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

    remove_debug_sessions()
    enable_debug_sessions()
    
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

    timings_path = start_timings()

    if replay(capture_path) != 0:
        print("replay failed")
        stop_timings()
        disable_debug_sessions()
        return 2

    stop_timings()
    disable_debug_sessions()
    
    compare_timings(capture_path, timings_path)
    compare_sessions()

    return 0


if __name__ == "__main__":
    sys.exit(main())
