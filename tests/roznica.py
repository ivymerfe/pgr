import random

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


def roznica_main(
    test_time: float,
    num_workers: int,
    cap_delay_min: float,
    cap_delay_max: float,
    replay_speed: float,
):
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
            str(num_workers),
            "-t",
            str(test_time),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(random.uniform(cap_delay_min, cap_delay_max))

    capture_path = start_capture()

    bench.wait()

    stop_capture()

    timings_path = start_timings()
    print_stats()

    if replay(capture_path, replay_speed) != 0:
        print("replay failed")
        stop_timings()
        disable_debug_sessions()
        return 2

    print_stats()

    stop_timings()
    disable_debug_sessions()

    compare_timings(capture_path, timings_path)
    compare_sessions()

    return 0
