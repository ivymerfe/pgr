from tests.base import *
from concurrent.futures import ThreadPoolExecutor
import random
import sys

JAR = "./tests/bench.jar"
CLASS = "tests.roznica.TempCatalogRoznicaLike"
USER = "yami"
TIME = 2
NUM_WORKERS = 1
CAPTURE_DELAY_MIN = 1
CAPTURE_DELAY_MAX = 1


def main():
    open('pg.log', 'w').close()

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

    capture_path = start_capture()

    bench.wait()
    stop_capture()

    if replay(capture_path) != 0:
        print("replay failed")
        return 2

    return 0 


if __name__ == "__main__":
    sys.exit(main())
