from tests.roznica import roznica_main
import sys

TIME = 20
NUM_WORKERS = 5
CAPTURE_DELAY_MIN = 2
CAPTURE_DELAY_MAX = 5

if __name__ == "__main__":
    sys.exit(roznica_main(TIME, NUM_WORKERS, CAPTURE_DELAY_MAX, CAPTURE_DELAY_MAX))
