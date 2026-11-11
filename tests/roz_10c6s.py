from tests.roznica import roznica_main
import sys

TIME = 6
NUM_WORKERS = 10
CAPTURE_DELAY_MIN = 1
CAPTURE_DELAY_MAX = 3
SPEED = 1.0

if __name__ == "__main__":
    sys.exit(roznica_main(TIME, NUM_WORKERS, CAPTURE_DELAY_MAX, CAPTURE_DELAY_MAX, SPEED))
