import csv
from collections import defaultdict
import os
import struct
import sys

OUTPUT = "trace.csv"

def main():
    totals = defaultdict(int)
    input = sys.argv[1]

    print(f"{input} -> {OUTPUT}")

    with (
        open(input, "rb") as file,
        open(OUTPUT, "w", newline="", encoding="utf-8") as csv_file,
    ):
        writer = csv.writer(csv_file)
        writer.writerow(["user_id", "index", "duration_us", "event_type"])
        data = file.read()
        for user_id, index, duration_us, event_type in struct.iter_unpack("<IIIb", data):
            totals[user_id] += duration_us
            event_char = chr(event_type & 0xFF)
            writer.writerow([user_id, index, duration_us, event_char])

    for user_id, total_sum in sorted(totals.items(), key=lambda x: x[0]):
        print(f"ID {user_id}: {total_sum}")

if __name__ == "__main__":
    main()
