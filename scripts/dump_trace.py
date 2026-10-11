import csv
from collections import defaultdict
import os
import struct


def dump_latest_trace(folder_path):
    with os.scandir(folder_path) as entries:
        files = [
            entry
            for entry in entries
            if entry.is_file() and entry.stat().st_size > 0
        ]

    if not files:
        print("no file.")
        return

    latest_entry = max(files, key=lambda entry: entry.stat().st_mtime)
    print(f"Trace file: {latest_entry.path}\n")

    totals = defaultdict(int)

    csv_path = "trace.csv"
    struct_fmt = "<IIIb"
    with open(latest_entry.path, "rb") as file, open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["user_id", "index", "duration_us", "event_type"])
        data = file.read()
        for user_id, index, duration_us, event_type in struct.iter_unpack(struct_fmt, data):
            totals[user_id] += duration_us
            event_char = chr(event_type & 0xFF)
            writer.writerow([user_id, index, duration_us, event_char])

    print(f"Output: {csv_path}\n")

    for user_id, total_sum in sorted(totals.items(), key=lambda x: x[0]):
        print(f"ID {user_id}: {total_sum}")


dump_latest_trace("../data/traces")
