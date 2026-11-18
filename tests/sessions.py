import os
import struct
import glob

from collections import Counter

import zstandard

from tests.base import DATA

GUC_SET, GUC_RESET, PREP_PUT, PREP_DROP = 1, 2, 3, 4
TBL_BEGIN, TBL_CHUNK, TBL_END, TBL_DROP = 5, 6, 7, 8
GROUP = {
    GUC_SET: 1,
    GUC_RESET: 1,
    PREP_PUT: 2,
    PREP_DROP: 2,
    TBL_BEGIN: 3,
    TBL_CHUNK: 3,
    TBL_END: 3,
    TBL_DROP: 3,
}


def read_frames(path):
    with open(path, "rb") as f:
        return (
            zstandard.ZstdDecompressor()
            .stream_reader(f, read_across_frames=True)
            .read()
        )


def rd_str(b, p):
    n = struct.unpack_from("<I", b, p)[0]
    return b[p + 4 : p + 4 + n], p + 4 + n


def parse_copy(b):
    p = 11 + 4
    ext = struct.unpack_from(">i", b, p)[0]
    p += 4 + ext
    rows = Counter()
    while p < len(b):
        n = struct.unpack_from(">h", b, p)[0]
        p += 2
        if n == -1:
            break
        row = []
        for _ in range(n):
            ln = struct.unpack_from(">i", b, p)[0]
            p += 4
            if ln == -1:
                row.append(None)
            else:
                row.append(b[p : p + ln])
                p += ln
        rows[tuple(row)] += 1
    return rows


def parse_session(path):
    b = read_frames(path)
    res = {
        "size": os.path.getsize(path),
        "sizes": Counter(),
        "gucs": {},
        "prep": [],
        "tables": {},
    }
    prep = {}
    cur = None
    p = 0
    while p < len(b):
        t = b[p]
        ln = struct.unpack_from("<I", b, p + 1)[0]
        body = b[p + 5 : p + 5 + ln]
        p += 5 + ln
        res["sizes"][GROUP[t]] += ln
        if t == GUC_SET:
            k, q = rd_str(body, 0)
            v, q = rd_str(body, q)
            res["gucs"][k] = v
        elif t == GUC_RESET:
            k, _ = rd_str(body, 0)
            res["gucs"].pop(k, None)
        elif t == PREP_PUT:
            name, q = rd_str(body, 0)
            fs = body[q]
            q += 1
            sql, q = rd_str(body, q)
            np_ = struct.unpack_from("<H", body, q)[0]
            prep[name] = (name, fs, sql, np_)
        elif t == PREP_DROP:
            name, _ = rd_str(body, 0)
            prep.pop(name, None)
        elif t == TBL_BEGIN:
            name, q = rd_str(body, 0)
            cols, q = rd_str(body, q)
            post, q = rd_str(body, q)
            cur = [name, cols, post, bytearray()]
        elif t == TBL_CHUNK:
            cur[3] += body
        elif t == TBL_END:
            name, cols, post, data = cur
            res["tables"][name] = (len(data), cols, post, parse_copy(bytes(data)))
            cur = None
        elif t == TBL_DROP:
            name, _ = rd_str(body, 0)
            res["tables"].pop(name, None)
    res["prep"] = list(prep.values())
    return res


def compare_session(sid):
    d = parse_session(f"{DATA}/sessions/d/{sid}.pgs")
    r = parse_session(f"{DATA}/sessions/r/{sid}.pgs")
    print(
        f"session {sid}: orig={d['size']} replay={r['size']} "
        f"ratio={r['size'] / max(d['size'], 1):.2f}"
    )
    for t, name in ((1, "gucs"), (2, "prepared"), (3, "tables")):
        print(f"  {name}: orig={d['sizes'][t]} replay={r['sizes'][t]}")
    bad = 0
    for k in sorted(set(d["gucs"]) | set(r["gucs"])):
        k_str = k.decode()
        if k_str == "pgr.client_id":
            continue

        if d["gucs"].get(k) != r["gucs"].get(k):
            print(f"  guc {k_str}: {d['gucs'].get(k)} != {r['gucs'].get(k)}")
            bad += 1
    if sorted(d["prep"]) != sorted(r["prep"]):
        a, b = set(d["prep"]), set(r["prep"])
        print(f"  prepared: only orig={len(a - b)} only replay={len(b - a)}")
        for x in sorted(a - b)[:5]:
            print(f"    - {x[0].decode()}: {x[2].decode()[:80]}")
        for x in sorted(b - a)[:5]:
            print(f"    + {x[0].decode()}: {x[2].decode()[:80]}")
        bad += 1
    for t in sorted(set(d["tables"]) | set(r["tables"])):
        a = d["tables"].get(t)
        b = r["tables"].get(t)
        if a is None or b is None:
            print(
                f"  table {t.decode()}: missing in {'orig' if a is None else 'replay'}"
            )
            bad += 1
            continue
        if a[1] != b[1] or a[2] != b[2]:
            print(f"  table {t.decode()}: ddl differs")
            bad += 1
        if a[3] != b[3]:
            only_a = sum((a[3] - b[3]).values())
            only_b = sum((b[3] - a[3]).values())
            print(
                f"  table {t.decode()}: rows orig={sum(a[3].values())} "
                f"replay={sum(b[3].values())} only_orig={only_a} only_replay={only_b} "
                f"bytes orig={a[0]} replay={b[0]}"
            )
            bad += 1
        elif a[0] != b[0]:
            print(f"  table {t.decode()}: same rows, bytes orig={a[0]} replay={b[0]}")
    return bad


def compare_sessions():
    ids = lambda s: {
        os.path.basename(f)[:-4] for f in glob.glob(f"{DATA}/sessions/{s}/*.pgs")
    }
    d, r = ids("d"), ids("r")
    for x in sorted(d - r):
        print(f"session {x}: no replay dump")
    for x in sorted(r - d):
        print(f"session {x}: no orig dump")
    bad = 0
    for sid in sorted(d & r, key=int):
        bad += compare_session(sid)
    print(f"sessions compared: {len(d & r)}, with differences: {bad}")
    return bad
