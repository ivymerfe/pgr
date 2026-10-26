import csv
import struct
import sys


OUTPUT = "session.csv"


class Cur:
    def __init__(self, d):
        self.d = d
        self.p = 0

    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self):
        v = struct.unpack_from("<H", self.d, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def s(self):
        n = self.u32()
        v = self.d[self.p : self.p + n].decode("utf-8", "replace")
        self.p += n
        return v

    def rest(self):
        return self.d[self.p :]


def copy_rows(d):
    if len(d) < 19 or not d.startswith(b"PGCOPY\n\xff\r\n\x00"):
        return -1
    pos = 15
    pos += 4 + struct.unpack_from(">I", d, pos)[0]
    n = 0
    while pos + 2 <= len(d):
        nf = struct.unpack_from(">h", d, pos)[0]
        pos += 2
        if nf == -1:
            break
        for _ in range(nf):
            l = struct.unpack_from(">i", d, pos)[0]
            pos += 4
            if l > 0:
                pos += l
        n += 1
    return n


def main():
    input = sys.argv[1]

    print(f"{input} -> {OUTPUT}")

    data = open(input, "rb").read()

    with open(OUTPUT, "w") as outfile:
        w = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)
        w.writerow(["rec", "offset", "type", "fields"])
        pos = 0
        rec = 0
        while pos + 9 <= len(data):
            t = data[pos]
            ln = struct.unpack_from("<Q", data, pos + 1)[0]
            body = data[pos + 9 : pos + 9 + ln]
            c = Cur(body)
            if t == 1:
                n = c.u32()
                for _ in range(n):
                    w.writerow([rec, pos, "guc", c.s(), c.s()])
            elif t == 2:
                n = c.u32()
                for _ in range(n):
                    name = c.s()
                    from_sql = c.u8()
                    q = c.s()
                    np_ = c.u16()
                    types = " ".join(str(c.u32()) for _ in range(np_))
                    w.writerow([rec, pos, "prepared", name, from_sql, q, types])
            elif t == 3:
                name = c.s()
                cols = c.s()
                post = c.s()
                raw = c.rest()
                w.writerow(
                    [rec, pos, "table", name, cols, post, len(raw), copy_rows(raw)]
                )
            elif t == 4:
                w.writerow([rec, pos, "drop_all"])
            else:
                w.writerow([rec, pos, "unknown_%d" % t, ln])
            pos += 9 + ln
            rec += 1
        if pos != len(data):
            w.writerow([rec, pos, "truncated", len(data) - pos])


if __name__ == "__main__":
    main()
