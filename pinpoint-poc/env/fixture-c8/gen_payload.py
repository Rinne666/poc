#!/usr/bin/env python3
"""Generate a valid ExportMetricsServiceRequest of a chosen wire size.

Pure-stdlib protobuf wire encoding (no generated classes): one
ResourceMetrics with a small Resource, one ScopeMetrics, one Sum metric
carrying K NumberDataPoints, each padded with a string attribute to hit a
target byte count. Valid enough for protobuf-java to parse into the full
message graph (which is the point: unbounded request = retained graph).

usage: python3 -I gen_payload.py --mib 8 --out big.pb
"""
import argparse
import struct
import sys


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field, wire):
    return varint((field << 3) | wire)


def lf(field, payload):  # length-delimited
    return tag(field, 2) + varint(len(payload)) + payload


def vi(field, n):        # varint field
    return tag(field, 0) + varint(n)


def fx64(field, val):    # fixed64
    return tag(field, 1) + struct.pack("<d" if isinstance(val, float) else "<Q", val)


def any_value_str(s):
    return lf(1, s.encode())            # AnyValue { string_value = 1 }


def kv(key, s):
    return lf(1, key.encode()) + lf(2, any_value_str(s))  # KeyValue {key=1, value=2}


def number_data_point(pad_bytes, ts):
    body = fx64(2, ts) + fx64(3, ts) + fx64(4, 0.5)  # start, time, as_double
    body += lf(7, kv("pad", pad_bytes))              # attributes = 7
    return body


def build(total_target, datapoints):
    pad_len = max(0, (total_target - 200) // datapoints)
    pad = "x" * pad_len
    dps = b"".join(lf(1, number_data_point(pad, 1730000000000000000 + i))
                   for i in range(datapoints))
    dps += vi(2, 2) + vi(3, 0)  # Sum: temporality=2 (cumulative), monotonic=false
    metric = lf(1, b"fixture.metric") + lf(7, dps)  # name=1, sum=7
    scope = lf(2, metric)                            # ScopeMetrics.metrics = 2
    resource = lf(1, kv("service.name", "c8-fixture-app"))  # Resource.attributes
    rm = lf(1, resource) + lf(2, scope)  # ResourceMetrics{resource=1, scope_metrics=2}
    msg = lf(1, rm)                      # ExportMetricsServiceRequest.resource_metrics=1
    return msg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mib", type=float, required=True)
    ap.add_argument("--datapoints", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    target = int(args.mib * 1024 * 1024)
    msg = build(target, args.datapoints)
    # pad by growing the last datapoint set if short (coarse but honest)
    while len(msg) < target:
        args.datapoints += 200
        msg = build(target, args.datapoints)
        if args.datapoints > 200000:
            break
    with open(args.out, "wb") as f:
        f.write(msg)
    print(f"wrote {args.out}: {len(msg)} bytes ({len(msg)/1048576:.2f} MiB, "
          f"{args.datapoints} datapoints)", file=sys.stderr)


if __name__ == "__main__":
    main()
