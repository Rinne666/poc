#!/usr/bin/env python3
"""C8 differential probes (http.client based; host curl lacks 100-continue).

Bounded, single-request POSTs against the fixture on 127.0.0.1:18091.
Nothing destructive: metrics bodies are accepted into a 128MiB lab heap we
own; trace bodies above the 4MiB cap are meant to be rejected by the real
admission filter.
"""
import http.client
import json
import sys
import time

B = ("127.0.0.1", 18091)
PROTO = "application/x-protobuf"


def probe(path, payload_file):
    data = open(payload_file, "rb").read()
    conn = http.client.HTTPConnection(*B, timeout=120)
    t0 = time.time()
    try:
        conn.request("POST", path, body=data,
                     headers={"Content-Type": PROTO,
                              "Content-Length": str(len(data))})
        r = conn.getresponse()
        r.read()
        return r.status, len(data), round(time.time() - t0, 2)
    except Exception as e:  # noqa: BLE001 — an OOM/reset mid-body IS the observation
        return f"conn-error:{type(e).__name__}", len(data), round(time.time() - t0, 2)
    finally:
        conn.close()


def stats():
    conn = http.client.HTTPConnection(*B, timeout=10)
    conn.request("GET", "/stats")
    r = conn.getresponse()
    d = json.loads(r.read())
    conn.close()
    return d


print("baseline:", stats())
for f in ("1", "8", "32", "64"):
    st, n, secs = probe("/opentelemetry", f"/tmp/pb{f}.pb")
    print(f"POST /opentelemetry  {n} bytes ({f}MiB-class) -> {st}  [{secs}s]")
    try:
        print("   stats:", stats())
    except Exception:
        print("   stats: UNREACHABLE (fixture process state after probe above)")

print()
for f in ("1", "8", "64"):
    st, n, secs = probe("/v1/traces", f"/tmp/pb{f}.pb")
    print(f"POST /v1/traces      {n} bytes ({f}MiB-class) -> {st}  [{secs}s]")
