# Astron Agent — proof-of-concept material

**Target** [`iflytek/astron-agent`](https://github.com/iflytek/astron-agent) — agentic
workflow platform (Console backend, workflow engine, core-database service)
**Version** release `v1.1.2` and `main`
**Commit tested** `b4f8ed57460cbfb32016a4afd3fd7212987d33c3` (clean checkout, unmodified stock docker compose stack; one image override pinning `minio` to a locally available image)
**Disclosure state** **not yet reported** to iFlytek or any CNA. The GHSA drafts are
being prepared; VulDB is the CNA route — see `../README.md`. The `cve/*.cve.json`
files carry `CVE-PENDING-*` identifiers and `state: RESERVED`; no CVE number has
been allocated.

> **If you run astron-agent, treat these as live.** The maintainers have not been
> notified yet, so there is no fix to wait for. Interim mitigations are listed per
> finding below and are deployment-level: none of them is a code fix.

All three findings were reproduced against the reporter's own local deployment of
the exact commit above. Each is triggered by input an ordinary end user of the
platform supplies through its stock APIs, on the stock deployment, with no
administrator action and no configuration change.

---

## Findings

| ID | Title | CWE | CVSS v3.1 | CVE |
|---|---|---|---|---|
| V1 | `core-database` DDL whitelist is bypassed with a comment containing an allowlisted keyword (unauthenticated route) | CWE-184 | **6.3** (AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L) | *pending* |
| V2 | Console skips knowledge-file ownership checks when the client supplies a `space-id` header | CWE-639 | **6.5** (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) | *pending* |
| V3 | `/workflow/v1/resume` accepts a paused event from an authenticated caller whose app does not own it | CWE-639 | **6.8** (AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N) | *pending* |

The privilege each finding requires:

- **V1 — no privilege.** The `/xingchen-db/v1/*` routers are mounted with no request
  authentication (`core/memory/database/main.py:114`). That is the shipped default.
  Reachability is deployment-qualified: the stock compose/Helm files do not publish
  port 7990, so the realistic surface is peers on the internal cluster network or
  deployments that publish the port. Hence `AV:A`, not `AV:N`.
- **V2 — any authenticated Console user.** A normal low-privilege session JWT is the
  only credential. That is the platform's default end-user role.
- **V3 — any registered app owner.** The caller needs *its own* valid Bearer
  credential plus the target `event_id` during the pause window — two simultaneous
  prerequisites, hence `AC:H`.

---

## V1 — DDL whitelist bypass via comment smuggling

**A peer with no credentials can get a rejected PostgreSQL command executed by the
core-database service, because the whitelist greps the raw SQL string for an
allowlisted keyword and any comment can supply one.**

The `exec_ddl` endpoint enforces a whitelist of DDL statement kinds. For statements
SQLGlot 26.29.0 models as `exp.Command` — `CREATE EXTENSION` among them — the
whitelist decides the statement type by searching the original SQL string:

```python
# core/memory/database/api/v1/exec_ddl.py:60-80
elif isinstance(parsed, Command):
    match = re.search(r"\bALTER\s+TABLE\b", sql, re.IGNORECASE)   # line 71
    if match:
        full_type = match.group(0).upper()      # "ALTER TABLE"
```

The regex matches against the raw string, not the AST. A comment containing
`ALTER TABLE` satisfies the guard while the statement remains the rejected command:

```sql
/* ALTER TABLE */ CREATE EXTENSION IF NOT EXISTS dblink
```

SQLGlot 26.29.0 parses `CREATE EXTENSION` to `exp.Command` (`.key` is the literal
`"command"`, so a bare statement is correctly rejected) and preserves the comment
when re-serializing — so the smuggled command passes validation and executes. The
service connects as the compose-shipped `spark` role, which the official postgres
image creates as a superuser.

**Affected code**

- `core/memory/database/api/v1/exec_ddl.py:60-80` — the Command branch greps raw SQL
- `core/memory/database/main.py:114` — routers mounted with no auth dependency
- `core/memory/database/uv.lock:1916` — sqlglot pinned at 26.29.0
- `docker/astronAgent/docker-compose.yaml:145` — superuser connection role (stock)

**Observed** — the bare statement was rejected with code 25040; the identical
statement behind the comment was accepted and `dblink` was installed in the
caller's own test database. See `evidence/01-ddl-whitelist-bypass.txt`.

**What was NOT demonstrated** — file reading, cross-schema access and host-level
code execution through this path. Not claimed. The demonstrated effect is
extension installation in a caller-created test database.

**Remediation**

1. Reject any `exp.Command` node outright; accept only `Create`/`Alter`/`Drop`
   nodes of a known kind. Never fall back to `re.search` over the raw string.
2. Strip comments before the whitelist check — comments are not statements.
3. Run the database role with least privilege and authenticate the routers.

---

## V2 — cross-user knowledge-file read via the space-id header

**An ordinary authenticated Console user can read the knowledge records of a file
owned by another user or space, by adding any numeric `space-id` header to the
request.**

The knowledge-list endpoint authorises each requested file only when the
client-supplied header is absent or unparseable:

```java
// console/backend/toolkit/.../FileInfoV2Service.java:903-930
Long spaceId = SpaceInfoUtil.getSpaceId();      // parses the client header
...
if (null == spaceId) {
    dataPermissionCheckTool.checkFileBelong(fileInfoV2);    // skipped otherwise
}
```

`SpaceInfoUtil.getSpaceId()` (`commons/.../SpaceInfoUtil.java:64-72`) returns
whatever `Long.parseLong(header)` accepts. Any parseable value — the victim's real
space id is *not* needed — suppresses the ownership check for every file id in the
request.

**Affected code**

- `console/backend/commons/.../SpaceInfoUtil.java:64-72` — header parsed as-is
- `console/backend/toolkit/.../FileInfoV2Service.java:903-930` — conditional skip
- `console/backend/toolkit/.../FileController.java:205-207` — the endpoint
- `console/backend/.../SecurityConfig.java:124-126` — session auth still required
  (this is object-level authorization, not an authentication bypass)

**Observed** — with two ordinary test users, the unrelated user received no records
for the victim's file without the header and received the file's knowledge records
with `space-id: 1`. Read-only differential, two requests. See
`evidence/02-console-space-id-bypass.txt`.

**What was NOT demonstrated** — cross-tenant write, delete or availability impact
on this endpoint. Not claimed.

**Impact** — confidentiality of knowledge content across users/spaces. Who is
exposed: every deployment whose Console API is reachable by low-privilege users,
which is the product's normal posture.

**Remediation** — authorize every requested file id against the authenticated user
unconditionally; if a request carries a space, verify membership server-side first.

---

## V3 — `/workflow/v1/resume` does not bind the paused event to the caller's app

**A second, unrelated application can resume someone else's paused workflow event
with content of its choosing, and receives the post-resume output on its own
connection.**

The endpoint **is** authenticated — it is in `CHAT_OPEN_API_PATHS` and the
middleware verifies the Bearer credential or the trusted gateway signature. The
defect is downstream:

```python
# core/workflow/api/v1/chat/open.py:106-165  (resume_open)
event = EventRegistry().get_event(event_id=event_id)
...
await EventRegistry().write_resume_data(...)    # no ownership check
```

The event record holds the owning `app_id`; the handler never compares it to the
authenticated caller's app. `event_id` is a Snowflake id
(`core/common/utils/snowfake.py:12`) that the platform itself discloses — most
directly in the INTERRUPT frame of the owner's own SSE stream when the flow pauses.

**Observed** — with two separately registered apps on a local deployment: the
victim app's flow paused at a question-answer node; the attacker app (different
`app_id`, its own valid credential) resumed the event and the engine consumed the
injected content as the node's answer; the post-resume output flowed on the
attacker's connection, not the victim's. Reproduced on both the debug path and the
production path. See `evidence/03-workflow-resume-authz.txt`.

**What this is NOT** — not an authentication bypass: an invalid Bearer is rejected
by the middleware before the handler. Events outside INTERRUPT status are not
reachable. Availability impact is not claimed.

**What was NOT demonstrated** — an exhaustive enumeration of every channel through
which a remote attacker can learn `event_id`. The owner's SSE frame is one
documented channel; server logs, OTel traces and cross-service Kafka echoes are
plausible others, noted in the report but not all separately exercised.

**Impact** — integrity: attacker-chosen content enters the victim's paused workflow
(a human-approval step answered by an attacker's assertion). Confidentiality:
post-resume node output is delivered to the attacker.

**Remediation** — in `resume_open`, compare the middleware-trusted caller
`app_id` with `event.app_id` and reject mismatches; log every resume attempt with
both; audit other by-id handlers for the same pattern.

---

## Reproducing

See `env/build-and-run.md`. In short, from inside the compose network:

```bash
python3 poc/v1_ddl_whitelist_comment_smuggling.py --base http://core-database:7990 --confirm-authorised
python3 poc/v2_knowledge_space_id_bypass.py --base http://<console-api> --jwt "$JWT" --victim-file-id 9001 --confirm-authorised
python3 poc/v3_workflow_resume_event_authz.py --base http://core-workflow:7880 \
    --victim-credential "$VK:$VS" --attacker-credential "$AK:$AS" \
    --flow-id <seeded id> --confirm-authorised
```

Each script refuses to run without `--confirm-authorised`, verifies its own
preconditions, prints the observed responses, and exits non-zero if the finding
does not reproduce. V1 cleans up after itself; V2 is read-only; V3 creates one
expiring chat event.

---

## Files

| Path | Contents |
|---|---|
| `report.md` | full reproduction report with environment and expected output |
| `poc/` | one runnable script per finding |
| `cve/` | CVE JSON 5.1 records, `state: RESERVED`, `exploitability: PROOF_OF_CONCEPT` |
| `nuclei/` | detection-only templates (fingerprint the precondition; they do not exploit) |
| `env/` | build and run instructions, victim-flow seed |
| `evidence/` | session records backing every claim above (redacted; see `evidence/README.md`) |
