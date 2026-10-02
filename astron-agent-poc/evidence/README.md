# Evidence — provenance and redaction

These files back the claims in `../README.md` and `../report.md`.

**Provenance.** The outputs below were captured during the reporting sessions
(2026-09-30 through 2026-10-02) against the reporter's own local docker compose
deployment of `iflytek/astron-agent` at main commit
`b4f8ed57460cbfb32016a4afd3fd7212987d33c3` (release v1.1.2 additionally verified at
source level). No third-party deployment was touched.

**Redaction.** Application keys, secrets and JWTs are replaced with `<redacted>`.
Object identifiers local to the test deployment (flow id, event ids, file ids) are
retained: they are meaningless outside that deployment, and the V3 finding is
precisely that such identifiers are observable and replayable.

**Completeness.** These are session records, not full packet captures: raw HTTP
response payloads were not all retained verbatim. The runnable PoC scripts in
`../poc/` regenerate complete transcripts against your own authorised deployment —
per `../../CONTRIBUTING.md`, re-run them and keep the unedited output if you need
byte-exact evidence.
