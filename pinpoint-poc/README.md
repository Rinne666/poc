# pinpoint-poc — Pinpoint APM web findings

**Product:** [pinpoint-apm/pinpoint](https://github.com/pinpoint-apm/pinpoint) (Pinpoint APM)
**Tested:** source `282c9a6523e90088ebdc2231dfaf0daa8aa0103d` (4.0.1-SNAPSHOT, master, 2026-11-05) against runtime images `pinpointdocker/pinpoint-web:4.0.0` / `pinpoint-collector:4.0.0` in a local Docker lab (Docker Desktop, linux/arm64 VM).
**Disclosure:** `NOT_REPORTED` — vendor not yet contacted as of this submission. **This project is not yet approved for public pull requests**; it is staged here for the private-vendor-contact workflow (see root README policy).

## Findings

| ID | Title | Class | Proof level | CVSS 3.1 |
|---|---|---|---|---|
| F1 | Web actuator `show-values: always` lets any ROLE_USER read the JWT signing secret and admin password; stolen HMAC secret enables offline `pinpointJwt` forgery and ROLE_ADMIN escalation on `/api/admin/**` | CWE-200 → privilege escalation | RUNTIME_VERIFIED | 8.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`) |
| F2 | Error pages disclose full internal stack traces to unauthenticated callers (shipped `server.error.include-*: always` + in-repo `@ControllerAdvice` on the permitAll `/api-public/error` path) | CWE-209 | RUNTIME_VERIFIED | 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| F3 | Collector serves `/monitor` actuator (env/configprops `show-values: always`, writable loggers) on its main HTTP port with no authentication, while the same application password-gates `/admin/**` on the same port | CWE-306 → credential disclosure + runtime config write | RUNTIME_VERIFIED | 8.2 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L`) |
| F4 | OTLP metric endpoint `POST /opentelemetry` buffers/parses unbounded unauthenticated request bodies, unlike sibling `/v1/traces` and `/v1/logs` which carry a 4 MiB / 256 MiB / 64-request admission budget | CWE-770 → availability | RUNTIME_VERIFIED (released-artifact fixture, storage stubbed) | 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) |

F1/F2 are runtime-verified against the official 4.0.0 web image with the vendor-documented `basicLogin` mode; F3 against the official 4.0.0 collector image; F4 against a fixture assembled from the released 4.0.0-metric artifacts (recipe in `env/fixture-c8/`). All with otherwise stock configuration. No administrator misconfiguration is required: the actuator disclosure knobs and the missing `/monitor` authorization rule are shipped defaults.

F3/F4 were initially recorded as deployment-facing observations outside this project's scope (the collector HTTP port is an internal surface); on 2026-11-06 the maintainer revised that decision — the shipped defaults plus the in-repo divergence (gated `/admin/**` vs ungated `/monitor/**`; budgeted `/v1/traces` vs unbudgeted `/opentelemetry`) make them product findings, and they are claimed here as F3/F4. The collector `/channelz` unauthenticated diagnostics surface remains a recorded observation for the vendor notification rather than a separate finding in this project.

## Files

- `submission.json` — canonical metadata (source of truth for findings, evidence paths, disclosure state)
- `report.md` — step-by-step reproduction with positive/negative controls and exact observed output
- `poc/` — two non-interactive Python scripts; both refuse to run without `--confirm-authorised`, are bounded to loopback, non-destructive, and exit non-zero if the claimed observation is absent
- `evidence/` — raw sanitized command output captured during the lab run (dummy values planted by us; no real credentials involved anywhere)
- `env/` — the exact Docker compose lab and setup/teardown instructions

## Why this is publishable material

All PoC traffic went to a local Docker lab the researcher owns. Every planted secret is a dummy value (`VERIFY-…`, `verify-…`); nothing real is disclosed by publishing this. The PoCs demonstrate reachability only — e.g. F1 forges a token whose only privileged use is a single read-only authenticated GET, and F2 only fetches the framework's own 404 handler output.

## Remediation sketch (for the vendor)

1. Set `management.endpoint.env/configprops.show-values: never` (or `when-authorized` with a dedicated role) and remove `env`/`configprops`/`loggers` from the default exposure list.
2. Add a `/monitor/**` authorization rule (or bind the management server to loopback by default).
3. Ship `server.error.include-*: never` for the release profile.
4. Consider binding the JWT to a server-side session/nonce or shortening the 12-hour fixed expiry.
