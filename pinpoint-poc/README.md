# pinpoint-poc — Pinpoint APM web findings

**Product:** [pinpoint-apm/pinpoint](https://github.com/pinpoint-apm/pinpoint) (Pinpoint APM)
**Tested:** source `282c9a6523e90088ebdc2231dfaf0daa8aa0103d` (4.0.1-SNAPSHOT, master, 2026-11-05) against runtime images `pinpointdocker/pinpoint-web:4.0.0` / `pinpoint-collector:4.0.0` in a local Docker lab (Docker Desktop, linux/arm64 VM).
**Disclosure:** `NOT_REPORTED` — vendor not yet contacted as of this submission. **This project is not yet approved for public pull requests**; it is staged here for the private-vendor-contact workflow (see root README policy).

## Findings

| ID | Title | Class | Proof level | CVSS 3.1 |
|---|---|---|---|---|
| F1 | Web actuator `show-values: always` lets any ROLE_USER read the JWT signing secret and admin password; stolen HMAC secret enables offline `pinpointJwt` forgery and ROLE_ADMIN escalation on `/api/admin/**` | CWE-200 → privilege escalation | RUNTIME_VERIFIED | 8.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`) |
| F2 | Error pages disclose full internal stack traces to unauthenticated callers (shipped `server.error.include-*: always` + in-repo `@ControllerAdvice` on the permitAll `/api-public/error` path) | CWE-209 | RUNTIME_VERIFIED | 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |

Both findings are runtime-verified against the official 4.0.0 Docker images with the vendor-documented `basicLogin` mode enabled and otherwise stock configuration. No administrator misconfiguration is required: the actuator disclosure knobs and the missing `/monitor` authorization rule are shipped defaults.

**Out of scope for this project (recorded for the vendor, not claimed here):** collector-side `/monitor` actuator and `/channelz` diagnostics endpoints serve environment and live socket data without authentication; these depend on the operator exposing the collector HTTP port to an untrusted network, so per this repository's scope filter they are deployment-facing observations rather than product findings. They will be included in the vendor notification.

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
