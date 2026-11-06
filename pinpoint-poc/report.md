# Report — pinpoint-poc findings F1, F2

## Environment (exact)

- Host: Apple Silicon (arm64) macOS, Docker Desktop 29.6.2, VM linux/arm64, Docker Compose v5.3.1.
- Images: `pinpointdocker/pinpoint-web:4.0.0`, `pinpointdocker/pinpoint-collector:4.0.0`, `mysql:8.0`, `zookeeper:3.8`, `redis:7`, `pinpointdocker/pinpoint-hbase:4.0.0` (HBase was NOT healthy — see Limitations; its absence does not affect either finding).
- Source under test: pinpoint-apm/pinpoint commit `282c9a6523e90088ebdc2231dfaf0daa8aa0103d` (master, 4.0.1-SNAPSHOT, clean shallow checkout, unmodified except fetching the `grpc-idl` submodule which is not part of the tested path).
- Web app launched with the vendor-documented basic-login mode and otherwise stock configuration, via environment only:
  `JAVA_TOOL_OPTIONS=-Dpinpoint.modules.web.login=basicLogin -Dweb.security.auth.user=verifyuser:verifypw -Dweb.security.auth.admin=verifyadmin:verifyadminpw -Dweb.security.auth.jwt.secretkey=VERIFY-DUMMY-SECRET-KEY-0123456789abcdef -Dadmin.password=verify-admin-pw`
  All values are dummy values planted by the researcher; no real credential appears anywhere in this project.
- Ports as mapped in the lab: web main `18080->8080`, web management `18443->8443`, collector `8081`.

Rebuild the lab with `env/` (compose file + setup/teardown scripts).

---

## F1 — actuator config disclosure → JWT forgery → ROLE_ADMIN escalation (RUNTIME_VERIFIED)

### Expected security boundary

Only ROLE_ADMIN may use `/api/admin/**` (Spring Security rule in `basic-login/src/main/java/com/navercorp/pinpoint/login/basic/PinpointBasicLoginConfig.java`, line 84, plus the separate `admin.password` interceptor). The JWT signing key (`web.security.auth.jwt.secretkey`) is the credential that mints `pinpointJwt` login cookies and must be readable by nobody but the operator. The actuator environment endpoint must never return secret property values.

### Step-by-step reproduction

All commands were run from the lab host. The exact session is in `evidence/`.

1. **Anonymous management-port check (negative control):**
   `curl -s -o /dev/null -w "%{http_code}" http://localhost:18443/monitor/env`
   → `302` (redirect to `/login`). The basic-login filter chain does cover the 8443 management server; anonymous access is rejected.
2. **ROLE_USER login (positive setup):**
   `curl -s -c cookies.txt -X POST http://localhost:18080/login -d "username=verifyuser&password=verifypw"` → `302`, cookie jar contains `pinpointJwt`.
3. **Read the environment (the disclosure):**
   `curl -s -b cookies.txt http://localhost:18443/monitor/env -o env.json` → HTTP 200, 34,728 bytes.
   `grep -c` for each planted dummy value in `env.json`:
   - `VERIFY-DUMMY-SECRET-KEY-0123456789abcdef` → present (property `web.security.auth.jwt.secretkey`, also under `JAVA_OPTS`/`JAVA_TOOL_OPTIONS`)
   - `verifyuser:verifypw` → present (`web.security.auth.user`)
   - `verifyadmin:verifyadminpw` → present (`web.security.auth.admin`)
   - `verify-admin-pw` → present (`admin.password`)
4. **Forge an admin token offline** (no traffic to the target): standard HS256 JWT with header `{"alg":"HS256"}`, payload `{"userId":"verifyadmin","userRole":["ROLE_ADMIN"],"iat":<now>,"exp":<now+3600>}`, HMAC-SHA256 over the stolen secret. This mirrors exactly what `JwtService.createToken` mints (jjwt 0.12.3, HS256, claims `userId` and `userRole`; note the server ignores the `userRole` claim and re-derives roles from the in-memory user map — which is why the forged `userId` must be an existing admin username, `verifyadmin`).
5. **Differential authorization probe (the escalation):**
   `GET /api/admin/agentIdMap?password=verify-admin-pw` with three cookies:
   | Cookie | Result |
   |---|---|
   | none | `302` (authentication rejected) |
   | real ROLE_USER cookie (from step 2) | `403` (authenticated, authorization denied) |
   | forged ADMIN cookie (step 4) | `500` (authenticated **and** authorized — the chain passed and the HBase-degraded handler errored; on a healthy backend this route returns 200) |
   The escalation step in `poc/poc_f1_actuator_jwt_forgery.py` additionally proves authorization end-to-end against the management server: the forged ADMIN cookie reads `/monitor/env` with HTTP 200 where the anonymous request is redirected (302).

### Observed impact (bounded)

- ROLE_USER → ROLE_ADMIN escalation: the forged cookie passed the `/api/admin/**` authorization that a real ROLE_USER cookie fails with 403.
- The stolen secret mints tokens for any existing username for the fixed 12-hour expiry; logout deletes only the client cookie (no server-side revocation in source).
- The same env payload disclosed `admin.password` (the second gate on `/api/admin`).

### Not demonstrated

- No destructive admin operation was executed; the escalation proof uses one read-only authenticated route whose authorization outcome differs by cookie (302/403/200).
- Only the 4.0.0 Docker images and source master commit were tested; no released-version sweep was performed.
- Two earlier probe runs (superseded) produced misleading "200" results for forged tokens: an early PoC draft omitted the `pinpointJwt=` cookie-name prefix and followed redirects, so those 200s were the SPA fallback after a 302. The final PoC uses raw `http.client`, never follows redirects, and prefixes the cookie name; the `evidence/f1-flap-note.txt` file records a separate transient 302-flap observed under lab load. Readers should rely only on the final PoC output.
- Exploitation was confined to the local lab.

### Remediation sketch

`management.endpoint.env/configprops.show-values: never` (or `when-authorized` against a dedicated operator role); drop `env`/`configprops`/`loggers` from the default exposure include; add a `/monitor/**` rule to the basic-login chain; rotate-the-secret guidance for operators (the leaked value alone is game over for the cookie scheme until rotated).

---

## F2 — unauthenticated full stack-trace disclosure on `/api-public/error` (RUNTIME_VERIFIED)

### Expected security boundary

Error responses for the release profile must not include internal exception classes, messages, or stack traces (`server.error.include-*` Spring Boot knobs exist precisely to gate this), and the in-repo `@ControllerAdvice` (`web/src/main/java/com/navercorp/pinpoint/web/problem/CustomExceptionHandler.java`, registered by `ProblemSpringWebConfig`) must not attach traces when the knob is off. Shipped configuration turns every knob to "always" and maps the error page onto the `permitAll` path `/api-public/error`.

### Step-by-step reproduction

1. `curl -s http://localhost:18080/api-public/error` (no cookie) → HTTP 200, RFC 7807 JSON.
2. The body's `trace` property contains a full Java stack trace (60+ frames observed): `org.springframework.web.servlet.resource.ResourceHttpRequestHandler.handleRequest(...)`, the entire Spring Security `FilterChainProxy` chain including `com.navercorp.pinpoint.login.basic.service.JwtRequestFilter` and `PreAuthenticationCheckFilter`, Tomcat internals down to `java.base/java.lang.Thread.run`. The `parameters`, `method` and `hostname` properties echo request data and the container hostname.
3. No authentication was presented at any point.

### Observed impact (bounded)

Unauthenticated reconnaissance value: internal package structure, security-filter layout, framework/library versions. No business-data disclosure was observed on this path.

### Not demonstrated

- The knob-off negative control (setting `include-stacktrace: never` and re-requesting) was not executed in the lab; the knob's effect is Spring Boot's documented `ErrorAttributes` behavior plus the in-repo `CustomExceptionHandler.addStackTraces` source.
- Exception-carrying endpoints (e.g. HBase storage failures surfacing raw `e.getMessage()` via `AdminController`) could not be triggered because HBase did not start in this lab (upstream image deadlock, see Limitations). Only the framework-level 404 handler output was captured.
- No released-version sweep.

---

## Limitations of the whole lab run

- `pinpointdocker/pinpoint-hbase:4.0.0` HMaster deadlocks during `RegionOpenAndInit-TraceV2` region creation on linux/arm64 (log freezes mid-initialization with the process alive; reproduced across three restarts, with `HBASE_HEAPSIZE=1500` + G1GC). Consequences: the collector could not run its realtime command service (it binds `EmptyCommandService` when HBase-dependent startup fails), so the collector-side observations recorded in the audit (actuator env disclosure, `/channelz`, log-level write) were captured against a collector started before HBase finalized; they are deployment-facing observations and are excluded from this project's findings per the repository scope filter.
- The web findings above do not depend on HBase.
- Only loopback-mapped ports were used; no third-party or shared target was touched.
