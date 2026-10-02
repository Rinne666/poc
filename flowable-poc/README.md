# Flowable Engine — REST API proof-of-concept material

**Target** `modules/flowable-app-rest` (`flowable-rest.war`)
**Version** 8.1.0-SNAPSHOT
**Commit tested** `74fdb349c134e96e1f10592020ccca6e2e4b85f0` (clean worktree)
**Disclosure state** not yet reported to the vendor or any CNA — see `../README.md`
**CNA** not yet assigned. VulDB is the likely route; Flowable has not enabled GitHub private
vulnerability reporting and publishes no `SECURITY.md`, so there is no private channel to use.

All three findings below were reproduced against a locally built instance of the exact commit
above. Each is triggered by input from a caller holding only the ordinary `access-rest-api` role,
on a stock deployment, with no administrator action and no configuration change.

---

## Findings

| ID | Title | CWE | CVSS v3.1 | CVE |
|---|---|---|---|---|
| V1 | Repository deployment is authorized by the API-consumption role and reaches an unsandboxed Groovy script engine | CWE-94 | **8.8** (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) | *pending* |
| V2 | Caller-supplied bytes reach `ObjectInputStream.readObject()` on the runtime variable API | CWE-502 | **8.3** (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L) | *pending* |
| V3 | External-worker identity is a request-body string that the API discloses | CWE-639 | **8.3** (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H) | *pending* |

`PR:L` across all three is accurate and not a formality: each requires a credential holding
`access-rest-api`. That is the role integrators hand out most freely, because it is the minimum an
order system or notification service needs to drive workflow state.

---

## V1 — Deployment reaching an unsandboxed script engine

**A caller with the API-consumption role can upload a process definition containing a Groovy
`scriptTask` and obtain arbitrary code execution.**

`access-restapi` authorizes both ordinary API consumption and process deployment. The shipped
application depends on `flowable-groovy-script-static-engine` unconditionally, and the script engine
applies no sandbox. The deployment endpoint is therefore a write path into an interpreter, gated by
the wrong role.

The `scriptTask` element is a developer-facing extension point, but the **script content** is
supplied by the caller. That distinction is the whole finding: supporting scripting is a product
decision; letting any API user author scripts is an authorization error.

**Affected code**

- `modules/flowable-app-rest/src/main/resources/flowable-default.properties:62-63` — ships
  `rest-admin` / `test`; the bootstrap principal receives `access-rest-api` and `access-admin`
- `modules/flowable-app-rest/src/main/java/org/flowable/rest/conf/BootstrapConfiguration.java:104-113`
  — creates that principal on first start
- `modules/flowable-app-rest/src/main/java/org/flowable/rest/conf/SecurityConfiguration.java:84,88`
  — `anyRequest()` granted to `access-rest-api`; repository deployment endpoints fall under it
- `modules/flowable-rest/src/main/java/org/flowable/rest/service/api/repository/ProcessDefinitionDeploymentsResource.java`
  — the deployment endpoint
- `modules/flowable-groovy-script-static-engine/src/main/java/org/flowable/impl/scripting/GroovyStaticScriptEngine.java:66-78`
  — compiles and evaluates the uploaded script, unsandboxed
- `modules/flowable-app-rest/pom.xml` — depends on the Groovy engine unconditionally

**Observed** — deployment returned `201` as a principal holding only `access-rest-api`; the
uploaded script wrote `GROOVY_ARBITRARY_CODE_EXEC jvm=17.0.20.1 user=rinne` to disk. The same
principal was correctly refused `/actuator` and `/actuator/env` with `403`, so the authorization
boundary works — it is drawn in the wrong place. See `evidence/04-groovy-deploy-rce.txt`.

---

## V2 — Unfiltered deserialization of caller-supplied bytes

**A caller with the API-consumption role can cause the Flowable JVM to reconstruct an arbitrary named
class and run its `readObject()`.**

Runtime variable endpoints accept `type=serializable` and pass the uploaded bytes to a bare
`java.io.ObjectInputStream`. No `ObjectInputFilter` is installed. `SerializableType` overrides only
`resolveClass`, substituting `ReflectUtil.loadClass` — an unbounded loader. The only guard is a
boolean that defaults to `true` **in code**, not merely in the shipped properties.

**Affected code**

- `modules/flowable-rest/.../runtime/process/BaseExecutionVariableResource.java:162-165` —
  `new ObjectInputStream(file.getInputStream()).readObject()`
- `modules/flowable-rest/.../runtime/process/BaseExecutionVariableResource.java:70` —
  `env.getProperty("rest.variables.allow.serializable", Boolean.class, true)`
- `modules/flowable-rest/.../runtime/task/TaskVariableBaseResource.java:184-185,53` — same sink
- `modules/flowable-cmmn-rest/.../caze/BaseVariableResource.java:365-366,67` — same sink
- `modules/flowable-cmmn-rest/.../task/TaskVariableBaseResource.java:185-186,54` — same sink
- `modules/flowable-variable-service/.../types/SerializableType.java:194-198` — unbounded
  `resolveClass`
- `modules/flowable-app-rest/.../flowable-default.properties:57` — ships the property as `true`

### What is and is not demonstrated

Stated precisely, because it is the difference between 8.3 and 9.8:

- **Demonstrated** — arbitrary class instantiation and `readObject()` execution inside the Flowable
  JVM, reached from an ordinary caller's upload.
- **Not demonstrated** — end-to-end command execution. `commons-collections 3.2.2` is on the
  classpath but gates its own `InvokerTransformer`, and ysoserial `CommonsBeanutils1` and `Spring1`
  payloads were rejected by Tomcat's multipart parser (`Could not process multipart content`; root
  cause not diagnosed).

The realistic risk today is classpath reconnaissance and denial of service. The risk tomorrow is
different in kind: any dependency upgrade that introduces a usable gadget turns the same upload into
remote code execution with no further work by the attacker.

### Two points that strengthen the case

The permissive default exists **in code**, so deleting line 57 from the properties file does not
close the sink. And the **JSON** variable path already refuses this type outright
(`HTTP 400 — Variable 'poly2' has unsupported type: 'serializable'`), which shows the maintainers
already consider it unsafe in at least one path. That inconsistency is more likely to produce a fix
than a generic argument about deserialization.

See `evidence/03-deser-rce.txt`.

---

## V3 — External-worker identity is a replayable, disclosed string

**A caller with the API-consumption role can read another worker's identity and act as that worker.**

`AbstractExternalWorkerJobCmd` authorizes worker operations by comparing a `workerId` from the
request body against the job's `lockOwner`. That `workerId` is never bound to the authenticated
principal, and `GET /external-job-api/jobs/{jobId}` returns it to any authenticated caller. The
authorization check therefore reduces to a string the API will hand out.

**Affected code**

- `modules/flowable-job-service/.../cmd/AbstractExternalWorkerJobCmd.java:73` —
  `if (!Objects.equals(workerId, job.getLockOwner())) throw …`
- `modules/flowable-external-job-rest/.../acquire/ExternalWorkerAcquireJobResource.java:84,109,161,201,241`
  — `workerId` read from the request body on every operation
- `modules/flowable-external-job-rest/.../query/ExternalWorkerJobResource.java:47` —
  `GET /jobs/{jobId}` returns `lockOwner`
- `modules/flowable-external-job-rest/.../acquire/ExternalWorkerUnacquireJobResource.java:51-60,81`
  — bulk release with no per-job ownership check and no tenant scoping

**Observed** — a wrong `workerId` returns `403` on every operation; the impersonated value returned
`204` for all three, with the effects read back from the running engine:

| Operation | Effect observed |
|---|---|
| `complete` | process instance `endTime` written — the workflow advanced on a caller's assertion |
| `fail` | `retries 3→2`, lock cleared, `exceptionMessage` set to caller-supplied text |
| `unacquire` | `lockOwner` and `lockExpirationTime` cleared on a **non-expired** lock |
| `unacquire/jobs` (bulk) | two live locks released in one call, no worker credential presented |

**What this is not.** The check is per-job. Presenting worker A's identity on worker B's job is
correctly refused with `403` — that case was tested explicitly and is *not* the defect. The defect is
that the identity is neither secret nor bound to a principal, so a caller who can read a `jobId`
can act as that job's owner. An earlier draft of this document implied cross-job access; it was
wrong, and the PoC now demonstrates the accurate version with two distinct accounts.

### Why this matters beyond availability

In Flowable's external-worker model, `complete` does not mean "mark this task done" — it asserts
**"the event that was supposed to happen outside the engine has happened."** The engine has no other
source for that fact. Forging it means asserting something about the outside world that never
occurred, in the system whose purpose is to trust that assertion.

The audit consequence is larger than the operational one: every external-worker completion ever
recorded under that identity is of unknown provenance, and the scope cannot be bounded, because
the value was never a credential.

**Not measured:** the bulk endpoint's cross-tenant scope is read from source. This audit ran
single-tenant. Do not assert it as observed.

See `evidence/06-external-worker-impersonation.txt`.

---

## Reproducing

See `env/build-and-run.md`. In short:

```bash
# build the target from a clean checkout
mvn -B -Pdistro -pl modules/flowable-app-rest -am install -DskipTests
java -jar modules/flowable-app-rest/target/flowable-rest.war
```

> **The BPMN API is served under `/flowable-rest/service/`, not `/flowable-rest/process-api/`.**
> `flowable-default.properties:43` sets `flowable.process.servlet.path=/service`, overriding the
> servlet default. `/process-api/` returns `404`. This differs from Flowable's published
> documentation and will make reproduction fail if the documented path is used.

Then:

```bash
python3 poc/v1_deployment_rce.py            --base http://localhost:8080/flowable-rest --confirm-authorised
python3 poc/v2_serializable_deser.py        --base http://localhost:8080/flowable-rest --confirm-authorised
python3 poc/v3_worker_impersonation.py      --base http://localhost:8080/flowable-rest --confirm-authorised
```

Each script creates only what it needs, verifies its own precondition, prints the observed server
response, and exits non-zero if the finding does not reproduce.

---

## Files

| Path | Contents |
|---|---|
| `report.md` | full reproduction report with environment and expected output |
| `poc/` | one runnable script per finding |
| `cve/` | CVE JSON 5.1 records, `state: RESERVED`, `exploitability: PROOF_OF_CONCEPT` |
| `nuclei/` | detection-only templates |
| `env/` | build and run instructions, minimal payloads |
| `evidence/` | verbatim captured output behind every claim above |
