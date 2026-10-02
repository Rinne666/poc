# Reproduction report — Flowable Engine 8.1.0-SNAPSHOT REST API

| | |
|---|---|
| **Product** | Flowable Engine, module `flowable-app-rest` (artifact `flowable-rest.war`) |
| **Version** | 8.1.0-SNAPSHOT |
| **Commit** | `74fdb349c134e96e1f10592020ccca6e2e4b85f0`, clean worktree, no local modifications |
| **Runtime** | Tomcat 11.0.21 · Spring Boot 4.1.0-RC1 · Spring Framework 7.0.7 · JDK 17.0.20.1 |
| **Platform** | macOS 26.5.2 (arm64), Maven 3.9.16 |
| **Build** | `mvn -B -Pdistro -pl modules/flowable-app-rest -am install -DskipTests` → BUILD SUCCESS, 95 modules, 03:21 |
| **Findings** | 3 — CWE-94 (CVSS 8.8), CWE-502 (CVSS 8.3), CWE-639 (CVSS 8.3) |
| **Disclosure** | Not yet reported to any vendor or CNA |

Every claim below was produced by running the proof scripts in `poc/` against the build described
above. Raw captured output is in `evidence/`.

---

## Common preconditions

All three findings require one credential holding `access-rest-api` and nothing else.

That privilege is created automatically on first start alongside `access-admin`, so it exists in
every default deployment, and it is grantable through the IDM API. It is the role integrators hand
out most freely, because it is the minimum an order system or notification service needs to drive
workflow state.

Each proof script provisions such an account, confirms it is refused by `/actuator` with `403`, uses
it for the exploit steps, and deletes it on exit.

**Reproduction warning.** The BPMN API is served under `/flowable-rest/service/`, not
`/flowable-rest/process-api/`. `flowable-default.properties:43` sets
`flowable.process.servlet.path=/service`, overriding the servlet default; the documented path
returns `404`. Discovery was done via `GET /actuator/mappings`, and all prefixes are listed in
`env/build-and-run.md`.

---

## V1 — Deployment privilege reaches an unsandboxed script engine (CWE-94, 8.8)

### Claim

A principal holding only `access-rest-api` can deploy a process definition containing a Groovy
`scriptTask` and obtain arbitrary code execution. The Groovy engine applies no sandbox.

### Affected code

- `modules/flowable-app-rest/src/main/resources/flowable-default.properties:62-63` — the bootstrap
  principal receives `access-rest-api` and `access-admin`
- `modules/flowable-app-rest/src/main/java/org/flowable/rest/conf/BootstrapConfiguration.java:104-113`
- `modules/flowable-app-rest/src/main/java/org/flowable/rest/conf/SecurityConfiguration.java:84,88`
  — `anyRequest()` granted to `access-rest-api`, which covers the deployment endpoints
- `modules/flowable-rest/src/main/java/org/flowable/rest/service/api/repository/ProcessDefinitionDeploymentsResource.java`
- `modules/flowable-groovy-script-static-engine/src/main/java/org/flowable/impl/scripting/GroovyStaticScriptEngine.java:66-78`
  — compiles and evaluates the uploaded script, unsandboxed
- `modules/flowable-app-rest/pom.xml` — the Groovy engine is an unconditional dependency

### Steps and observed result

```
== precondition ==
  acting as 'flowable-poc-v1-user' (must hold access-rest-api, not access-admin)
  GET /actuator              -> 403  (confirmed: no admin role)
  GET repository/deployments -> 200  (access-rest-api granted)

== step 1: deploy a definition containing an unsandboxed scriptTask ==
  POST /service/repository/deployments -> 201
  deploymentId = a7bdba0b-be3c-11f1-9ac2-6211d8ffd8b2

== step 2: start an instance (evaluates the uploaded script) ==
  POST /service/runtime/process-instances -> 201
```

Side effect on the target:

```
$ cat <java.io.tmpdir>/flowable-poc-v1.txt
V1-REACHABLE jvm=17.0.20.1 user=rinne
```

The uploaded script is `env/payloads/flowable-poc-v1-groovy.bpmn20.xml`, reproduced in full in the
proof script's docstring. It contains no network call, no process execution and no data access.

### Why the developer's scripting support is not a defence

`scriptTask` is a developer-facing extension point, but the **content** of the script is supplied
by the caller in the uploaded file. Supporting scripting is a product decision; exposing a write
path into the interpreter to the ordinary consumption role is an authorization error. The engine
being present by default is a contributing factor, not a required misconfiguration.

### Impact

Arbitrary Java code execution in the Flowable process, from a role an administrator would
reasonably believe is limited to consuming the API. The process holds the datasource credentials and
every process variable in the instance, and a workflow engine frequently holds in-flight business
state that no reporting system duplicates.

A second-order consequence specific to this product class: where the engine is the system of record
for approvals, a caller who can deploy definitions can deploy one that approves what should not be
approved. The forged approval is a well-formed record, so auditing the database does not reveal it.

### Remediation

1. A dedicated deployment privilege required for `POST`/`DELETE` on repository deployment endpoints.
   This removes the chain and is confined to the filter chain plus one bootstrap entry.
2. Remove the Groovy engine from default dependencies so script execution is opt-in.
3. Where it is present, apply a `SecureASTCustomizer` or a Groovy sandbox with an explicit policy.

Evidence: `evidence/04-groovy-deploy-rce.txt`

---

## V2 — Unfiltered deserialization of caller-supplied bytes (CWE-502, 8.3)

### Claim

The variable API accepts `type=serializable` and passes the uploaded bytes to a bare
`ObjectInputStream`, so a caller can cause the Flowable JVM to reconstruct an arbitrary named class
and run its `readObject()`. No `ObjectInputFilter` is installed.

### Affected code

- `modules/flowable-rest/.../runtime/process/BaseExecutionVariableResource.java:162-165` — the sink
- `modules/flowable-rest/.../runtime/process/BaseExecutionVariableResource.java:70` —
  `env.getProperty("rest.variables.allow.serializable", Boolean.class, true)`, **default true in code**
- `modules/flowable-rest/.../runtime/task/TaskVariableBaseResource.java:184-185,53` — same sink
- `modules/flowable-cmmn-rest/.../caze/BaseVariableResource.java:365-366,67` — same sink
- `modules/flowable-cmmn-rest/.../task/TaskVariableBaseResource.java:185-186,54` — same sink
- `modules/flowable-variable-service/.../types/SerializableType.java:194-198` — `resolveClass`
  override via `ReflectUtil.loadClass`, unbounded
- `modules/flowable-app-rest/.../flowable-default.properties:57`

### Steps and observed result

```
== precondition ==
  acting as 'flowable-poc-v2-user'
  GET /actuator -> 403
  processInstanceId = e76e328f-be3c-11f1-9ac2-6211d8ffd8b2   (oneTaskProcess, shipped demo definition)

== step 1: upload a java-serialization stream as type=serializable ==
  POST /service/runtime/process-instances/<id>/variables -> 201
  {"name": "flowable-poc-v2-var", "scope": "local", "type": "serializable", "value": null,
   "valueUrl": ".../variables/flowable-poc-v2-var/data"}

== step 2: read the variable back through the /data endpoint ==
  GET  .../variables/flowable-poc-v2-var/data -> 200
  Content-Type: application/x-java-serialized-object

== verdict ==
  Round trip is byte-identical (83 bytes in, 83 out).
```

### Why no gadget chain is needed to establish this

Flowable cannot store the variable without first calling `readObject()`: the reconstructed object
is what gets persisted, and the resulting variable type is decided by inspecting it. The `/data`
endpoint is only served after the object has been reconstructed and re-serialized. A 201 plus a
correct read-back is therefore the proof, and the payload is a serialization stream of
`java.util.ArrayList` containing one string.

### What was NOT demonstrated

Command execution. `commons-collections 3.2.2` is on the shipped classpath but gates its own
`InvokerTransformer`, and ysoserial `CommonsBeanutils1` and `Spring1` payloads were rejected by the
servlet container's multipart parser (`Could not process multipart content`, root cause not
diagnosed).

This is why the score is 8.3 rather than higher, and why the record describes a deserialization
primitive rather than an RCE. The realistic present impact is classpath reconnaissance and denial of
service. The risk is that a later dependency upgrade introducing a usable gadget converts the same
upload into remote code execution with no further work by an attacker.

### An observation worth passing to the maintainers

A serialized `java.lang.String` is also accepted, but the response comes back as
`{"type":"string"}` — Flowable reclassifies the reconstructed object via its `StringType`, so no
`/data` endpoint is offered. That is not a mitigation: it does not apply to any class that is not a
first-class Flowable variable type, as the `ArrayList` result shows. It does show that the JSON
variable path already refuses this type outright with `HTTP 400 Variable ... has unsupported type:
'serializable'`, which makes the multipart permissiveness look like an inconsistency rather than a
design choice.

### Remediation

1. Default `rest.variables.allow.serializable` to `false` **in code**, and remove the shipped
   property.
2. Install an explicit JEP 290 `ObjectInputFilter` allow list.
3. Remove the `resolveClass` override so `ReflectUtil.loadClass` cannot resolve arbitrary names.

Evidence: `evidence/03-deser-rce.txt`

---

## V3 — External-worker identity is a disclosed, replayable string (CWE-639, 8.3)

### Claim

External-worker operations are authorized by comparing a request-body `workerId` against the job's
`lockOwner`. That value is never bound to the authenticated principal, and
`GET /external-job-api/jobs/{jobId}` returns it to any authenticated caller. A caller who can read a
job identifier can therefore act as that job's owner.

### Affected code

- `modules/flowable-job-service/.../cmd/AbstractExternalWorkerJobCmd.java:73` —
  `if (!Objects.equals(workerId, job.getLockOwner())) throw …`
- `modules/flowable-external-job-rest/.../acquire/ExternalWorkerAcquireJobResource.java:84,109,161,201,241`
  — `workerId` read from the request body on every operation
- `modules/flowable-external-job-rest/.../query/ExternalWorkerJobResource.java:47` — returns `lockOwner`
- `modules/flowable-external-job-rest/.../acquire/ExternalWorkerUnacquireJobResource.java:51-60,81`
  — bulk release, no per-job ownership check, no tenant scoping

### Steps and observed result

```
== precondition ==
  setup account 'rest-admin': GET /actuator -> 200
  attacker account 'flowable-poc-v3-user': GET /actuator -> 403

== step 1: two workers acquire one job each ==
  flowable-poc-v3-workerA holds 3719b4d2-...
  flowable-poc-v3-workerB holds 371a9f3a-...

== step 2: the job resource discloses the worker's identity ==
  GET /external-job-api/jobs/371a9f3a... -> 200
  lockOwner = 'flowable-poc-v3-workerB'   <- the only credential the API ever checks
  same path unauthenticated -> 401

== step 3: control — an identity that holds no lock is refused ==
  complete 371a3fa... as flowable-poc-v3-outsider -> 403
    {"message":"Forbidden","exception":"... does not hold a lock on the requested job"}

== step 4: a different account replays the disclosed string ==
  account 'flowable-poc-v3-user' has never acquired 371a9f3a..., has no worker
  credential, and has no relationship to 'flowable-poc-v3-workerB'.
  complete 371a9f3a... as 'flowable-poc-v3-workerB' -> 204
  accepted.
```

### Scope, stated precisely

The check is per-job. Presenting worker A's identity on worker B's job is correctly refused with
`403`; that case was tested and is **not** the defect. The defect is that the identity is neither
secret nor bound to a principal.

An earlier draft of this material described cross-job impersonation. That was wrong, and it is
corrected here and in the proof script.

Also not measured: the bulk endpoint's cross-tenant scope is read from source. Testing was
single-tenant, and this report does not claim otherwise.

### Impact

In Flowable's external-worker model a `complete` call does not mean "mark this task done". It asserts
that the event which was supposed to happen outside the engine has happened, and the engine has no
other source for that fact. For a payment integration, "the charge settled"; for a provisioning
integration, "the account was created". Forging it asserts something about the outside world that
never occurred, in the system whose purpose is to trust that assertion.

The audit consequence exceeds the operational one. Every external-worker completion recorded under
that identity is of unknown provenance, and the scope cannot be bounded, because the value was never
a credential.

`fail` and `unacquire` are repeatable denial-of-service primitives: `fail` burns retries and sets a
caller-supplied `exceptionMessage` that may surface in operational tooling, and `unacquire` clears a
lock that has not expired.

### Remediation

1. Mint a per-worker secret at acquire time, store it with the lock, require it on complete/fail/unacquire.
2. Or bind worker identity to the authenticated principal, so two credentials cannot be one worker.
3. Stop returning `lockOwner` to non-owners.
4. Apply the per-job ownership check to bulk unacquire; require admin when no tenant is given.

Evidence: `evidence/06-external-worker-impersonation.txt`

---

## Common structure

Three findings, one pattern: **a value that is not a credential is being used as one, or a privilege
is doing two jobs.**

| | Trusted as | Actually |
|---|---|---|
| V1 | `access-rest-api` means "consume the API" | also "write code the server executes" |
| V2 | `type=serializable` is a variable type | is an instruction to reconstruct an arbitrary class |
| V3 | `workerId` identifies a worker | is a request-body string the API discloses |

The fixes are structural for this reason: split the privilege, treat the type as untrusted input,
bind the identity to something the caller cannot choose and others cannot read.

## Exploitability tier

All three are filed as **Proof-of-Concept**, per VulDB's definition of that tier — a simple exploit
illustrating basic functionality, without productionised reliability or customisation. The published
proof scripts write at most one marker file, create only objects they name `flowable-poc-*`, and
delete the temporary account they create. None contains a reverse shell, a data export, a
persistence mechanism or a bundled gadget chain.
