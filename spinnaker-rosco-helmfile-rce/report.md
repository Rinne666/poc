# Report — RCE on rosco pods via helmfile `hooks`/`postRenderers` in baked artifacts

Companion to [`README.md`](README.md). Everything marked **measured** was executed against a live
stack and the raw output is in `evidence/`, unedited. Everything else is labelled as source
inspection and cites the file and line. The distinction is kept deliberately: a reader should be
able to tell which claims are observations and which are readings of code.

| | |
|---|---|
| **Package** | `io.spinnaker.rosco:rosco-manifests` (Maven) |
| **Affected** | all released versions through **2026.3.0** (2026-09-07) |
| **Fixed** | **rosco-2026.3.1** (2026-09-24, commit `3567b1c`) |
| **CWE** | CWE-78 (primary), CWE-693 |
| **CVSS v3.1** | **9.0** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (see [Correction](#correction-cvss-was-88-in-the-first-filed-advisory)) |
| **Disclosure** | reported to `security@spinnaker.io`; fixed in the release above |

---

## 1. Environment

Everything below was run on:

| Component | Version |
|---|---|
| rosco | `rosco:main-latest`, built 2026-09-19 — **carries the #8015 guard** |
| helmfile | 1.7.0 |
| helm | helm3 via `--helm-binary helm3` (rosco's default) |
| Stack | 10 containers: deck, gate, orca, rosco, clouddriver, front50, echo + redis, mysql, attacker |
| Driver OS | Linux host, docker compose |

The running service had the guard. That is deliberate: the released versions are *easier* to trigger
(§4.1), and testing the harder branch is what surfaced the gaps the vendor then closed.

`helm` matters. rosco's image ships Helm **2.17.0**; had `--helm-binary` selected that build,
helmfile fails at the Tiller check **before** any hook runs, and the payload would look like a
rejection. Every result here is with helm3.

## 2. Root cause

rosco implements `templateRenderer: HELMFILE` by writing the input artifacts to a temp directory and
exec'ing `helmfile template --file <path>` (`HelmfileTemplateUtils.buildCommand`). The `helmfile.yaml`
it parses is **caller-supplied input**, and helmfile honours two features that execute local
commands from that file even under `template`:

| Feature | Fires |
|---|---|
| `hooks:` with `events: ["prepare"]` | before rendering — **measured** |
| `hooks:` with `events: ["cleanup"]` | after rendering — *not exercised in this stack* |
| `helmDefaults.args` containing `--post-renderer=` | during helm rendering — **measured** |

`helmfile template` is documented and understood as a read-only operation. It is not one, and that
gap is the whole finding.

**A failing bake is not a mitigation.** With a `hooks:` entry and no renderable release,
`helmfile template` exits `3` — but `prepare` has already run and its side effect is already on
disk. **measured**: in every A/B below the payload response was `HTTP=200` *and* the marker was
present; in the release-version case a bake can be red with the hook still executed.

## 3. Two roles

| Role | Owns | Controls |
|---|---|---|
| **A — artifact author** | one URL, branch or registry path | the bytes rosco parses |
| **B — pipeline author** | Spinnaker pipeline write access | which artifact a bake stage references |

Role A needs **no Spinnaker credential**. The realistic trigger is therefore not an attacker action
at all: the attacker edits a file they already control, and the victim's next ordinary pipeline run
fires it. §4.2 demonstrates exactly that.

## 4. Reproduction

### 4.1 Service level — the guard fails open

Shortest path: rosco's own API, skipping gate/orca entirely. In a real deployment rosco is not
internet-facing, so this is "already inside the cluster".

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data @control.json \
  http://<rosco>:8087/api/v2/manifest/bake/HELMFILE
```

**Control** — parseable, `hooks:` in the entry file. The guard should reject:

```
HTTP=400 bytes=569
{"status":400,"exception":"java.lang.IllegalArgumentException",
 "message":"The helmfile content at /tmp/rosco-.../fdd2c6d1-... declares `hooks`, which helmfile
 executes as an arbitrary local com..."
  [ok] no marker - hook did not run
```

**Payload** — same hook, plus one value nested past 50 levels:

```
HTTP=200 bytes=249
  [!!] COMMAND EXECUTED - marker present:
      === F-01 rosco helmfile hook executed ===
      uid=10111(spinnaker) gid=10111(spinnaker) groups=10111(spinnaker),10111(spinnaker)
      44c48ade52c2
      cwd=/tmp/rosco-18318496637419916271
```

Raw: `evidence/01-service-level-ab.txt`.

**Why.** The guard parses with SnakeYAML at `nestingDepthLimit=50`. Past that depth `load()` throws
`YAMLException`, and the `catch` logged at debug and **returned** — skipping validation rather than
rejecting. helmfile's own Go parser has no depth limit, so it executed what the guard never read.

### 4.2 The second fail-open — `helmfiles:` vs `bases:`

Same sub-file, same absolute path, only the reference key differs:

| Entry file references the sub-file via | Result |
|---|---|
| `bases:` | **400** — guard rejected |
| `helmfiles:` | **200** — hook executed |

The single-file enumeration returned only the entry file, and `helmfiles` appeared nowhere in the
class, so a sub-helmfile reached by `helmfiles:` was never opened. Raw:
`evidence/03-helmfiles-vs-bases-ab.txt`.

### 4.3 Supply chain — the attacker never calls Spinnaker

A victim pipeline references a **fixed** URL the attacker already serves. The pipeline definition is
never edited.

| | Phase A (benign) | Phase B (same URL, bytes changed) |
|---|---|---|
| Attacker action | serve 263 B plain helmfile | serve 1 073 B, `hooks:` + deep nesting |
| Victim action | normal manual execution | normal manual execution |
| Trigger | `POST /pipelines/v2/...` → 202 | → 202 |
| Execution | SUCCEEDED, all tasks green | SUCCEEDED, all tasks green |
| Marker | **absent** | **present**, ~5 s later |

Expected output, Phase B:

```
[attacker] wrote supply_poc/supply_evil.yaml
[attacker]   -> served at http://evil.example.com:8000/supply.yaml (1073 bytes)
[attacker]   no Spinnaker credentials were used, and none are needed.
[victim] a normal operator clicks 'Start Manual Execution'...
         POST http://localhost:8084/pipelines/v2/rosco-poc/rosco-poc-supply
         HTTP=202
         (202 is gate's optimistic return - it does NOT mean orca accepted it)
         hook side effect observed after ~5s
--- rosco pod: hook side effect ---------------------------------
  [!!] === supply-chain trigger: rosco helmfile hook executed ===
  [!!] uid=10111(spinnaker) gid=10111(spinnaker) groups=10111(spinnaker),10111(spinnaker)
  [!!] 44c48ade52c2
  [!!] entry-file=/tmp/rosco-* (uuid-named, attacker never names it)
```

The pipeline config was byte-identical across both phases — same artifact URL, same config sha256
(`09161a4321cc168b95e6dac3479df5737606fe345917d57d9ee8658403a52b88`) — so nothing about the
victim's pipeline changed; only the served bytes did. Raw:
`evidence/06-supply-chain-trigger/`.

The original run used an outbound HTTP beacon as an observation aid. **It is not required and is not
reproduced by the published PoC** — see [`README.md`](README.md#what-the-poc-does-and-deliberately-does-not-do).

### 4.4 End to end through Deck

The same chain driven from the console (Application → Pipelines → Start Manual Execution), recorded
in `evidence/04-deck-ui-e2e/`, including orca execution records and the marker read from inside the
rosco container.

## 5. Reproduction pitfalls

Ordered by how often each one produces a false negative.

1. **`202` from gate is optimistic.** It means gate queued an event, not that orca created an
   execution. Confirm with `GET /pipelines/{id}` — the first `GET` often returns `404` and a retry
   returns `200`.
2. **Echo's pipeline-config cache polls every ~30 s.** A pipeline saved seconds ago is not in Echo's
   view and the trigger event is **dropped silently** — `202`, no execution, no logs anywhere. Wait
   one cycle between saving and triggering.
3. **Artifact type must be `http/file`.** On this build `HttpArtifactCredentials` advertises that one
   literal; `http` and `file` both 404 at the resolver.
4. **Payloads must be LF-only.** CRLF turns `id` into `id\r` inside the shell and the failure looks
   like a guard rejection.
5. **Check the marker inside the rosco pod.** The hook writes to *rosco's* `/tmp`; a host-side check
   always reports "not executed".
6. **A red bake can still be a successful exploit.** Check the marker before reading the execution
   status.

## 6. What was NOT demonstrated

Stated explicitly, because the report the vendor scored should not be read as claiming more than
was measured.

- **No `cleanup` hook timing.** `events: ["cleanup"]` was not exercised; only `prepare` is measured.
- **No privilege escalation beyond the rosco process.** Code execution as `uid=10111(spinnaker)` is
  demonstrated. Reaching clouddriver, orca or front50 with the credentials rosco holds is
  *architecturally obvious* and was **not** tested. The `Scope: Changed` reading rests on that
  reasoning, not on an observation — which is part of why 9.0 is the primary score.
- **No cloud credential material was read, copied or displayed.** The marker records the process
  identity only.
- **No data was exfiltrated and no reverse shell was opened.**
- **No remote `bases:` bypass was measured.** The report's original note that a `git::` reference
  was skipped with a warning is a source reading, not a run.
- **No fix was verified by execution.** §7 is source inspection at a tag. A 2026.3.1 build was
  never run against the PoC; a negative-result run is still outstanding.
- **The published PoC is not the code that produced `evidence/`.** The original drivers were bash
  plus payloads and are preserved verbatim; `poc/entry_hook_marker.py` is a single consolidated
  proof written to this repository's conventions, and it drops the beacon. It has not been executed.

## 7. Fix status and how it was verified

The guard was merged to `main` on 2026-09-14
([#8015](https://github.com/spinnaker/spinnaker/pull/8015)) and backported the same day to
`release-2026.1.x`, `release-2026.2.x` and `release-2026.3.x`
([#8016](https://github.com/spinnaker/spinnaker/pull/8016),
[#8017](https://github.com/spinnaker/spinnaker/pull/8017),
[#8018](https://github.com/spinnaker/spinnaker/pull/8018)).

**That guard was incomplete, and the gap this report documents is what
[#8034](https://github.com/spinnaker/spinnaker/pull/8034) closed.** #8034 is the PR that threads an
env map through `BakeRecipe -> JobRequest -> JobExecutorLocal` "for the first time" in order to
disable hooks and insecure template functions on the helmfile subprocess itself; it is cherry-picked
into `release-2026.1.x` (commit `3039b0f`). The vendor's own
[Next Release Preview](https://www.spinnaker.io/community/releases/next-release-preview/) credits
the pair together — *"`#8015` and `#8034` close a local-code-execution vector in Rosco's helmfile
baking"* — and lists it under **Breaking Changes for release 2026.4.0**.

`rosco-2026.3.1` was tagged 2026-09-24 and already carries the hardened guard.

| Gap demonstrated in `evidence/` | State at `rosco-2026.3.1` |
|---|---|
| parse failure → validation skipped | **fails closed** — `catch` now `throw hookRejection(...)` |
| `helmfiles:` never inspected | **inspected** — `HELMFILES_KEY` resolved and recursed |
| remote / templated reference skipped | **rejected** — `isUnresolvableReference` |

Beyond closing those, that release adds two layers the original report did not ask for:
`HELMFILE_DISABLE_HOOKS=true` and `HELMFILE_DISABLE_INSECURE_FEATURES=true` are set on the
subprocess, which disables helmfile's `exec`/`envExec`/`readFile` template functions and remote base
fetching independently of the static guard; and the guard enumerates `helmfile.d/` fragment
directories and tracks visited paths against symlink cycles.

**Method and its limit.** This was established by reading
`rosco/rosco-manifests/src/main/java/com/netflix/spinnaker/rosco/manifests/helmfile/HelmfileTemplateUtils.java`
at tag `rosco-2026.3.1`. Only that tag was inspected. Whether the `release-2026.1.x` /
`release-2026.2.x` / `release-2026.3.x` patch releases carry the same hardening, and what exists for
`release-2026.0.x` and `release-2025.4.x` (which received no backport), was **not** checked.

**Scope, per the vendor's own release notes.** Only the helmfile path changed: *"Plain `helm
template` and `kustomize build` baking are unaffected."* The change is flagged as a **breaking
change** for 2026.4.0, with a deliberate opt-in for operators who trust their sources:

```yaml
helmfile:
  allow-hooks-and-post-renderers: true
```

## 8. Correction: CVSS was 8.8 in the first-filed advisory

The advisory submitted to the vendor quoted `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` with a base score
of **8.8**. That vector does not evaluate to 8.8. `env/cvss.py` derives it from the CVSS 3.1
specification, and the implementation is checked against the specification's own example vector
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8):

```
ISCbase = 1 - (1-0.56)^3              = 0.914816
Impact  = 6.42 x 0.914816             = 5.873      (S:U)
Expl.   = 8.22 x 0.85 x 0.77 x 0.68 x 0.85 = 3.110
Base    = Roundup(min(5.873 + 3.110, 10))    = 9.0
```

**9.0** is used throughout this repository. The `Scope: Changed` reading
(`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`) gives **9.9** and is the better argument if the vendor's own
precedent is followed — it scored the same class of crossing `Scope: Changed` in CVE-2026-32604.
9.0 is primary because the measured blast radius stays inside the rosco process (§6).

The correction is recorded here rather than quietly dropped, per this repository's convention: the
advisory was sent at 8.8, and a reader who saw it deserves to know it was an arithmetic error — and
that the vendor's own ranking independently landed on 9.0.

**The vendor chose the same vector.** The maintainer confirmed
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H:A:H` as the ranking in use, so the CVE will carry 9.0 and the
arithmetic slip in the filed advisory never reaches a published record. No correction to the vendor
is required on this point.

## 9. Provenance

`evidence/` is the unedited captured output of the 2026-09-19 run against `rosco:main-latest`. It is
reproduced byte-for-byte from the submission bundle sent to the vendor; `SHA256SUMS.txt` in that
bundle covers all 32 files and verifies clean. Nothing in `evidence/` has been reworded, reordered
or curated. The original driver scripts are preserved as-is.

The HTTP beacon in the original run is documented in `02-trigger-and-repro.md` §4 for completeness
and is **not** reproduced by the published PoC.
