# Spinnaker rosco — proof-of-concept material

**Target** [`spinnaker/spinnaker`](https://github.com/spinnaker/spinnaker) — component **rosco**
(Maven `io.spinnaker.rosco:rosco-manifests`), the service that renders Bake (Manifest) stages
**Version affected** every released version through **2026.3.0** (2026-09-07)
**Fixed in** **rosco-2026.3.1** (2026-09-24, commit `3567b1c`) — verified by reading the source at
that tag, see [Fix status](#fix-status) below
**Commit tested** the running service was `rosco:main-latest` as of **2026-09-19**, on a 10-container
stack (deck / gate / orca / rosco / clouddriver / front50 / echo + redis + mysql + attacker)
**Disclosure state** **reported and fixed.** Submitted to the Spinnaker Security SIG at
`security@spinnaker.io`; the fix shipped in `rosco-2026.3.1`. No CVE ID has been published at the
time of writing, so `cve/` carries a `CVE-PENDING-*` identifier with `state: RESERVED`.

> **This is not live.** Unlike the other two projects in this repository, the vendor was notified and
> a fix exists. If you run rosco **2026.3.1 or later** you are not affected. If you run **2026.3.0 or
> earlier**, upgrade — the exposure is silent, and a failing bake does not mean you were not hit.

---

## The finding

**Anyone who can control the bytes of a `helmfile.yaml` that rosco bakes can run arbitrary commands
as the rosco process, during a bake that is documented as side-effect free.**

rosco implements a Bake stage with `templateRenderer: HELMFILE` by shelling out to
`helmfile template`. The helmfile content is supplied to rosco as an **input artifact** — data the
calling pipeline provides — and it is that data which decides what runs. helmfile executes two
features from that file even under `template`:

```yaml
hooks:
  - events: ["prepare"]
    command: "sh"
    args: ["-c", "id > /tmp/marker.txt"]
```

```yaml
helmDefaults:
  args: ["--post-renderer=./evil.sh"]     # second route to the same sink
```

The maintainer states the trust boundary himself, in the PR that later added a guard
([#8015](https://github.com/spinnaker/spinnaker/pull/8015)):

> The `helmfile.yaml` baked by rosco is a user-supplied input artifact, which may not be as trusted
> as the pipeline referencing it (e.g. a git branch anyone can push to), so **this is a real
> local-code-execution vector on the rosco host** during a supposedly side-effect-free bake.

| | |
|---|---|
| **CWE** | CWE-78 (primary, OS command injection), CWE-693 (protection mechanism failure) |
| **CVSS v3.1** | **9.0** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CVE** | *pending* — see `cve/` |

### Why 9.0 and not the 8.8 first filed

The original advisory shipped this vector with a score of **8.8**, which is an arithmetic error: the
vector does not evaluate to 8.8. `env/cvss.py` derives it from the 3.1 specification
(verified against the spec's own example vector, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8):

```
ISCbase  = 1 - (1-0.56)^3            = 0.914816
Impact   = 6.42 x 0.914816           = 5.873    (S:U)
Expl.    = 8.22 x 0.85 x 0.77 x 0.68 x 0.85 = 3.110
Base     = Roundup(min(5.873 + 3.110, 10))    = 9.0
```

```bash
python3 env/cvss.py "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"   # 9.0
```

A `Scope: Changed` reading (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`) gives **9.9**, and is arguably the
better fit: code execution inside rosco can reach clouddriver, orca and front50, which sit across a
trust boundary from the bake caller. The 9.0 figure is used as primary here because the demonstrated
blast radius stays within the rosco process.

### Scope note — why this is in this repository

This repository admits findings whose trigger is *input supplied by an end user*, not a
misconfigured or deliberately hostile deployment. That distinction is worth stating rather than
assuming, because in this case the input is a **file**, not a request body:

- The input is an ordinary **input artifact** to a Bake stage — the same category of
  caller-supplied data as a request body, not an administrator's deployment decision.
- On every affected version there is **no configuration to get wrong**. The guard only exists in
  fixed builds, and it defaults to enabled. Nothing has to be switched on.
- The privilege required is `PR:L`: the ability to reference an artifact in a bake. An operator who
  additionally controls the referenced source (a git branch, an HTTP path, a registry entry) needs
  **no Spinnaker credential at all** — the victim's next ordinary pipeline run is the trigger. That
  variant is reproduced in `evidence/06-supply-chain-trigger/`.

The counter-argument — that whoever can write to the referenced repository is "an attacker with repo
access, not an API user" — is the framing the vendor itself rejected, in the quoted text above.

---

## Affected versions

| Version | Guard | What triggering requires |
|---|---|---|
| **≤ 2026.3.0** (all released versions) | **absent** | `hooks:` in the **entry** file. No bypass needed |
| **rosco-2026.3.1** (2026-09-24) | present, and closed the gaps the original report documented | — fixed |

Measured by unzipping `rosco-manifests-*.jar` from each image and counting
`rejectHooksAndPostRenderers` in `HelmfileTemplateUtils.class`:

| Build | hits | class size |
|---|---|---|
| ≤ 2026.3.0 | 0 | 11 334 B |
| `main-latest` @ 2026-09-19 (carries #8015) | 1 | 19 189 B |
| `rosco-2026.3.1` @ 2026-09-24 | present, hardened | — |

## Fix status

The gaps this repository's evidence demonstrates against the **2026-09-19** `main-latest` build were
closed before the 2026-09-24 release. Read at tag `rosco-2026.3.1`,
`rosco/rosco-manifests/src/main/java/com/netflix/spinnaker/rosco/manifests/helmfile/HelmfileTemplateUtils.java`:

| Gap the evidence shows | State at `rosco-2026.3.1` |
|---|---|
| Parse failure → validation **skipped** (deep nesting raised `YAMLException`, the `catch` returned) | **fails closed** — the `catch` now calls `throw hookRejection(...)` |
| `helmfiles:` nested sub-helmfile never inspected | **inspected** — `HELMFILES_KEY` is resolved and recursed into, same as `bases:` |
| Remote / templated `bases:` skipped with a warning | **rejected outright** via `isUnresolvableReference` |

Two hardening layers in that release were not in the original report and are worth the vendor's
credit:

1. `buildCommand` sets `HELMFILE_DISABLE_HOOKS=true` and `HELMFILE_DISABLE_INSECURE_FEATURES=true` on
   the subprocess. That disables helmfile's `exec`/`envExec`/`readFile` template functions and remote
   base fetching **independently of the static guard** — a belt-and-braces layer that holds even for
   constructs no YAML key check could enumerate.
2. The guard enumerates `helmfile.d/` fragment directories, tracks a `visited` set against symlink
   cycles, and resolves `helmfiles:` entries in both bare-string and `{path: ...}` form.

**What was not verified.** Only `rosco-2026.3.1` was inspected. The fix was also backported to
`release-2026.1.x`, `release-2026.2.x` and `release-2026.3.x`
([#8016](https://github.com/spinnaker/spinnaker/pull/8016),
[#8017](https://github.com/spinnaker/spinnaker/pull/8017),
[#8018](https://github.com/spinnaker/spinnaker/pull/8018)); whether those branches' patch releases
carry the same hardened guard, and what the equivalent patch releases for `release-2026.0.x` and
`release-2025.4.x` are, was **not** checked. Treat the table above as scoped to 2026.3.1.

**This fix was verified by reading source at the tag, not by executing the PoC against a 2026.3.1
build.** The reproduction evidence in `evidence/` is from the 2026-09-19 run against the *vulnerable*
configuration. A negative-result run against 2026.3.1 has not been performed.

---

## What the PoC does, and deliberately does not do

`poc/entry_hook_marker.py` demonstrates the sink with the least capability that still proves it:

| Prohibited by this repository's rules | What this PoC does instead |
|---|---|
| Reverse shell | writes one marker file into **rosco's own** `/tmp` |
| Data exfiltration | prints `uid`/`gid` of the rosco process — the value the PoC itself needs to prove execution |
| Outbound beacon | **none.** The original audit used an HTTP beacon as an observation aid; it is dropped here. Execution is confirmed from inside the rosco container with `docker exec` |
| Persistence | nothing survives the bake; the marker is removed by the verification step |
| Bundled gadget chain | a `hooks: prepare:` entry whose only behaviour is the marker write |

It requires `--confirm-authorised`, verifies its own preconditions, and exits non-zero when the
finding does not reproduce. See `poc/README.md`.

---

## Files

| Path | Contents |
|---|---|
| `report.md` | full reproduction report: environment, exact steps, expected output, what was **not** demonstrated |
| `poc/` | one runnable proof (`entry_hook_marker.py`), `--confirm-authorised` gated |
| `cve/` | CVE JSON 5.1 record, `state: RESERVED`, `exploitability: PROOF_OF_CONCEPT` |
| `nuclei/` | detection-only template (fingerprints the precondition; it does not exploit) |
| `env/` | `build-and-run.md` to reproduce from a clean checkout, `cvss.py`, `make_cve_records.py` |
| `evidence/` | verbatim captured output from the 2026-09-19 run (unedited) |
