# poc

Minimised proof-of-concept material for vulnerabilities found during authorised security research.

Each subdirectory is one project. The layout and conventions are defined once here so that a CNA
reviewer, a vendor maintainer, or the next researcher adding a project all find the same things in
the same place.

---

## Disclosure status — read this first

**Disclosure state differs per project, and every project directory states its own.** Check the
project you are about to rely on:

| Project | State | Consequence for an operator |
|---|---|---|
| `spinnaker-rosco-helmfile-rce` | **reported, fixed, credited**; CVE requested, not yet allocated | upgrade to rosco 2026.3.1 or later. ≤ 2026.3.0 is exposed |
| `flowable-poc` | not yet reported to the vendor or any CNA | treat as live until Flowable publishes a fix |
| `astron-agent-poc` | not yet reported to iFlytek or any CNA | treat as live; there is no fix to wait for |
| `maxkey-poc` | **reported to the vendor** via GitHub private vulnerability reporting; no fix yet | treat as live; any instance from the shipped compose file may still hold the seeded admin credential |

This repository is public. That was a deliberate choice by the maintainer of this repository, made
to support a CNA submission. It has a consequence worth stating plainly rather than burying: for the
Flowable and astron-agent findings, downstream users of those products have no vendor warning period
yet. The Spinnaker finding is the exception — the vendor was notified and shipped a fix, so there is
a fixed version to move to.

The sequence that would normally precede publication:

1. Submit to the vendor's security contact, or to a CNA, using the `cve/*.cve.json` records here.
2. Observe the confidentiality window. VulDB allows 90 days; other CNAs vary.
3. Obtain the CVE ID and replace the `CVE-PENDING-*` identifiers.
4. Update the project directory with the new identifiers and the vendor's response.

Steps 1–3 have not been completed. Each project's `submission.json` records its actual disclosure state, and the optional `cve/*.cve.json` directory now contains only records whose CVE IDs were genuinely assigned by a CNA — pre-allocation drafts are kept out of the public repository. See the project README and `submission.json` for the per-project status.

**A note on why this is still publishable.** VulDB's requirement is a *publicly verifiable* proof of
concept, which can be satisfied by an accessible test instance or by screenshots of a local
reproduction, and does not by itself require a public code repository. The code is public here as a
choice. The inertness rule below is what keeps it publishable at all.

---

## The one rule that shapes every PoC in this repository

**A PoC demonstrates that a vulnerability is reachable. It does not exploit it.**

VulDB's `Proof-of-Concept` exploitability tier — the correct tier for material of this kind —
is defined as *"a simple exploit is available which illustrates the basic functionality of
exploitation, without a certain level of reliability, no customization possibilities, and no error
handling"*. The CNA is establishing whether the defect is real, not how much damage it can do.

Concretely, every PoC here obeys all of the following:

| Prohibited | Required instead |
|---|---|
| Reverse shells | a marker file written under the target's own temp directory |
| Data exfiltration | printing one value the caller already supplied |
| Persistence | nothing that survives the request |
| Bulk or destructive actions | a single record created and, where relevant, deleted by the PoC itself |
| Bundled gadget chains | a minimal class whose only behaviour is a visible side effect |
| Third-party or production targets | an explicitly required `--confirm-authorised` flag |

Payloads here are deliberately less capable than what the vulnerability permits. The gap is
intentional and is the point: it is what distinguishes research material from an attack tool, and
it is what keeps this repository publishable.

---

## Layout

```
poc/
├── README.md                  this file — conventions and disclosure state
├── CONTRIBUTING.md            how to add a project, and the review checklist
├── spinnaker-rosco-helmfile-rce/  Spinnaker rosco (Bake / Manifest rendering)
│   ├── README.md              summary, affected versions, fix status, links
│   ├── report.md              full reproduction report: environment, steps, expected output
│   ├── poc/                   one runnable proof
│   ├── cve/                   CVE JSON 5.1 record, ready for CNA submission
│   ├── nuclei/                Nuclei detection template
│   ├── env/                   how to build and run the target; CVSS and CVE generators
│   └── evidence/              verbatim captured output from the run
├── flowable-poc/              Flowable Engine REST API
│   ├── README.md              one-line-per-finding summary, affected versions, links
│   ├── report.md              full reproduction report: environment, steps, expected output
│   ├── poc/                   runnable proofs, one file per finding
│   ├── cve/                   CVE JSON 5.1 records, ready for CNA submission
│   ├── nuclei/                Nuclei detection templates
│   ├── env/                   how to build and run the target, plus minimal payloads
│   └── evidence/              verbatim captured output backing every claim
├── astron-agent-poc/          iFlytek astron-agent (Console backend, workflow engine, core-database)
│   ├── README.md              one-line-per-finding summary, affected versions, links
│   ├── report.md              full reproduction report: environment, steps, expected output
│   ├── poc/                   runnable proofs, one file per finding
│   ├── cve/                   CVE JSON 5.1 records, ready for CNA submission
│   ├── nuclei/                Nuclei detection templates
│   ├── env/                   how to build and run the target, plus the victim-flow seed
│   └── evidence/              session records backing every claim (redacted; see evidence/README.md)
├── maxkey-poc/               dromara MaxKey IAM/SSO (OAuth2/OIDC, SAML 2.0, CAS, JWT, SCIM)
│   ├── README.md              summary, affected versions, disclosure state, inertness
│   ├── cve/                   CVE JSON 5.1 records, ready for CNA submission
│   ├── poc/                   Java harnesses + integration reproduction scripts
│   ├── env/                   two-tenant seed SQL for the cross-tenant test
│   └── evidence/              verbatim captured output + RESULTS.md
└── _template/                 scaffold for a new project
```

> One template in this repository is deliberately *not* a vulnerability probe.
> `spinnaker-rosco-helmfile-rce/nuclei/` only confirms the bake endpoint is reachable, using
> a request that is rejected before any artifact is fetched — because the only request that
> distinguishes a guarded rosco from an unguarded one would execute a command on the target.
> The file explains that reasoning in full.

## Naming

Lowercase ASCII, hyphen-separated, matching what a CNA entry would be called:

```
<product>-<component>-<vulnerability-type>
flowable-rest-deployment-rce
flowable-rest-serializable-deser
```

Never embed a CVE ID in a filename. A CNA allocates it, and a file named after an ID that is later
reallocated or rejected is worse than no ID at all.

## Required content per project

| Path | Must contain |
|---|---|
| `submission.json` | **canonical structured metadata** — product, exact test version/commit, disclosure state, finding IDs, proof level, prerequisites, observed impact, CVE status, evidence paths |
| `README.md` | human-readable index derived from `submission.json`; affected versions, CWE, CVSS vector and score, disclosure state, links |
| `report.md` | exact environment, exact steps, positive and negative controls, expected/actual results, what was *not* demonstrated |
| `poc/` | runnable, non-interactive, exits non-zero on failure, refuses to run without explicit authorisation |
| `cve/` | **optional** — only actually CNA-assigned, official-schema-validated CVE records; no self-issued `state: RESERVED` or `CVE-PENDING-*` records |
| `nuclei/` | a template that **detects** the condition, never one that exploits it |
| `env/` | reproducible build instructions for the target, from a clean checkout |
| `evidence/` | unedited captured output — not paraphrased, not curated |

> The `submission.json` row is the new normative entry. The `cve/` row above replaces the prior rule that required `exploitability: PROOF_OF_CONCEPT` and `state: RESERVED`. Per the policy addendum below, `CVE-PENDING-*` is a human-readable internal label only and is not a valid CVE ID; `submission.json` is the canonical place for unassigned drafts.

## What belongs in this repository

Findings reproduced against a local build of the target, under authorisation, where the trigger is
**input supplied by an end user of the API** rather than a misconfigured or deliberately hostile
application deployment.

The second clause is a real filter, not a formality. "The administrator turned on a feature that is
documented as unsafe" and "any ordinary API caller can reach a sensitive sink" are different classes
of defect, reported to different audiences, and only the second belongs here.

---

## AI contribution policy and CNA submission gates

> **Normative repository policy.** This section applies to humans and coding agents. Before changing any PoC, read `AGENTS.md`, `CONTRIBUTING.md`, the relevant project report, and this policy. If they disagree, stop and request human review; do not silently relax a requirement. This policy is a repository quality gate, **not** a claim that a CNA must accept every passing submission.

### Evidence before claims

A submitted finding is a security vulnerability candidate, not an assigned CVE. The researcher must demonstrate an actual violation of an expected security boundary, not merely the presence of a dangerous API, HTTP 200 response, stack trace, or scanner alert.

Every finding MUST have a version-pinned target, stated attacker privileges and deployment prerequisites, one non-destructive positive test, one relevant negative/control test (or a justified exception), captured machine output, source location, and a bounded observed security impact. Every untested inference MUST appear under `Not demonstrated`. Never describe a code-level harness as full HTTP end-to-end exploitation; never claim RCE, unauthenticated access, impact on all versions, or CVSS impacts that were not established. Do not invent vendor acknowledgements, mitigations, releases, CWE/CVSS evidence, test runs, or external links.

Classify each finding using one of:

- `RUNTIME_VERIFIED`: tested against the running target, with an observable security impact and appropriate control.
- `COMPONENT_VERIFIED`: tested with real target classes/components, but the complete application/HTTP boundary is untested.
- `SOURCE_ONLY`: code path is identified, but its security impact is not observed at runtime.
- `HYPOTHESIS`: a potential issue remains unverified.

Use the most conservative applicable class. `SOURCE_ONLY` and `HYPOTHESIS` findings MUST NOT be labeled `CNA_READY` in this repository; this is our stricter publishing standard, not an official CNA eligibility rule. Likewise, `COMPONENT_VERIFIED` needs human review and a clear description of untested layers before claiming readiness.

### Public disclosure and authorization are distinct gates

Only run PoCs against lab systems the operator owns or is expressly authorized to test. A `--confirm-authorised` flag is an operator acknowledgement, **not proof of permission**. Default targets must be loopback or private disposable test fixtures; avoid mass scanning, third-party endpoints, exfiltration, reverse shells, persistence, destructive changes, or unlimited requests. Clean up only fixtures created by the PoC, and fail with a nonzero exit code if the claimed observation is absent. A detection template is not evidence of exploitability.

This is a public repository: DO NOT open a public PR with previously undisclosed exploit material by default. Record vendor/CNA contact attempts, coordination state, and an explicit human publication approval in each project's `submission.json`. When those fields are incomplete, use a private reporting channel and do not push sensitive PoC details here. No universal 90-day deadline is assumed; coordinate according to the actual parties and disclosure agreement. A release decision always requires maintainer approval.

### Submission format and single source of truth

For every new or materially updated project, use `_template/project-poc/` and include:

| Path | Purpose |
|---|---|
| `submission.json` | Canonical metadata: product, exact test version/commit, disclosure state, finding IDs, proof level, prerequisites, observed impact, CVE status, evidence paths |
| `README.md` | Human-readable index and disclosure state, derived from `submission.json` |
| `report.md` | Step-by-step reproducibility, exact commands, positive/negative controls, expected/actual results, limitations |
| `poc/` | Minimal, bounded, authorized reproduction that signals success/failure correctly |
| `evidence/` | Raw sanitized captures with provenance (date, commands, target, exit codes); redactions must be labeled |
| `env/` | Reproducible isolated lab setup and teardown |
| `cve/` | Optional: **only** actual CNA-assigned, schema-valid CVE records; no self-issued IDs |
| `nuclei/` | Optional: safe detection-only templates; never claim they prove exploitation |

The finding set in `submission.json`, `README.md`, and `report.md` MUST agree. All listed PoC/evidence paths must exist. Include regression findings that failed testing only when clearly identified as rejected hypotheses, not as confirmed vulnerabilities. Claims, scope, CVSS and affected versions must not exceed observed evidence.

### CVE IDs, schema, and CNA workflow

`CVE-PENDING-*` MAY appear only as a human-readable internal tracking label outside official CVE record fields. It is not a valid CVE ID. Do not impersonate a CNA by setting `assignerShortName` to the researcher's account or by adding `state: RESERVED` to an invented published record. Until a real ID and authorized CNA metadata exist, keep a *non-CVE* draft in `submission.json`. Once an ID is genuinely assigned and the record's author/submitter is authorized, validate its `cve/` JSON against the pinned official schema; no arbitrary top-level `notes` or `exploitability` in the CNA container. Include project-specific public references when the CVE record is published.

Before contacting a CNA, check vendor/product scope, existing CVEs/GHSAs, overlap or duplicates, affected release versions (do not assume a snapshot affects all releases), and the actual disclosure state. The chosen CNA decides CVE eligibility, severity, scope and publication timing. Passing our CI does **not** confer CVE acceptance.

### Acceptance gates (all mandatory for public PRs)

1. Lab authorization and the current code/commit under test are explicitly recorded.
2. `submission.json` is complete; paths, findings, and proof levels are internally consistent.
3. The positive and negative control results and the exact observed impact match the report. Failed and missing tests are disclosed.
4. CVSS score and affected-version assertions are backed by evidence and do not overclaim.
5. Vendor/CNA coordination is recorded and a human maintainer has approved this public disclosure.
6. Scripts are bounded/non-destructive; secrets and real user data have been removed or redacted transparently.
7. Local validator and GitHub Actions pass. A human reviewer approves the technical claim; CI can check syntax and structure but cannot establish vulnerability truth.

References: [CNA Rules v4.2.0](https://github.com/CVEProject/cve-documents/blob/master/CNA_Rules.md), [Official CVE Record schema](https://github.com/CVEProject/cve-schema), [VulDB submission policy](https://vuldb.com/kb/submission).
