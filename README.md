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

Steps 1–3 have not been completed. The records are `state: RESERVED` and the identifiers are
`CVE-PENDING-*` precisely because no number has been allocated yet — do not read those files as
assigned CVE records.

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
| `README.md` | summary, affected versions, CWE, CVSS vector and score, disclosure state, links |
| `report.md` | exact environment, exact steps, expected output, what was *not* demonstrated |
| `poc/` | runnable, non-interactive, exits non-zero on failure, refuses to run without explicit authorisation |
| `cve/` | CVE JSON 5.1, `exploitability: PROOF_OF_CONCEPT`, `state: RESERVED` until published |
| `nuclei/` | a template that **detects** the condition, never one that exploits it |
| `env/` | reproducible build instructions for the target, from a clean checkout |
| `evidence/` | unedited captured output — not paraphrased, not curated |

## What belongs in this repository

Findings reproduced against a local build of the target, under authorisation, where the trigger is
**input supplied by an end user of the API** rather than a misconfigured or deliberately hostile
application deployment.

The second clause is a real filter, not a formality. "The administrator turned on a feature that is
documented as unsafe" and "any ordinary API caller can reach a sensitive sink" are different classes
of defect, reported to different audiences, and only the second belongs here.
