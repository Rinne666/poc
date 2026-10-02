# poc

Minimised proof-of-concept material for vulnerabilities found during authorised security research.

Each subdirectory is one project. The layout and conventions are defined once here so that a CNA
reviewer, a vendor maintainer, or the next researcher adding a project all find the same things in
the same place.

---

## Disclosure status — read this first

**This repository is private. Nothing in it has been disclosed to any vendor or CNA yet.**

Material is not published until this sequence completes for the relevant finding:

1. Submit to the vendor's security contact, or to a CNA, using the `cve/*.cve.json` records here.
2. Observe the confidentiality window. VulDB allows 90 days; other CNAs vary.
3. Obtain the CVE ID and replace the `CVE-PENDING-*` identifiers.
4. Republish this repository publicly, or publish a per-project public mirror.

Publishing a working remote-code-execution proof of concept before step 2 is complete removes the
maintainer's ability to ship a fix before downstream users are exposed. It also invalidates the
reporter's own claim to have followed coordinated disclosure.

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
├── flowable-poc/              Flowable Engine REST API
│   ├── README.md              one-line-per-finding summary, affected versions, links
│   ├── report.md              full reproduction report: environment, steps, expected output
│   ├── poc/                   runnable proofs, one file per finding
│   ├── cve/                   CVE JSON 5.1 records, ready for CNA submission
│   ├── nuclei/                Nuclei detection templates
│   ├── env/                   how to build and run the target, plus minimal payloads
│   └── evidence/              verbatim captured output backing every claim
└── _template/                 scaffold for a new project
```

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
