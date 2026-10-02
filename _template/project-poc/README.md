# <product> — proof-of-concept material

<!--
Scaffold. Copy to <product>-poc/ and fill in.
Read ../../README.md and ../../CONTRIBUTING.md first.
-->

**Target** `<module or artifact>`
**Version** `<version tested>`
**Commit tested** `<full sha>` (clean worktree)
**Disclosure state** not yet reported to the vendor or any CNA
**CNA** not yet assigned

All findings below were reproduced against a locally built instance of the exact commit above.

---

## Findings

| ID | Title | CWE | CVSS v3.1 | CVE |
|---|---|---|---|---|
| V1 | `<one line>` | CWE-### | **0.0** (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) | *pending* |

State the privilege each finding requires and whether that privilege exists by default. `PR:L` is
meaningless without that.

---

## V1 — `<title>`

**`<one sentence: what an ordinary caller can do that they should not be able to do>`**

**Affected code**

- `path/to/File.java:42` — <role>

**Preconditions**

1. <what must be true, and whether it is true by default>

**Steps and observed result**

```
<verbatim output from the PoC, not a paraphrase>
```

**What was NOT demonstrated**

<State it. This section is what separates a Proof-of-Concept from an overclaim, and it is the first
thing a CNA reviewer checks.>

**Impact**

<Who is affected and what it costs. Separate technical exploitability from business consequence —
they are scored separately and reviewers conflate them constantly.>

**Remediation**

1. <the structural fix, not "validate input">

---

## Files

| Path | Contents |
|---|---|
| `report.md` | full reproduction report |
| `poc/` | one runnable script per finding |
| `cve/` | CVE JSON 5.1 records |
| `nuclei/` | detection-only templates |
| `env/` | build and run instructions, minimal payloads |
| `evidence/` | verbatim captured output |
