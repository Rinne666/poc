# Contributing — adding a project to this repository

This repository holds proof-of-concept material for vulnerabilities found during authorised
security research. One directory per project. Read `README.md` first: the disclosure state and the
inertness rule there are not stylistic preferences, they are what keeps this repository
publishable.

## Before you start

Material does not go public until it has been through a CNA or the vendor, and the confidentiality
window has elapsed. Check the target for an existing CVE first — a duplicate wastes the work and
the reviewer's time.

Findings are in scope when the trigger is **input supplied by an end user of the API**, on a stock
deployment, with no administrator action and no configuration change. Findings that require a
misconfigured or deliberately hostile deployment belong in a report to that deployment's owner, not
here.

## Checklist

```
[ ] target built from a clean checkout, unmodified — record the commit hash
[ ] every claim in the report came from running the PoC, not from reading the code
[ ] each PoC refuses to run without --confirm-authorised
[ ] each PoC creates only objects it names <project>-poc-*, and cleans up its account
[ ] no reverse shell, no data export, no persistence, no bundled gadget chain
[ ] CVSS vector and score derived, not guessed; state what was NOT demonstrated
[ ] cve/*.cve.json is dataVersion 5.1, state RESERVED, exploitability PROOF_OF_CONCEPT
[ ] evidence/ holds unedited captured output
[ ] nuclei/ templates DETECT; they never exploit
[ ] README.md states the disclosure state, including "not yet reported"
```

That last item is the one people skip, and it is the one that decides whether the repository can
ever be made public.

## Procedure

```bash
cp -r _template/project-poc <project>-poc
cd <project>-poc
```

Then fill in each file. `README.md` is written for a reviewer who has never seen the product —
lead with what the finding is, not with how you found it. `report.md` is the artefact a CNA
actually reads, and it should read like a trail rather than a puzzle: every step must be executable
by someone who does not know your environment.

Generate the CVE records with a script rather than hand-writing them, so sibling records stay
structurally identical. `flowable-poc/env/make_cve_records.py` is the working example.

## Naming

Lowercase ASCII, hyphen-separated, no CVE ID in any filename:

```
<product>-<component>-<vulnerability-type>
flowable-rest-deployment-rce
```

A file named after a CVE ID that is later reallocated or rejected is worse than no ID at all.

## Verifying before you commit

```bash
# syntax
python3 -m py_compile poc/*.py

# the real test — against a target you are authorised to run
python3 poc/<finding>.py --base http://localhost:8080/<context> --confirm-authorised
echo "exit=$?"          # must be 0

# a PoC that cannot fail is not a PoC
python3 poc/<finding>.py --base http://localhost:8080/<context>   # must refuse, non-zero
```

Capture that output into `evidence/` verbatim. Do not paraphrase it.

## When a PoC contradicts the report

Fix the report, not the wording of the PoC. This repository has one such correction on record — an
earlier draft claimed cross-job external-worker impersonation; testing showed Flowable correctly
refuses that case with `403`, and the finding was restated as the accurate one (identity readable
and replayable, not usable across jobs). The correction is described in `flowable-poc/report.md`
rather than quietly dropped, because a reader who saw the earlier claim deserves to know it was
wrong and why.
