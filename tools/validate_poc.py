#!/usr/bin/env python3
"""Validate structure and authenticity gates for project PoC contributions.

Does not execute PoCs and cannot confirm that a claimed vulnerability is real.
When --base is provided, only project directories changed since that commit
are validated. Legacy projects without submission.json will need migration
before further changes. Root policy-only PRs remain possible.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
SHA_RE = re.compile(r"^[a-fA-F0-9]{40}$")
CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
PROOF_LEVELS = {"HYPOTHESIS", "SOURCE_ONLY", "COMPONENT_VERIFIED", "RUNTIME_VERIFIED"}
DISCL_STATES = {"NOT_REPORTED", "VENDOR_NOTIFIED", "COORDINATED", "PUBLIC"}
REQUIRED_FILES = ("README.md", "report.md", "submission.json")
PLACEHOLDER = ("REPLACE_WITH", "example.invalid", "TODO", "TBD")


def changed_projects(base: str) -> list[Path]:
    run = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRD", f"{base}...HEAD"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    projects = set()
    for rel in run.stdout.splitlines():
        parts = Path(rel).parts
        if len(parts) < 2 or parts[0].startswith(".") or parts[0].startswith("_"):
            continue
        folder = ROOT / parts[0]
        if folder.is_dir() and (folder / "README.md").exists():
            projects.add(folder)
    return sorted(projects)


def all_projects() -> list[Path]:
    return sorted(p for p in ROOT.iterdir() if p.is_dir()
                  and not p.name.startswith((".", "_"))
                  and (p / "README.md").is_file())


def validate_project(p: Path, schema: dict | None) -> list[str]:
    errors = []
    def bad(msg: str) -> None:
        errors.append(f"{p.name}: {msg}")
    for file in REQUIRED_FILES:
        if not (p / file).is_file():
            bad(f"missing {file}")
    if not (p / "submission.json").exists():
        return errors
    try:
        raw = (p / "submission.json").read_text(encoding="utf8")
        doc = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        bad(f"invalid submission.json: {exc}")
        return errors
    if doc.get("schemaVersion") != 1:
        bad("schemaVersion must equal 1")
    for key in ("vendor", "product", "upstreamUrl", "testedVersion", "testedCommit"):
        val = doc.get(key)
        if not isinstance(val, str) or not val.strip() or any(w in val for w in PLACEHOLDER):
            bad(f"{key} is missing or contains a placeholder")
    if not SHA_RE.fullmatch(str(doc.get("testedCommit", ""))):
        bad("testedCommit must be a full 40-character Git commit SHA")
    disclosure = doc.get("disclosure") or {}
    if disclosure.get("status") not in DISCL_STATES:
        bad("disclosure.status invalid")
    if disclosure.get("publicationApproved") is not True:
        bad("publicationApproved must be true for public pull requests")
    if not isinstance(disclosure.get("publicationApproval"), str) or not disclosure["publicationApproval"].strip():
        bad("publicationApproval must identify human approval and where it was recorded")
    if disclosure.get("status") == "NOT_REPORTED":
        bad("unreported findings must use a private coordination channel, not a public PR")
    if not isinstance(disclosure.get("vendorContact"), str) or not disclosure["vendorContact"].strip():
        bad("disclosure.vendorContact is mandatory (include unsuccessful attempts)")
    findings = doc.get("findings")
    if not isinstance(findings, list) or not findings:
        bad("findings must be a nonempty array")
        return errors
    readme = (p / "README.md").read_text(encoding="utf8") if (p / "README.md").exists() else ""
    report = (p / "report.md").read_text(encoding="utf8") if (p / "report.md").exists() else ""
    ids = set()
    for f in findings:
        if not isinstance(f, dict):
            bad("finding must be an object")
            continue
        fid = str(f.get("id", ""))
        if not fid or fid in ids:
            bad(f"missing/duplicate finding id: {fid!r}")
            continue
        ids.add(fid)
        for name, value in (("README.md", readme), ("report.md", report)):
            if not re.search(r"(?<![A-Za-z0-9])" + re.escape(fid) + r"(?![A-Za-z0-9])", value):
                bad(f"finding {fid} missing from {name}")
        for key in ("slug", "title", "preconditions", "positiveControl", "negativeControl", "observedImpact", "notDemonstrated"):
            v = f.get(key)
            if not isinstance(v, str) or not v.strip() or any(w in v for w in PLACEHOLDER):
                bad(f"{fid}.{key}: required, non-placeholder string")
        if not CWE_RE.fullmatch(str(f.get("cwe", ""))):
            bad(f"{fid}.cwe must be a non-placeholder CWE-NNN")
        proof = f.get("proofLevel")
        if proof not in PROOF_LEVELS:
            bad(f"{fid}.proofLevel invalid")
        if f.get("readyForCnaReview") is True and proof != "RUNTIME_VERIFIED":
            bad(f"{fid}: repository policy forbids CNA_READY without runtime verification")
        poc = f.get("poc")
        if not isinstance(poc, str) or not safe_exists(p, poc, "poc/"):
            bad(f"{fid}.poc must exist under poc/")
        evidence = f.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            bad(f"{fid}.evidence must be nonempty list")
        else:
            for e in evidence:
                if not isinstance(e, str) or not safe_exists(p, e, "evidence/"):
                    bad(f"{fid}.evidence missing or outside evidence/: {e!r}")
        cve = f.get("cveId")
        if cve is not None and (not isinstance(cve, str) or not ID_RE.fullmatch(cve)):
            bad(f"{fid}.cveId invalid: use null until genuine assignment")
        cvss = f.get("cvssVector")
        if cvss is not None and (not isinstance(cvss, str) or not cvss.startswith(("CVSS:3.1/", "CVSS:4.0/"))):
            bad(f"{fid}.cvssVector must be a complete standardized vector or null")
    for cve_file in (p / "cve").glob("*.json") if (p / "cve").is_dir() else []:
        try:
            obj = json.loads(cve_file.read_text(encoding="utf8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            bad(f"bad {cve_file.name}: {exc}")
            continue
        cve_id = obj.get("cveMetadata", {}).get("cveId")
        if not isinstance(cve_id, str) or not ID_RE.fullmatch(cve_id):
            bad(f"{cve_file.name} uses an invalid/unassigned CVE ID")
        if schema is None:
            bad("full CVE record schema validation needs --schema <official schema JSON>")
        else:
            try:
                import jsonschema
                jsonschema.validate(obj, schema)
            except ImportError:
                bad("install jsonschema to validate CVE records")
            except Exception as exc:
                bad(f"{cve_file.name}: official schema failure: {exc}")
    return errors


def safe_exists(root: Path, rel: str, prefix: str) -> bool:
    if not rel.startswith(prefix) or ".." in Path(rel).parts:
        return False
    try:
        path = (root / rel).resolve()
        path.relative_to(root.resolve())
    except ValueError:
        return False
    return path.is_file()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--all", action="store_true", help="validate all project folders (legacy projects must migrate)")
    scope.add_argument("--base", help="git base commit to check changed project directories only")
    parser.add_argument("--schema", type=Path, help="pinned official CVE JSON Schema path")
    args = parser.parse_args()
    try:
        schema = json.loads(args.schema.read_text(encoding="utf8")) if args.schema else None
        projects = all_projects() if args.all else changed_projects(args.base)
    except Exception as exc:
        print(f"validator setup failed: {exc}", file=sys.stderr)
        return 2
    if not projects:
        print("PASS: no project directories changed")
        return 0
    failures = [failure for p in projects for failure in validate_project(p, schema)]
    if failures:
        for error in failures:
            print("FAIL:", error, file=sys.stderr)
        print(f"FAIL: {len(failures)} issue(s) across {len(projects)} project(s)")
        return 1
    print(f"PASS: validated {len(projects)} project(s). Human proof and disclosure review still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
