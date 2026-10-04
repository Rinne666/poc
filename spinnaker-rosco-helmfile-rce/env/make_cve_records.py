#!/usr/bin/env python3
"""Generate the CVE JSON 5.1 record for the spinnaker-rosco-helmfile-rce finding.

Kept as a script rather than a hand-written file for two reasons:

  1. The CVSS base score is DERIVED from the vector here, not typed in. The advisory
     first filed quoted AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H as 8.8, which is an
     arithmetic error -- it evaluates to 9.0. Deriving it in code means the number in
     the record, the number in README.md and the number in report.md cannot drift
     apart again.
  2. When a CNA allocates a real identifier, re-run with --cve-id and --state
     PUBLISHED instead of hand-editing five places.

    python3 env/make_cve_records.py                                   # CVE-PENDING, RESERVED
    python3 env/make_cve_records.py --cve-id CVE-2027-12345 --publish

The base score is cross-checked against the CVSS 3.1 specification's own example
vector (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, documented as 9.8) on every run, so a
mistake in the local implementation is caught here rather than shipped.
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from cvss import base_score  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent.parent / "cve"
ASSIGNER = "rinne666"
PRODUCT = "rosco"
REPO = "https://github.com/spinnaker/spinnaker"

VECTOR = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
VECTOR_SCOPE_CHANGED = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"

SEVERITY = {0.0: "NONE", 4.0: "MEDIUM", 7.0: "HIGH", 9.0: "CRITICAL"}


def self_check() -> None:
    """Verify the local CVSS implementation against the specification's example."""
    spec_example = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    got = base_score(spec_example)
    if abs(got - 9.8) > 1e-9:
        raise SystemExit(
            f"cvss.py is wrong: spec example {spec_example} gave {got}, expected 9.8"
        )
    print(f"  self-check ok: spec example {spec_example} -> {got}")


def severity_for(score: float) -> str:
    best = "NONE"
    for threshold in sorted(SEVERITY):
        if score >= threshold:
            best = SEVERITY[threshold]
    return best


AFFECTED = [
    ("2026.3.0", "affected"),
    ("2026.1.1", "affected"),
    ("2026.0.3", "affected"),
    ("2025.4.4", "affected"),
    ("main-latest at 2026-09-19 (carries the incomplete #8015 guard)", "affected"),
    ("2026.3.1", "unaffected"),
]

DESCRIPTION = (
    "Spinnaker rosco implements a Bake (Manifest) stage with templateRenderer: HELMFILE by "
    "writing the caller's input artifacts to a temporary directory and exec'ing `helmfile "
    "template --file <path>` (HelmfileTemplateUtils.buildCommand). The helmfile content is "
    "supplied to rosco as an input artifact and is therefore caller-controlled data.\n\n"
    "helmfile executes two features from that file even under the read-only `template` "
    "subcommand: `hooks:` entries (events such as prepare fire before rendering) and "
    "post-renderers, reachable as `postRenderers:` or as a `--post-renderer` flag inside "
    "`helmDefaults.args`. Either causes helmfile to run an arbitrary local command as the "
    "rosco process (uid 10111, user spinnaker) inside the rosco pod, during a bake the "
    "codebase describes as side-effect free. Execution does not require the bake to succeed: "
    "with a hooks entry and no renderable release, `helmfile template` exits 3 while the "
    "prepare hook has already run and its side effect is already on disk.\n\n"
    "The trigger is input supplied by an end user, not an administrator action or a "
    "misconfigured deployment. An operator able to reference an artifact in a bake requires "
    "only pipeline write access; an operator who additionally controls the referenced source "
    "(a git branch, an HTTP path, a registry entry) requires no Spinnaker credential at all, "
    "and the victim's next ordinary pipeline run is the trigger. That second case was "
    "reproduced end to end: the victim pipeline configuration was byte-identical across the "
    "benign and malicious phases (same artifact URL, same config sha256) and only the served "
    "bytes changed.\n\n"
    "Observed against rosco:main-latest on 2026-09-19: a parseable control helmfile carrying "
    "`hooks:` was rejected with HTTP 400, while a byte-identical payload with one value nested "
    "past SnakeYAML's 50-level limit was accepted with HTTP 200 and the hook executed, observed "
    "from inside the rosco container. The same sub-helmfile was rejected when referenced via "
    "`bases:` and executed when referenced via `helmfiles:`.\n\n"
    "All released versions through 2026.3.0 (2026-09-07) contain no guard at all, so a hooks "
    "entry in the entry file executes with no bypass required. A guard was merged to main on "
    "2026-09-14 (#8015) and backported to release-2026.1.x, release-2026.2.x and "
    "release-2026.3.x the same day. That first guard was incomplete, and #8034 closed the gaps "
    "this report demonstrated: rosco-2026.3.1 (2026-09-24, commit 3567b1c) already carries the "
    "hardened form, in which content that fails to parse is rejected rather than skipped, "
    "`helmfiles:` sub-helmfiles are inspected, and HELMFILE_DISABLE_HOOKS / "
    "HELMFILE_DISABLE_INSECURE_FEATURES are set on the helmfile subprocess itself. The project "
    "lists the change as a breaking change for release 2026.4.0 and notes that plain helm "
    "template and kustomize build baking are unaffected."
)

NOTES = {
    "disclosure": (
        "Reported to the Spinnaker Security SIG at security@spinnaker.io. The vendor confirmed "
        "the finding, added the reporter as a CVE contact, and requested a CVE. The fix shipped "
        "in rosco-2026.3.1 (2026-09-24, commit 3567b1c) and is announced as a breaking change "
        "for release 2026.4.0. The identifier here is a placeholder until a number is "
        "allocated; state is RESERVED, so this is not an assigned CVE record."
    ),
    "vendor_ranking": (
        "The maintainer confirmed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H as the ranking in "
        "use, which evaluates to 9.0. Note for comparison: CVE-2026-55175 "
        "(GHSA-p68j-q7hf-3qcp) is a different finding in this same package - unsafe YAML tag "
        "processing in the Kustomize bake path - and the project scored it 7.5 with AC:H. This "
        "finding is scored AC:L because a hooks entry is inert unless a bake actually references "
        "it, whereas the Kustomize deserialisation fires on the file being read at all."
    ),
    "not_claimed": (
        "No privilege escalation beyond the rosco process was demonstrated. Code execution as "
        "uid 10111 (spinnaker) is measured; reaching clouddriver, orca or front50 with the "
        "credentials rosco holds is architecturally plausible but was not tested, which is why "
        "Scope: Unchanged is used rather than the Scope: Changed reading. No cleanup hook "
        "timing, no cloud credential access, no data exfiltration and no reverse shell. The fix "
        "was verified by reading source at the 2026.3.1 tag, not by executing the PoC against a "
        "2026.3.1 build; a negative-result run is outstanding."
    ),
    "exploit_tier": (
        "Proof-of-Concept. The published PoC writes a single marker file into rosco's own /tmp "
        "and prints the process identity. It has no reverse shell, no outbound callback, no "
        "persistence and no credential access, and it refuses to run without "
        "--confirm-authorised."
    ),
}


def build(cve_id: str, state: str, published: str | None) -> dict:
    score = base_score(VECTOR)
    record = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerShortName": ASSIGNER,
            "state": state,
        },
        "containers": {
            "cna": {
                "title": (
                    "Command execution on Spinnaker rosco via helmfile hooks/postRenderers "
                    "in caller-supplied input artifacts"
                ),
                "descriptions": [{"lang": "en", "value": DESCRIPTION}],
                "affected": [
                    {
                        "vendor": "Spinnaker",
                        "product": PRODUCT,
                        "defaultStatus": "affected",
                        "versions": [
                            {"version": v, "status": s} for v, s in AFFECTED
                        ],
                        "repo": REPO,
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-78",
                                "lang": "en",
                                "description": (
                                    "Improper Neutralization of Special Elements used in an OS "
                                    "Command - the caller-supplied helmfile selects a local "
                                    "command that helmfile runs as the rosco process"
                                ),
                                "type": "CWE",
                            },
                            {
                                "cweId": "CWE-693",
                                "lang": "en",
                                "description": (
                                    "Protection Mechanism Failure - on all released versions no "
                                    "guard existed, and the first guard that shipped failed open "
                                    "on unparseable YAML and did not inspect helmfiles: "
                                    "sub-helmfiles"
                                ),
                                "type": "CWE",
                            },
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/Rinne666/poc/tree/main/"
                        "spinnaker-rosco-helmfile-rce/README.md"
                    },
                    {
                        "url": "https://github.com/Rinne666/poc/tree/main/"
                        "spinnaker-rosco-helmfile-rce/report.md"
                    },
                    {
                        "url": "https://github.com/Rinne666/poc/tree/main/"
                        "spinnaker-rosco-helmfile-rce/poc/entry_hook_marker.py"
                    },
                    {"url": "https://github.com/spinnaker/spinnaker/pull/8015"},
                    {"url": "https://github.com/spinnaker/spinnaker/pull/8034"},
                    {
                        "url": "https://www.spinnaker.io/community/releases/"
                        "next-release-preview/"
                    },
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [{"lang": "en", "value": "GENERAL"}],
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": f"CVSS:3.1/{VECTOR}",
                            "baseScore": score,
                            "baseSeverity": severity_for(score),
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "LOW",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                        },
                    }
                ],
                "solutions": [
                    {
                        "type": "vendor-fix",
                        "value": (
                            "Upgrade to rosco 2026.3.1 or later. The project ships this as a "
                            "breaking change in 2026.4.0: only the helmfile path is affected, and "
                            "plain helm template and kustomize build baking are unaffected. As "
                            "defence in depth beyond the static YAML inspection, 2026.3.1 sets "
                            "HELMFILE_DISABLE_HOOKS and HELMFILE_DISABLE_INSECURE_FEATURES on the "
                            "helmfile subprocess unless the source is explicitly opted in."
                        ),
                    }
                ],
                "workarounds": [
                    {
                        "lang": "en",
                        "value": (
                            "On versions that cannot be upgraded immediately: treat bake input "
                            "artifacts as trusted code, not as data. Restrict which repositories, "
                            "branches and paths a bake stage may reference, and require review "
                            "before a referenced branch changes."
                        ),
                    }
                ],
                "source": {"discovery": "EXTERNAL"},
                "exploitability": "PROOF_OF_CONCEPT",
                "notes": dict(NOTES),
            }
        },
    }
    if published:
        record["cveMetadata"]["datePublished"] = published
    return record


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--cve-id",
        default="CVE-PENDING-spinnaker-rosco-helmfile-hooks-rce",
        help="allocated CVE id; leave unset while it is still pending",
    )
    ap.add_argument(
        "--publish",
        action="store_true",
        help="mark the record PUBLISHED instead of RESERVED",
    )
    ap.add_argument("--date-published", default=None)
    args = ap.parse_args()

    print("deriving CVSS from the vector (not typed in):")
    self_check()
    print(f"  {VECTOR} -> {base_score(VECTOR)}")
    print(f"  {VECTOR_SCOPE_CHANGED} -> {base_score(VECTOR_SCOPE_CHANGED)} (appendix only)")

    state = "PUBLISHED" if args.publish else "RESERVED"
    record = build(args.cve_id, state, args.date_published)

    # Uppercase the slug so the filename matches the sibling projects
    # (CVE-PENDING-*.json), and so an allocated CVE-YYYY-NNNNN keeps its
    # conventional casing rather than being lowercased onto the filesystem.
    slug = args.cve_id.upper() if args.cve_id.startswith("CVE-") else args.cve_id
    suffix = ".cve.json" if args.publish else ".json"
    path = OUT / f"{slug}{suffix}"
    OUT.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
