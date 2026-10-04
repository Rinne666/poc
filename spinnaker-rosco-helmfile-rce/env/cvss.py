#!/usr/bin/env python3
"""Compute a CVSS v3.1 base score from a vector string.

The repository checklist requires the vector and score to be *derived*, not
guessed, so the score quoted in README.md / cve/ comes from running this.

    python3 env/cvss.py AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
"""
import math
import sys

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_UNCHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number to 1 decimal >= value."""
    return math.ceil(value * 10.0 - 1e-9) / 10.0


def base_score(vector: str) -> float:
    parts = dict(p.split(":", 1) for p in vector.split("/"))
    scope = parts["S"]

    pr_weight = (PR_UNCHANGED if scope == "U" else PR_CHANGED)[parts["PR"]]
    exploitability = (
        8.22
        * WEIGHTS["AV"][parts["AV"]]
        * WEIGHTS["AC"][parts["AC"]]
        * pr_weight
        * WEIGHTS["UI"][parts["UI"]]
    )

    impact_sub = 1 - (
        (1 - WEIGHTS["C"][parts["C"]])
        * (1 - WEIGHTS["I"][parts["I"]])
        * (1 - WEIGHTS["A"][parts["A"]])
    )
    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15

    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + exploitability, 10.0))
    return roundup(min(1.08 * (impact + exploitability), 10.0))


if __name__ == "__main__":
    for vec in sys.argv[1:]:
        print(f"{vec}  ->  {base_score(vec)}")
