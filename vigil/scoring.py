"""Turn findings into a 0-100 score and a letter grade.

The weights are a judgement call. They're kept in one place so they're easy to
tune and to explain in a README or interview.
"""

from __future__ import annotations

from .models import Finding, Severity

PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (55, "D"), (0, "F")]


def score(findings: list[Finding]) -> tuple[int, str]:
    total = 100 - sum(PENALTY[f.severity] for f in findings)
    # A single critical issue (e.g. leaked .env) caps the grade, no matter how
    # good the headers are.
    if any(f.severity is Severity.CRITICAL for f in findings):
        total = min(total, 50)
    total = max(0, min(100, total))
    grade = next(g for threshold, g in GRADES if total >= threshold)
    return total, grade
