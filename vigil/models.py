"""Core data types shared by every check, the scorer, the CLI and the web app."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Lower rank = more severe. Used for sorting."""
        return list(Severity).index(self)


@dataclass
class Finding:
    check: str
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    target: str
    final_url: str
    started_at: str
    duration_ms: int
    score: int
    grade: str
    findings: list[Finding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "passed": self.passed,
            "errors": self.errors,
            "summary": self.summary(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScanResult:
        findings = [Finding(**{**f, "severity": Severity(f["severity"])}) for f in d.get("findings", [])]
        return cls(
            target=d["target"], final_url=d["final_url"], started_at=d["started_at"],
            duration_ms=d["duration_ms"], score=d["score"], grade=d["grade"],
            findings=findings, passed=d.get("passed", []), errors=d.get("errors", []),
        )

    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
