from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _json_safe(value: Any) -> Any:
    from pathlib import Path
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return value
    return value


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    category: str
    derivation: str
    description: str
    source_field: str | None = None
    raw_value: Any | None = None
    confidence: float | None = None
    citation: str | None = None
    likelihood: str = "medium"
    impact: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = _json_safe(asdict(self))
        if self.confidence is not None:
            payload["confidence_pct"] = round(self.confidence * 100, 1)
        return payload


@dataclass(slots=True)
class AnalysisArtifacts:
    executive_report_id: str
    technical_report_id: str


@dataclass(slots=True)
class AnalysisResult:
    score: int
    subscores: dict[str, int]
    findings: list[Finding]
    threat_matrix: dict[str, list[dict[str, Any]]]
    reports: AnalysisArtifacts | None
    session_summary: dict[str, Any]
    compliance: dict[str, Any] = field(default_factory=dict)
    remediations: list[dict[str, Any]] = field(default_factory=list)
    flow_statistics: dict[str, Any] = field(default_factory=dict)
    threat_intel: list[dict[str, Any]] = field(default_factory=list)
    quantum_resilience: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_ids = (
            {
                "executive": self.reports.executive_report_id,
                "technical": self.reports.technical_report_id,
            }
            if self.reports is not None
            else {}
        )
        return {
            "score": self.score,
            "subscores": self.subscores,
            "findings": [finding.to_dict() for finding in self.findings],
            "threat_matrix": self.threat_matrix,
            "report_ids": report_ids,
            "session_summary": _json_safe(self.session_summary),
            "compliance": _json_safe(self.compliance),
            "remediations": _json_safe(self.remediations),
            "flow_statistics": _json_safe(self.flow_statistics),
            "threat_intel": _json_safe(self.threat_intel),
            "quantum_resilience": _json_safe(self.quantum_resilience),
        }
