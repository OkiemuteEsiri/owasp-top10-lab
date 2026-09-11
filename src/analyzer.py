"""Deterministic offline risk analysis for synthetic web security findings."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Assessment, Finding

SEVERITY_WEIGHT = {"critical": 70, "high": 55, "medium": 35, "low": 15, "info": 0}


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    risk_score: int
    risk_class: str
    decision_id: str


def load_assessment(path: str | Path) -> Assessment:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("assessment input must be a JSON object")
    return Assessment.from_dict(raw)


def deterministic_id(finding: Finding) -> str:
    material = "|".join((finding.finding_id, finding.category, finding.affected_component, finding.status))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def score_finding(finding: Finding) -> int:
    score = SEVERITY_WEIGHT[finding.severity]
    if finding.internet_exposed:
        score += 12
    if not finding.authentication_required:
        score += 8
    if finding.sensitive_data:
        score += 10
    if finding.status == "remediated":
        score = max(0, score - 60)
    elif finding.status in {"accepted", "false_positive"}:
        score = max(0, score - 30)
    return min(100, score)


def classify(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def prioritize(findings: Iterable[Finding]) -> list[PrioritizedFinding]:
    result = [
        PrioritizedFinding(f, score_finding(f), classify(score_finding(f)), deterministic_id(f))
        for f in findings
    ]
    return sorted(result, key=lambda item: (-item.risk_score, item.finding.finding_id))


def portfolio_metrics(findings: Iterable[Finding]) -> dict[str, object]:
    items = list(findings)
    open_items = [f for f in items if f.status == "open"]
    category_count = len({f.category for f in items})
    high_risk = sum(score_finding(f) >= 60 for f in open_items)
    return {
        "total_findings": len(items),
        "open_findings": len(open_items),
        "high_or_critical_risk": high_risk,
        "owasp_categories_represented": category_count,
        "remediated": sum(f.status == "remediated" for f in items),
    }


def remediation_ready(finding: Finding) -> bool:
    return bool(finding.remediation.strip() and finding.validation.strip())
