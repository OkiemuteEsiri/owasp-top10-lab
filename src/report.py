"""Recruiter-facing report rendering for OWASP assessment results."""
from __future__ import annotations

from .analyzer import portfolio_metrics, prioritize
from .models import Assessment


def render_markdown(assessment: Assessment) -> str:
    metrics = portfolio_metrics(assessment.findings)
    rows = prioritize(assessment.findings)
    lines = [
        f"# Web Security Assessment — {assessment.application}",
        "",
        f"**Environment:** {assessment.environment}",
        "**Authorization:** explicitly confirmed for lab use",
        "",
        "## Executive metrics",
        "",
        f"- Total findings: {metrics['total_findings']}",
        f"- Open findings: {metrics['open_findings']}",
        f"- High/Critical contextual risk: {metrics['high_or_critical_risk']}",
        f"- OWASP categories represented: {metrics['owasp_categories_represented']}",
        f"- Remediated findings: {metrics['remediated']}",
        "",
        "## Prioritized findings",
        "",
        "| ID | Finding | OWASP | Severity | Risk | Status |",
        "|---|---|---|---:|---:|---|",
    ]
    for item in rows:
        f = item.finding
        lines.append(
            f"| {item.decision_id} | {f.title} | {f.category.split('-')[0]} | "
            f"{f.severity} | {item.risk_score} ({item.risk_class}) | {f.status} |"
        )
    lines += ["", "## Remediation and validation", ""]
    for item in rows:
        f = item.finding
        lines += [
            f"### {f.finding_id} — {f.title}",
            f"**Affected component:** {f.affected_component}",
            f"**Evidence:** {f.evidence}",
            f"**Remediation:** {f.remediation}",
            f"**Validation:** {f.validation}",
            f"**MITRE ATT&CK context:** {', '.join(f.mitre_attack) if f.mitre_attack else 'Not mapped'}",
            "",
        ]
    lines += [
        "## Limitations",
        "",
        "This report is produced from synthetic, offline evidence. Scores support prioritization; they do not replace CVSS, threat intelligence, business context, or manual security review.",
    ]
    return "\n".join(lines)
