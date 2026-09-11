"""Domain models for offline OWASP-aligned security assessment evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_STATUSES = {"open", "remediated", "accepted", "false_positive"}
ALLOWED_CATEGORIES = {
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery",
}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    affected_component: str
    evidence: str
    remediation: str
    validation: str
    status: str = "open"
    internet_exposed: bool = False
    authentication_required: bool = True
    sensitive_data: bool = False
    mitre_attack: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Finding":
        required = {
            "finding_id", "title", "category", "severity", "affected_component",
            "evidence", "remediation", "validation"
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing required finding fields: {', '.join(missing)}")
        severity = str(raw["severity"]).lower()
        status = str(raw.get("status", "open")).lower()
        category = str(raw["category"])
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {severity}")
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported status: {status}")
        if category not in ALLOWED_CATEGORIES:
            raise ValueError(f"unsupported OWASP category: {category}")
        if not str(raw["finding_id"]).strip():
            raise ValueError("finding_id cannot be empty")
        return cls(
            finding_id=str(raw["finding_id"]), title=str(raw["title"]), category=category,
            severity=severity, affected_component=str(raw["affected_component"]),
            evidence=str(raw["evidence"]), remediation=str(raw["remediation"]),
            validation=str(raw["validation"]), status=status,
            internet_exposed=bool(raw.get("internet_exposed", False)),
            authentication_required=bool(raw.get("authentication_required", True)),
            sensitive_data=bool(raw.get("sensitive_data", False)),
            mitre_attack=tuple(str(v) for v in raw.get("mitre_attack", [])),
        )


@dataclass(frozen=True)
class Assessment:
    application: str
    environment: str
    authorized: bool
    findings: tuple[Finding, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Assessment":
        for field in ("application", "environment", "authorized", "findings"):
            if field not in raw:
                raise ValueError(f"missing assessment field: {field}")
        if not raw["authorized"]:
            raise ValueError("assessment authorization must be explicitly true")
        if str(raw["environment"]).lower() not in {"local", "lab", "staging"}:
            raise ValueError("only local, lab, or staging evidence is accepted")
        findings = tuple(Finding.from_dict(item) for item in raw["findings"])
        ids = [f.finding_id for f in findings]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate finding_id values are not allowed")
        return cls(str(raw["application"]), str(raw["environment"]).lower(), True, findings)
