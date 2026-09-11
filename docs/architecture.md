# Architecture

## Purpose

This repository models a safe, offline web-application security assessment workflow. It is intentionally designed around synthetic evidence and authorized lab environments so the project demonstrates security-engineering judgment without containing exploit payloads or production targeting logic.

## Data flow

```text
Synthetic assessment JSON
        |
        v
Validated immutable models
        |
        v
Deterministic risk engine
        |
        +--> contextual score / risk class
        +--> stable decision ID
        +--> portfolio metrics
        |
        v
Markdown reporting
        |
        v
Remediation + retest workflow
```

## Components

- `src/models.py` — schema enforcement, environment/authorization gates, OWASP category validation, duplicate rejection.
- `src/analyzer.py` — deterministic scoring, prioritization, metrics, stable decision IDs.
- `src/report.py` — recruiter-facing Markdown rendering with evidence, remediation, validation, and ATT&CK context.
- `src/cli.py` — offline command-line interface.
- `data/synthetic_assessment.json` — fictional application evidence only.
- `tests/test_assessment.py` — unit coverage for scoring, gates, validation, ordering, reporting, and ingestion.

## Trust boundaries

The toolkit does not make outbound HTTP requests, discover hosts, send test traffic, execute payloads, authenticate to applications, or modify infrastructure. Input is treated as untrusted data and is rejected when required fields, authorization, environment, categories, or identifiers violate policy.

## Risk model

The score is deliberately explainable rather than probabilistic. Technical severity establishes a base score, then limited contextual modifiers account for internet exposure, unauthenticated reachability, and sensitive-data impact. Remediated and dispositioned findings receive bounded reductions. The score never substitutes for CVSS, business impact analysis, threat intelligence, or expert review.

## Security design decisions

1. Fail closed on unauthorized or production-labelled evidence.
2. Keep scoring deterministic and auditable.
3. Separate evidence from interpretation.
4. Require both remediation guidance and validation steps in every finding.
5. Preserve ATT&CK as threat-model context, not proof of compromise.
6. Use synthetic identifiers and fixtures to avoid confidential data leakage.
