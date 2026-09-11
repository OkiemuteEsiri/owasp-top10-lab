# OWASP Top 10 Security Assessment Lab

A recruiter-facing **Web Application Security / Application Security Engineering** project that models how findings move from controlled evidence through classification, contextual risk prioritization, remediation, retesting, and defensible closure.

The repository is intentionally safe and offline. It demonstrates security-engineering judgment without shipping exploit payloads, credential attacks, active scanners, or production-targeting logic.

## Problem statement

Finding a weakness is only one part of application security. Mature programs must also answer:

- Is the assessment explicitly authorized and in scope?
- What security control failed, and which OWASP weakness class best describes it?
- What is the affected component and business/security context?
- Which findings should be remediated first?
- What objective evidence proves the fix works?
- Can another analyst reproduce the assessment and understand its limitations?

This project implements that workflow using synthetic data and deterministic Python components.

## Architecture

```text
Synthetic JSON evidence
        |
        v
Authorization + environment gate
        |
        v
Immutable validated finding models
        |
        v
Deterministic contextual risk engine
        |
        +--> 0-100 score
        +--> risk class
        +--> stable SHA-derived decision ID
        +--> portfolio metrics
        |
        v
Markdown security report
        |
        v
Remediation -> retest -> evidence-based closure
```

See [`docs/architecture.md`](docs/architecture.md) for component and trust-boundary details.

## Repository structure

```text
.github/workflows/security-ci.yml  Least-privilege CI validation
src/models.py                      Validated immutable assessment models
src/analyzer.py                    Risk scoring, prioritization, metrics
src/report.py                      Markdown report renderer
src/cli.py                         Offline command-line interface
data/synthetic_assessment.json     Fictional web security evidence
tests/test_assessment.py           Unit tests for gates and analysis logic
docs/architecture.md               Technical architecture
docs/methodology.md                Assessment and validation methodology
reports/example-assessment.md      Example recruiter-facing report
templates/                         Existing finding/retest templates
```

## Implemented security controls

### Authorization and scope guardrails

Input fails closed unless authorization is explicitly true. Evidence labelled as production is rejected; only `local`, `lab`, and `staging` environments are accepted.

### Schema and data-quality controls

Every finding requires an identifier, title, supported OWASP category, severity, affected component, evidence, remediation guidance, and validation plan. Duplicate IDs and unsupported states are rejected.

### Contextual risk prioritization

The deterministic 0-100 score starts from technical severity and adds bounded context for:

- internet exposure;
- lack of authentication requirements; and
- sensitive-data implications.

Remediated and dispositioned findings receive controlled reductions. The algorithm is deliberately explainable and does **not** claim to replace CVSS, threat intelligence, or business-specific risk analysis.

### Evidence-based remediation validation

Each finding carries both remediation guidance and an explicit validation method. Closure is framed around proving that the original weakness no longer reproduces while legitimate behavior continues to work.

Examples:

- access-control fixes require negative and positive role tests;
- query-construction fixes require bound-parameter regression evidence;
- logging fixes require field, normalization, correlation, and retention checks;
- security configuration fixes require validation of effective runtime state.

## Synthetic assessment coverage

The example dataset intentionally includes multiple weakness classes:

| ID | OWASP category | Scenario | Status |
|---|---|---|---|
| WEB-001 | A01 Broken Access Control | Administrative export authorization gap | Open |
| WEB-002 | A03 Injection | Unsafe query construction in a training fixture | Open |
| WEB-003 | A09 Logging & Monitoring Failures | Missing correlation fields | Open |
| WEB-004 | A10 SSRF | Incomplete outbound destination policy | Open |
| WEB-005 | A07 Authentication Failures | Session-cookie hardening | Remediated |

All names, routes, identities, and evidence are fictional.

## MITRE ATT&CK context

ATT&CK mappings are used for threat modeling only; they are **not evidence that an intrusion occurred**.

- **T1190 — Exploit Public-Facing Application**: context for public-facing injection/SSRF weaknesses.
- **T1078 — Valid Accounts**: context for authorization abuse using legitimate identities.
- **T1539 — Steal Web Session Cookie**: context for session-management weaknesses.
- **T1070 — Indicator Removal**: context for monitoring/forensic visibility concerns.

## Usage

Requires Python 3.11+ and only the standard library.

```bash
python -m src.cli data/synthetic_assessment.json
```

Write a Markdown report:

```bash
python -m src.cli data/synthetic_assessment.json --report assessment.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Testing

The current unit-test suite covers:

- severity and context scoring;
- 0-100 score bounds;
- remediation score reduction;
- risk-class boundaries;
- deterministic decision IDs;
- duplicate finding rejection;
- authorization enforcement;
- production-environment rejection;
- OWASP category validation;
- prioritization ordering;
- metrics/report rendering; and
- valid JSON ingestion.

## CI/CD security checks

The GitHub Actions workflow uses `contents: read` only and performs:

1. Python source compilation;
2. unit-test discovery/execution; and
3. synthetic assessment parsing plus report generation.

A committed workflow is not treated as proof of a passing build; workflow status must be verified separately.

## Assessment methodology

The workflow is documented in [`docs/methodology.md`](docs/methodology.md):

1. confirm authorization and scope;
2. collect minimal reproducible evidence;
3. classify the failed control;
4. apply contextual prioritization;
5. add ATT&CK threat-model context where useful;
6. remediate at the authoritative enforcement point;
7. retest both failure and legitimate-use cases; and
8. close only with objective validation evidence.

## Example output

[`reports/example-assessment.md`](reports/example-assessment.md) demonstrates executive summary, prioritization, remediation evidence, retest expectations, ATT&CK context, and limitations using fictional data.

## Design principles

- **Fail closed** on unsupported scope or malformed evidence.
- **Deterministic over opaque** for prioritization and identifiers.
- **Evidence before assertion**: every finding describes the observed control condition.
- **Remediation is incomplete without validation**.
- **Threat-model mappings are contextual, not incident claims**.
- **No confidential data**: only synthetic application evidence is committed.
- **No active offensive capability**: this repository does not scan, exploit, fuzz, spray credentials, execute payloads, or send SSRF requests.

## Skills demonstrated

Web application security engineering, OWASP classification, risk-based vulnerability triage, secure design review, evidence handling, Python defensive tooling, deterministic scoring, security reporting, remediation engineering, validation/retest methodology, ATT&CK contextualization, test design, and least-privilege CI/CD.

## Limitations

This is a portfolio lab, not a production DAST/SAST platform or penetration-testing framework. The risk model is intentionally compact and does not incorporate CVSS vectors, live asset inventories, EPSS, external threat intelligence, exploit telemetry, business-owner attestations, or real application traffic. Those integrations should be added only where their provenance and authorization can be validated.

## Roadmap

- Add machine-readable remediation evidence records and closure validation.
- Add OWASP ASVS control references alongside Top 10 classification.
- Add synthetic API authorization matrices for object- and function-level access controls.
- Add SARIF export for defensive CI integration.
- Add trend reporting across repeated synthetic assessment snapshots.
- Add policy-as-code checks for security headers and outbound destination controls using local fixtures.

## Safety and ethics

Use only systems you own or are explicitly authorized to assess. This repository is deliberately structured around fictional, local, and controlled evidence. It contains no real credentials, employer/client data, production endpoints, exploit payloads, persistence mechanisms, or instructions for bypassing security controls.
