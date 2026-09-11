# Assessment Methodology

## 1. Authorization and scope

Every assessment record must explicitly assert authorization and identify the environment as `local`, `lab`, or `staging`. Production-labelled input is rejected by design.

## 2. Evidence collection

Evidence should be reproducible, minimal, and synthetic where possible. Capture the affected route/component, observed control condition, role or trust context, expected behavior, actual behavior, and sufficient metadata for another reviewer to reproduce the conclusion without exposing secrets.

## 3. OWASP classification

Map the control weakness to the relevant OWASP Top 10 2021 category. Classification communicates weakness class; it is not the same as severity. Unsupported categories are rejected so reporting remains consistent.

## 4. Contextual prioritization

Severity is the starting point. The engine then considers three transparent factors: internet exposure, absence of authentication requirements, and sensitive-data implications. These modifiers help order remediation work but do not replace CVSS or a business-specific risk methodology.

## 5. ATT&CK contextualization

ATT&CK mappings describe plausible adversary behavior associated with a weakness. They are threat-model context only. A mapping must never be interpreted as evidence that the behavior occurred.

Examples in the synthetic dataset include:

- `T1190` — Exploit Public-Facing Application
- `T1078` — Valid Accounts
- `T1539` — Steal Web Session Cookie
- `T1070` — Indicator Removal

## 6. Remediation workflow

1. Assign a technical owner.
2. Fix the control at the authoritative enforcement point.
3. Add regression coverage where feasible.
4. Retest using the original evidence conditions.
5. Verify expected negative and positive cases.
6. Record objective validation evidence.
7. Change status only after validation is complete.

## 7. Validation expectations

A remediation is not considered complete because a ticket is closed or code changed. Validation should confirm that the original weakness no longer reproduces and that legitimate functionality remains intact. For access-control issues, this means testing both unauthorized denial and authorized success. For logging issues, it means checking field presence, correlation, normalization, and retention. For configuration issues, it means verifying the effective runtime state rather than only source configuration.

## 8. Limitations

This project does not perform active scanning, fuzzing, exploitation, credential testing, SSRF requests, SQL injection attempts, or payload execution. It demonstrates assessment engineering, evidence handling, risk communication, and remediation validation using controlled offline data.
