# Web Security Assessment — Northstar Training Portal

**Environment:** lab  
**Authorization:** explicitly confirmed for lab use

## Executive summary

The synthetic assessment contains five findings across five OWASP Top 10 categories. Highest remediation priority is assigned to the deliberately insecure search path because it combines High technical severity, internet exposure, unauthenticated reachability, and sensitive-data context. One authentication-control finding is retained as remediated to demonstrate evidence-based closure and regression expectations.

## Prioritized findings

| Finding | Category | Severity | Context | Disposition |
|---|---|---|---|---|
| WEB-002 Legacy search query construction | A03 Injection | High | Internet exposed, unauthenticated, sensitive data | Remediate first |
| WEB-001 Administrative export authorization | A01 Broken Access Control | High | Internet exposed, authenticated, sensitive data | High priority |
| WEB-004 Outbound destination policy | A10 SSRF | High | Internet exposed | High priority |
| WEB-003 Incomplete security audit correlation | A09 Logging & Monitoring | Medium | Detection/forensics impact | Planned remediation |
| WEB-005 Session cookie hardening | A07 Authentication Failures | Medium | Validated fix | Remediated |

## Remediation validation examples

### WEB-001

**Control objective:** Only explicitly authorized administrator roles can export administrative datasets.  
**Fix:** Centralize server-side policy enforcement for privileged objects/actions.  
**Retest:** Repeat the synthetic role matrix. Non-admin roles must receive `403`; the approved administrator case must continue to succeed.  
**Evidence required for closure:** test results showing both negative and positive cases, linked to the corrected authorization policy version.

### WEB-002

**Control objective:** User-supplied values cannot alter query structure.  
**Fix:** Use bound parameters and least-privileged database permissions.  
**Retest:** Execute benign metacharacter regression cases and verify application behavior plus driver-level parameter binding.  
**Evidence required for closure:** integration-test output demonstrating parameterized execution and unchanged legitimate search behavior.

### WEB-003

**Control objective:** Security-relevant events are attributable and correlatable.  
**Fix:** Emit actor, request correlation, action, resource, outcome, source context, and UTC timestamps.  
**Retest:** Generate controlled lab events and verify required fields are present, normalized, queryable, and retained.

## ATT&CK context

Mappings are used only to communicate plausible adversary behavior associated with weaknesses. They do not assert compromise.

- T1190 — Exploit Public-Facing Application
- T1078 — Valid Accounts
- T1539 — Steal Web Session Cookie
- T1070 — Indicator Removal

## Limitations

This report is based entirely on fictional offline evidence. No target discovery, scanning, exploitation, credential testing, payload execution, or external requests were performed.
