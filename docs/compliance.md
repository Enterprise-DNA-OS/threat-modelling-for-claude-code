# Design review evidence checks

Checked 2026-11-05. These checks implement local evidence policies inspired by published practices. They are not legal rules, a full standards assessment or a security certification. The operator chooses the applicable framework and an authorised reviewer judges adequacy.

Sources:

- [NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final), especially PW.1 design requirements and risk modelling, and PW.2 design review.
- [OWASP Threat Modeling Process](https://community.owasp.org/Threat_Modeling_Process), which describes scoping, threats, countermeasures and assessment.
- [OWASP Threat Modeling Project](https://owasp.org/www-project-threat-modeling/), the current project overview.

| Check | Records tested | Basis and limit |
|---|---|---|
| scope-owner and design-inventory | Scope, responsible owner and component inventory | SSDF PW.1 and OWASP scoping, presence only |
| trust-zone and flow-context | Component zones, data movement and protocol context | OWASP trust levels and data flow modelling, no network inspection |
| boundary-review | Crossing or unknown-zone flows without threat instances | Local prompt to assess a boundary, not proof one threat covers it |
| risk-assessment | Likelihood, impact and rationale | SSDF risk modelling and OWASP threat analysis, operator-assessed values |
| treatment-owner and control-owner | Owner and due date for treatment work | Local accountability policy supporting SSDF design review |
| control-evidence and closure-evidence | Latest verification with a named actor and evidence reference | SSDF review and OWASP assessment, evidence references are not automatically fetched |
| acceptance-expired | Expiry of a recorded risk acceptance | Local exception policy, no universal statutory expiry is claimed |
| review-current and review-date | Revision covered by the last review and next date | SSDF PW.2 and local review cadence |
| high-open | Open threat score at or above 60 | Local attention threshold, not a NIST or OWASP severity standard |

A control has a sequence of immutable verification records. The latest result controls its current state. Invalidating a control reopens a closed threat. Threat acceptance expires on its recorded calendar date, inclusive, in UTC. Reassessment of the threat makes an older acceptance ineffective.

A model review records the exact revision and the reviewer's note even when open risks remain. This is a record of review, never a release approval. Material changes increment the revision. Evidence checks expose gaps and do not assert secure design, regulatory compliance, a penetration test result or the absence of vulnerabilities.

This trusted local tool does not authenticate the actor name. Use controlled database access and independent evidence records for an operational deployment. The database owner can change database rules, so append-only triggers are an operational safeguard, not cryptographic tamper-proofing.
