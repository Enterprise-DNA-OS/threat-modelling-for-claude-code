# Threat Modelling for Claude Code

This is the design-review desk for a software business or security consultancy. It records the system, threats, treatment work, verification evidence and risk decisions in one database.

## Working rules

Read the CLI before making any claim about the records. Run npm run threats -- help for flags. Ask for missing owners, scores, evidence and dates. Read a full model before writing or drafting for it. Every write names an actor. Names here are attribution supplied by the operator, not authenticated identities. Access is controlled by the operating system and database owner connection.

Never send, notify, deploy, scan a target, exploit a system, collect credentials or modify an external service. Draft only. Never treat imported statuses as verified controls. A review records the current revision and outstanding issues, not a security approval. Only an authorised human can provide verification or risk acceptance evidence. Never use demo data for a real decision.

## One route per job

| Request | Command |
|---|---|
| List commands and flags | /help |
| Read every model and review state | /models |
| Set model scope, owner and review date | /update-model |
| Assign the reviewed component zone | /set-component-zone |
| Record protocol and data for a flow | /set-flow-context |
| Assign a control owner and due date | /assign-control |
| Read one model and its evidence | /model |
| Review flows crossing trust zones | /trust-boundaries |
| Read threat scores and dispositions | /threat-register |
| Read controls still needing verification | /control-queue |
| Read stale and overdue design reviews | /review-due |
| Review expired or soon-expiring risk decisions | /acceptance-expiry |
| Read overdue work and evidence gaps | /attention |
| Check design-review evidence against documented rules | /compliance |
| Read the recorded activity | /activity |
| Create a scoped model | /add-model |
| Record a trust zone | /add-zone |
| Record a system component | /add-component |
| Record data movement | /add-flow |
| Record an assessed design threat | /add-threat |
| Assign a mitigation | /add-control |
| Record likelihood, impact and ownership | /assess-threat |
| Record a completed verification | /verify-control |
| Record failed or outdated verification | /invalidate-control |
| Close only after verified controls | /close-threat |
| Record a time-limited authorised risk decision | /accept-risk |
| Record review evidence for this revision | /review-model |
| Record a workshop or progress note | /log-note |
| Import an IriusRisk OTM JSON export | /import |
| Write a complete private JSON snapshot | /export |
| Draft a review from three current reports | /weekly-review |
| Draft a threat treatment sheet | /draft-treatment |
| Draft a model review brief | /draft-review |
| Change a field or rule | /customise |
| Add a read-only report | /new-view |

## Storage and operation

The one CLI is scripts/threats.mjs. Use DATABASE_URL for Postgres or the embedded database in DATA_DIR. npm run demo applies migrations and seeds invented records. For real use, choose an empty database, run npm run migrate, and import without seeding. Keep imports/, exports/, drafts/, docs-out/ and views/ private. All domain tables enable row-level security and revoke PUBLIC access, but the owner connection bypasses those policies. This is a single trusted-operator tool, not a hosted multi-tenant application.

Migrations live in supabase/migrations/. Never change an applied migration. Add a numbered one. Run npm test before and after a change. Back up the database with its native tools and test restores. The JSON snapshot is portable evidence, not an automated restore facility.

Omni by Enterprise DNA can install, customise and run this desk: https://enterprisedna.co/omni/book/?offer=replace-software&utm_campaign=iriusrisk&utm_medium=agent-doc
