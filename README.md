# Threat Modelling for Claude Code

Know which design risks remain open, which controls have evidence, and which reviews are out of date. Keep the working history in a database you own.

## Three ways to own it

- **Do it yourself:** free MIT-licensed software, operated through Claude Code, Codex, OpenCode or Cursor. Hosting, an agent subscription and your team's time are separate.
- **We customise it:** Enterprise DNA imports your IriusRisk export, adds your fields and review rules, connects your existing work systems, and builds a web front end or another stack when required. One setup fee, then a retainer for ongoing work.
- **We run it for you:** Omni by Enterprise DNA installs the desk, manages access and backups, prepares the reviews and maintains your version. One setup fee, then a retainer.

[Book a 30-minute call with Sam](https://enterprisedna.co/omni/book/?offer=replace-software&utm_source=github&utm_medium=readme&utm_campaign=iriusrisk).

## Run the synthetic demo

Node 20 or newer. No cloud account or network service is needed for the demo after installing dependencies.

```sh
npm install
npm test
npm run demo
npm run threats -- threat-register
npm run threats -- trust-boundaries
npm run threats -- attention
npm run view
npm run docs
```

Two invented models include an overdue control, an expired risk acceptance, unscored threats and a component without a trust zone. Repeated seeding preserves edits. For real work, use an empty DATA_DIR or DATABASE_URL, run npm run migrate, and do not seed.

## What it does

Model scope, trust zones, components and data flows underpin a threat register and a mitigation queue. Scores use likelihood times impact divided by 100, with each input between 0 and 100. Missing scores stay unknown. The threshold of 60 for attention is a local demo policy, not an industry standard or a probability estimate. No percentage reduction is inferred from a proposed mitigation.

A threat closes only when every attached control has current verification evidence and at least one control exists. Invalidating a control reopens its closed threat. Risk acceptance needs an actor, rationale, evidence and expiry. A later threat assessment invalidates the earlier acceptance. Expired decisions appear in the review queue.

Model reviews record the exact revision considered. Changes to design, threats, controls or decisions advance the revision. A review can record open risks and is never a declaration that the system is secure. Actor names are operator-provided attribution, not electronic signatures.

## Recurring jobs

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

33 CLI commands and 35 slash commands. Use --name=value flags and --json for machine-readable output. Case-insensitive names, partial codes and partial IDs are supported. Ambiguous references print candidates and exit with status 1.

## Ten questions to ask your own records

1. Which high-scoring threats still have no verified controls? (threat-register)
2. Which data movements cross a trust boundary without a recorded threat? (trust-boundaries)
3. Which models changed after the last recorded review? (review-due)
4. Which controls are overdue and who owns them? (control-queue)
5. Which accepted risks have expired or expire in the next month? (acceptance-expiry)
6. Which imported controls claim implementation but have no local verification? (model)
7. Which components have no recorded trust zone? (compliance)
8. Which threats still lack an owner, a due date or an assessment? (compliance)
9. Which review evidence covers the current model revision? (model)
10. Who changed a risk assessment, and what did they record? (activity)

These are real analyses supported by this build. They are not a claim that IriusRisk cannot produce similar answers. Ownership lets your team extend the joins, policies and reports itself.

## Your first hour: ten things to ask for

1. Put our business name and colours in brand.json.
2. Show the models due for review.
3. Show data movements crossing a trust boundary.
4. Show high-scoring threats without verified controls.
5. List expired risk acceptances.
6. Draft the Monday review from the current reports.
7. Preview our IriusRisk OTM JSON export.
8. Compare imported component, flow and threat counts with the source.
9. Add our internal service code with a tested migration.
10. Export a private snapshot before changing a policy.

## Bring your IriusRisk records

```sh
npm run threats -- import iriusrisk --file=imports/project.otm.json --dry-run --actor="Your name"
npm run threats -- import iriusrisk --file=imports/project.otm.json --actor="Your name"
```

[The replace guide](docs/replace-iriusrisk.md) documents the vendor's export route and the exact mapping. The import retains the full original JSON and all extra attributes. Repeating the identical file is a no-op. A changed file cannot overwrite a working model. Imported threats remain open and implementation claims remain unverified until reviewed locally. The supplied fixture is synthetic, not a captured vendor account.

## Documents and read-only views

Three branded HTML reports show the design week, trust boundaries and decisions. Three document types produce a model review paper, a treatment plan and a boundary register per model. Edit brand.json, then run npm run view or npm run docs. Draft commands write private Markdown files. All outputs stay local and send nothing.

## Compliance and scope

[Evidence checks](docs/compliance.md) follow selected NIST SSDF and OWASP threat-modelling practices. They flag missing context, unreviewed changes, missing verification and stale exceptions. This desk does not certify compliance, generate a complete threat model automatically, validate a live system, or replace an authorised security reviewer.

IriusRisk also supplies its maintained threat libraries, automatic threat generation, interactive diagrams, integrations and enterprise access controls. This free base is an independently authored review workflow, with no vendor libraries or code. [Why no front end](docs/why-no-front-end.md) sets out the limits. Scope integrations and access controls before replacing a live team service.

The database uses a trusted owner connection. Restrict operating-system and database access, keep reports and exports private, and maintain native backups. Do not store credentials in model records. A JSON export includes all operational records and original import payloads, but no restore command is included.

## Verification and licence

npm test uses a disposable database and output folder, exercises every CLI command and tests imports, evidence, state changes, dates and HTML escaping. CI includes Windows and Ubuntu with Node 20 and 22, and PostgreSQL 16. TEST_DATABASE_URL must name an empty disposable database.

[Research and scores](docs/research.md). MIT licence. Copyright 2026 Enterprise DNA. IriusRisk is a third-party product. This project is independent and contains no vendor assets or threat libraries.
