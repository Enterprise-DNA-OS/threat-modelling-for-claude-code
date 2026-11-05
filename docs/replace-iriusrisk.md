# Switch from IriusRisk

## Export from the vendor

The [vendor CLI](https://github.com/iriusrisk/iriusrisk-cli) documents an OTM export with JSON format. In your own authorised IriusRisk environment, export the selected project as OTM JSON. The vendor example is iriusrisk otm export PROJECT_ID --format json. Check its installed help for the output-file option and save only the OTM object, not a console wrapper. Keep the exported file private.

The [Enterprise plan](https://www.iriusrisk.com/plans) offers full model exports. Community diagram XML is not a full OTM export and is not supported here. This importer does not require a vendor token because it reads the file you already exported.

## One command to import

Run npm run threats -- import iriusrisk --file=imports/project.otm.json --actor="Your name". Add --dry-run first to validate and see counts without writes. The expected format is [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel), versions 0.1.0 or 0.2.0 encoded as JSON. YAML, native IriusRisk XML and draw.io XML need a separately reviewed conversion.

| Source | Working record |
|---|---|
| project id, name, owner, description | Model code, name, owner and scope |
| trustZones and risk.trustRating | Zones and trust rating |
| components and parent | Components, with inherited zone for nested components |
| dataflows source and destination | Data flows between known components |
| dataflows target in the README example | Accepted alias for destination, conflicting values rejected |
| threats definitions referenced by components or flows | A separate threat instance for each surface |
| threat likelihood, impact and comments | Assessment values and rationale |
| mitigations referenced by threat instances | Unverified controls |
| source states, assets, unused definitions, nesting, layout, tags and attributes | Preserved in original JSON and source fields |

Unknown identifiers, duplicate definitions and component-parent cycles fail before writes. A database error rolls back the entire import. Missing risk values remain unknown. Optional collections may be null. Scores accept up to two decimals from 0 to 100. Imports do not infer control owners or deadlines from arbitrary custom attributes.

No vendor status is a local security decision. A source threat marked mitigated becomes open. A mitigation marked implemented becomes unverified. Record the owner and due date, then attach real test evidence with verify-control. Record risk acceptance again only with the authorised decision, its expiry and its evidence.

## Check before switching

Compare project, component, flow, threat-instance and mitigation-instance counts. A shared definition becomes more than one instance when it appears on multiple surfaces. Unreferenced definitions are preserved but do not enter the working threat register. Assets remain source context, not a separately queryable asset catalogue. Nested zones and diagram coordinates stay in the original payload. Protocols, workflow ownership and due dates need a review.

Use update-model, set-component-zone, set-flow-context, assess-threat and assign-control to complete the missing context. Review source-only records and any vendor-generated threats before deciding your coverage is sufficient. The fixture is independently invented from the published format. Run a real export through a test database before relying on the mapping.

## Updates and rollback

The same byte-for-byte file imports once. A modified export with the same project id is rejected to protect local work. Use a distinct project version id for a separate comparison model, or design a reviewed merge. No silent overwrite or automatic synchronisation exists.

Keep IriusRisk and your original export until all counts, decisions and required integrations have been checked. The JSON snapshot exports every working record, including original import text and activity. Keep native database backups for a full restore. This project does not copy vendor threat libraries, run an IriusRisk account or cancel a subscription.
