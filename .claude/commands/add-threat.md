# Record an assessed design threat

Read CLAUDE.md first. Read the current model before changing or drafting its records.

Run:

```sh
npm run threats -- add-threat --model=DEMO-PORTAL --code=T-NEW --name="Describe the unwanted outcome" --component=API --category=Tampering --likelihood=50 --impact=80 --owner="Risk owner" --due=YYYY-MM-DD --rationale="Workshop assessment evidence" --actor="Operator name"
```

Replace examples with the operator's actual references. YYYY-MM-DD is a placeholder, never an inferred deadline. All commands accept --json. Supported flags: --model, --code, --name, --component, --flow, --category, --likelihood, --impact, --owner, --due, --rationale, --actor.

Report the actual result and missing evidence. A review records what was considered, not a finding that the system is secure. Verification and acceptance require an authorised person's evidence. Never invent the actor, risk scores, evidence or dates. If a reference is ambiguous, list the candidates. Drafts stay in drafts/ and never send.
