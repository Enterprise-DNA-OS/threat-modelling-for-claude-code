# Record a time-limited authorised risk decision

Read CLAUDE.md first. Read the current model before changing or drafting its records.

Run:

```sh
npm run threats -- accept-risk --model=DEMO-PORTAL --threat=T-ACCESS --expires=YYYY-MM-DD --reason="Authorised temporary exception" --evidence="private://signed-decision" --actor="Authorised risk owner"
```

Replace examples with the operator's actual references. YYYY-MM-DD is a placeholder, never an inferred deadline. All commands accept --json. Supported flags: --model, --threat, --expires, --reason, --evidence, --actor.

Report the actual result and missing evidence. A review records what was considered, not a finding that the system is secure. Verification and acceptance require an authorised person's evidence. Never invent the actor, risk scores, evidence or dates. If a reference is ambiguous, list the candidates. Drafts stay in drafts/ and never send.
