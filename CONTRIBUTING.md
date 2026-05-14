# Contributing

Thanks for thinking about contributing — this repo gets better when more hunters share what they've learned.

## How to contribute

### Adding a hypothesis

1. Copy [`hypotheses/_template.yml`](./hypotheses/_template.yml)
2. Save it under the matching ATT&CK tactic folder, e.g. `hypotheses/persistence/H-0XX-short-slug.yml`
3. Fill **every** field — incomplete hypotheses get rejected because they aren't reproducible
4. Add a row to the hypotheses table in `README.md`

### Adding a detection rule

1. Pick the right format folder: `rules/elastic/`, `rules/sigma/`, or `rules/yara/`
2. Use the matching `_template` file in that folder
3. Include:
   - ATT&CK tactic + technique IDs
   - Confidence rating (Low / Medium / High)
   - Noise rating (alerts/day expected on a 1k-endpoint estate)
   - Sample log / test data that fires the rule
   - Known false positives

### Adding a write-up

- Drop the markdown into `writeups/` with a date prefix: `2026-05-12-hunting-wmi-persistence.md`
- If it's also on Medium, add it to the README write-ups table

## PR checklist

- [ ] File lives in the correct folder
- [ ] Template is fully filled in
- [ ] ATT&CK ID is in the PR title (e.g. `[T1547.001] Run key persistence hunt`)
- [ ] No secrets, real customer data, or PII included
- [ ] README tables updated if applicable

## Style notes

- **Be specific.** "Suspicious PowerShell" is not a hypothesis — "PowerShell with encoded command launched by Office process within 5min of email delivery" is.
- **Cite sources.** ATT&CK page, DFIR Report, vendor blog — whatever inspired the hunt.
- **Show your work.** False positives, noise levels, and dead ends are as valuable as wins.

## Code of conduct

Be kind. Critique ideas, not people. Assume good faith.
