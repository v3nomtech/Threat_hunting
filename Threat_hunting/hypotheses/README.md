# Hypotheses

Each subfolder maps to a [MITRE ATT&CK tactic](https://attack.mitre.org/tactics/enterprise/). A hypothesis lives in the folder of the tactic it primarily targets — even if it touches several.

## Folder map

| Folder                  | ATT&CK tactic            | ID     |
| ----------------------- | ------------------------ | ------ |
| `initial-access/`       | Initial Access           | TA0001 |
| `execution/`            | Execution                | TA0002 |
| `persistence/`          | Persistence              | TA0003 |
| `privilege-escalation/` | Privilege Escalation     | TA0004 |
| `defense-evasion/`      | Defense Evasion          | TA0005 |
| `credential-access/`    | Credential Access        | TA0006 |
| `discovery/`            | Discovery                | TA0007 |
| `lateral-movement/`     | Lateral Movement         | TA0008 |
| `collection/`           | Collection               | TA0009 |
| `command-and-control/`  | Command and Control      | TA0011 |
| `exfiltration/`         | Exfiltration             | TA0010 |
| `impact/`               | Impact                   | TA0040 |

## Naming convention

`H-XXX-short-slug.yml`

- `XXX` — zero-padded sequential ID (H-001, H-002, …)
- `short-slug` — kebab-case, max 5 words, describes the signal

Example: `H-001-wmi-event-subscription-persistence.yml`

## Template

See [`_template.yml`](./_template.yml). Every field is required. If you don't have data for a field, write `unknown` rather than deleting it — that's still useful signal.

## Lifecycle

```
Draft  →  Hunting  →  Productionized  →  Retired
```

- **Draft** — idea, not yet tested against data
- **Hunting** — actively running, gathering baseline
- **Productionized** — graduated into `rules/` as a detection
- **Retired** — superseded, no longer useful, or coverage moved upstream
