# Detection rules

Rules graduate here from `hypotheses/` once a hunt produces a repeatable signal.

## Folders

| Folder      | Format                                   | Use it when…                                  |
| ----------- | ---------------------------------------- | --------------------------------------------- |
| `elastic/`  | Elastic Detection Rule (TOML, EQL/ES\|QL)| You're running Elastic Security               |
| `sigma/`    | [Sigma](https://github.com/SigmaHQ/sigma)| You want vendor-agnostic, convertible logic   |
| `yara/`     | YARA                                     | You're matching file / memory artefacts       |

## Quality bar

Every rule must include:

- **ATT&CK mapping** — tactic + technique IDs
- **Confidence:** Low / Medium / High
- **Noise rating:** estimated alerts/day on a 1k-endpoint estate
- **Test data:** at least one sample log line / artefact that fires the rule
- **Tuning notes:** known FPs and how to filter them
- **Origin:** link back to the `hypotheses/H-XXX` file it came from

## Sigma → Elastic conversion

```sh
pip install sigma-cli
sigma convert -t lucene -p ecs_windows sigma/your-rule.yml > elastic/your-rule.lucene
```

For ES|QL output, use the `esql` backend.
