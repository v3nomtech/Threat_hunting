---
title: "Hunting WMI Persistence in Elastic — from hypothesis to production detection"
author: v3nomtech
date: 2026-05-12
status: draft
tags: [persistence, wmi, elastic, eql, hunting]
hypothesis: H-001
rule: rules/elastic/wmi-event-subscription-persistence.toml
---

# Hunting WMI Persistence in Elastic

> *"The interesting thing about WMI persistence isn't that it's clever —
> it's that it's still rarely instrumented properly six years after the
> first big writeups."*

This write-up walks through how I took a single hunt hypothesis —
[H-001](../hypotheses/persistence/H-001-wmi-event-subscription.yml) —
from initial idea to a production Elastic detection rule. Three weeks,
two iterations, one true positive caught by the red team.

---

## TL;DR

- WMI event subscriptions (T1546.003) are a quiet persistence mechanism
  with a small, knowable baseline of legitimate creators.
- An EQL `sequence` query that pairs scripting-host activity with writes
  under the `Wbem\CIMOM\` registry hive surfaces ~99% of malicious cases.
- The hardest part wasn't the query — it was the baselining. Three FP
  sources accounted for almost all noise; once excluded, the rule held.

---

## Why WMI persistence is worth hunting

Most Windows persistence today either survives because nobody is looking
for it, or because it lives in a place where the noise/signal ratio is
miserable (registry run keys, scheduled tasks). WMI event subscriptions
sit in a sweet spot: they are powerful enough that real attackers use
them, but rarely created by legitimate software outside a small, named set.

The three relevant objects are:

- `__EventFilter` — the trigger condition (e.g. "every 60s")
- `__EventConsumer` — what to run when the filter fires (CommandLine,
  ActiveScript, etc.)
- `__FilterToConsumerBinding` — the glue between the two

If an attacker has SYSTEM, they can register a `CommandLineEventConsumer`
that runs any binary on a trigger — and it survives reboots without
touching any of the usual persistence locations the IR community trained
defenders to watch.

## The hypothesis

The full hypothesis is in
[hypotheses/persistence/H-001-wmi-event-subscription.yml](../hypotheses/persistence/H-001-wmi-event-subscription.yml).
The compressed version:

> If an adversary establishes WMI persistence, we will see writes under
> `HKLM\Software\Microsoft\Wbem\CIMOM\...` from a process that is NOT
> one of `ccmexec.exe`, EDR-vendor agents, or `mofcomp.exe` during a
> documented patch window.

That's the bet. The hunt is asking "what would I see if it were here?",
not "is it here?".

## Building the query

I started broad and narrowed. The first iteration was just:

```eql
registry where event.action == "modification"
  and registry.path : "*\\Wbem\\CIMOM\\*"
```

…which returned ~1,400 events/day across the estate and was useless.

The improvement came from realizing that legitimate creators (SCCM, EDR
agents) are services, and adversary-created subscriptions almost always
involve an interactive scripting host first. So I paired the two:

```eql
sequence by host.id with maxspan=5m
  [process where event.type == "start" and
    process.name in ("powershell.exe", "wmic.exe", "cscript.exe", "wscript.exe")]
  [registry where event.action == "modification" and
    registry.path like "*\\Software\\Microsoft\\Wbem\\CIMOM\\*"]
```

Same data, ~5 events/day. That ratio shift is the whole game.

## Baselining (the boring, important part)

Over the next week the hunt produced:

| Day | Hits | Root cause                                      |
| --- | ---- | ----------------------------------------------- |
| 1   | 7    | SCCM client health check                        |
| 2   | 6    | SCCM + 1 CrowdStrike on-deploy                  |
| 3   | 4    | SCCM                                            |
| 4   | 4    | SCCM                                            |
| 5   | 5    | SCCM + 1 legacy patching script in finance OU   |
| 6   | 3    | SCCM                                            |
| 7   | 3    | SCCM                                            |

Three signatures explained 100% of the noise:

1. `ccmexec.exe` health-check subscriptions
2. CrowdStrike agent on first deploy
3. A long-running PowerShell script under finance — owned, tracked, allowlisted

I added exclusions, the daily volume dropped to 0–1, and the rule moved
to `Hunting` status.

## The catch

Two weeks in, a purple-team exercise detonated Empire's `wmi` module on
a test host. The detection fired in **90 seconds**, ahead of any of the
other endpoints they expected to trip first. The same query graduated to
`rules/elastic/wmi-event-subscription-persistence.toml` and now runs as
a production detection.

## What I'd do differently

- I baselined for a week. In hindsight two weeks would have caught the
  monthly patching cycle and saved one false positive in production.
- I didn't capture the `EventConsumer` command line in the hunt output —
  that ended up being the most useful pivot during the purple-team
  investigation. Added it to the rule's `investigation_fields`.
- The hunt log in the hypothesis file is the single most valuable
  artifact I produced. Future-me trusts it more than any post-mortem doc.

## References

- [MITRE ATT&CK — T1546.003](https://attack.mitre.org/techniques/T1546/003/)
- [Elastic Security Labs — Hunting for Persistence](https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1)
- [FireEye / Mandiant — WMI vs WMI](https://www.fireeye.com/blog/threat-research/2019/05/wmi-vs-wmi-monitoring-wmi-malicious-uses.html)
- [The hypothesis](../hypotheses/persistence/H-001-wmi-event-subscription.yml)
- [The rule](../rules/elastic/wmi-event-subscription-persistence.toml)
