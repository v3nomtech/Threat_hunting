# Datasets

Sample logs, replay packs, and lab artifacts used to validate hunts and
detection rules in this repo.

> ⚠️ **Nothing in this folder should contain real production data.**
> All samples are either synthetic, drawn from public datasets, or
> generated in a lab. If you contribute a dataset, scrub hostnames,
> usernames, IPs (RFC1918 only or sanitized externals), and any
> identifying metadata before committing.

---

## Layout

```text
datasets/
├── README.md                       # this file
├── synthetic/                      # logs we generate in-lab (Atomic Red Team etc.)
├── public/                         # pointers to / mirrors of public datasets
└── replay-packs/                   # tcpdump pcaps + sysmon evtx bundles per hypothesis
```

(Subfolders are created lazily — only when a real dataset lands.)

---

## Conventions

| Field        | Convention                                                         |
| ------------ | ------------------------------------------------------------------ |
| Filename     | `H-<hypothesis-id>_<short-desc>_<YYYY-MM-DD>.{evtx,pcap,jsonl}`    |
| Manifest     | Each dataset ships with a `manifest.yml` describing source + scope |
| License      | Match upstream license; for in-lab samples, MIT (repo default)     |
| Max size     | Keep individual files <50MB. Use Git LFS if a sample must be larger |

### `manifest.yml` template

```yaml
id: DS-XXX
name: Short descriptive name
hypothesis: H-XXX            # what this validates / replays
collected: 2026-05-12
collector: v3nomtech
source: |
  How was this generated? Atomic Red Team T-id? Custom script?
  Public dataset URL?
sanitization: |
  What was scrubbed before commit (hostnames, IPs, usernames, etc.)
format: evtx | pcap | jsonl | csv
notes: |
  Anything a future hunter needs to know to replay this.
```

---

## Public datasets worth knowing

These are not mirrored here — go fetch them from the source.

- [Security Datasets (formerly Mordor)](https://securitydatasets.com/)
  — pre-recorded ATT&CK-aligned simulations
- [BOTSv3 — Splunk](https://github.com/splunk/botsv3) — large blue-team CTF dataset
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  — single-technique EVTX captures
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) —
  generate your own samples by technique ID
- [DetectionLab](https://detectionlab.network/) — full lab build for
  generating fresh telemetry on demand

---

## Adding a dataset

1. Generate or download the sample.
2. Sanitize aggressively — hostnames, IPs, usernames, tokens.
3. Pick the right subfolder (`synthetic/`, `public/`, `replay-packs/`).
4. Write the `manifest.yml`.
5. Open a PR referencing the hypothesis or rule it validates.
