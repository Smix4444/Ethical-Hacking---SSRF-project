# toolkit/ — `ssrfkit`

**Phase 4/6.** Our own SSRF toolkit for the lab, forged into one coherent CLI
(`ssrfkit.py`) whose subcommands follow the **Cyber Kill Chain**. It reuses the
individual modules underneath rather than duplicating them.

> ⚠️ **Lab-only.** Point this **exclusively** at the lab's own services. Using
> these techniques against any system you do not own or lack written permission
> to test is illegal. See [../SECURITY.md](../SECURITY.md).

## The unified tool: `ssrfkit`

`ssrfkit` is designed to run **inside** the lab network (so it can reach the
internal services). With the lab running (`docker compose up`), from the repo
root:

```
docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" python:3.12-slim python /t/ssrfkit.py full
```

Swap `full` for any subcommand. Standard library only — no installs needed.

### Subcommands → Cyber Kill Chain

| Subcommand | Kill-chain stage | What it does |
|------------|------------------|--------------|
| `recon` | Reconnaissance | Detects SSRF, including **blind** SSRF: makes the app call the OOB listener with a unique token and confirms the callback. |
| `weaponize` | Weaponization | Generates the alternate IP-encoding bypass payloads (reuses `ssrf_payloads`). |
| `exploit` | Exploitation / Delivery | Fires the payload set at the app **without** and **through** the WAF, reporting BLOCKED/FETCHED/LOOT/WAF-403 (reuses `ssrf_scan`). |
| `loot` | Actions on Objectives | Exfiltrates the fake IAM credentials via SSRF (and shows this fail cleanly under IMDSv2). |
| `audit` | Defensive | Checks whether metadata enforces IMDSv1 or IMDSv2 (reuses `imds_check`). |
| `rebind` | — | **DNS rebinding**: resets the `rebind.lab` DNS, runs the TOCTOU level (L2.5) → LOOT, then L3 → BLOCKED, showing the TTL-0 flip. |
| `report` | — | Runs every check live and writes a **professional pentest scorecard** (HTML + Markdown): exec summary, findings with severity/evidence/remediation, kill-chain + MITRE ATT&CK, a live scorecard table. |
| `full` | — | Runs recon → weaponize → exploit → loot as a guided demo. |

Every subcommand supports `--help`, and common flags let you retarget:
`--app`, `--waf`, `--oob`, `--metadata`, `--metadata-ip`, `--level {0..3}`,
`--no-color`.

### Examples

```
# Full guided kill-chain demo at L0
docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" python:3.12-slim python /t/ssrfkit.py full

# Just confirm blind SSRF out-of-band
... python /t/ssrfkit.py recon

# Exploit matrix with/without WAF at level 1
... python /t/ssrfkit.py exploit --level 1

# Defensive: is IMDSv2 enforced?
... python /t/ssrfkit.py audit

# DNS rebinding: TOCTOU level (L2.5) falls, L3 resolve-then-pin holds
... python /t/ssrfkit.py rebind

# Generate the pentest scorecard (HTML + Markdown) into reports/
docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" -v "${PWD}/reports:/out" python:3.12-slim python /t/ssrfkit.py report --out /out
```

## Underlying modules (reused, still runnable on their own)

| File | Purpose |
|------|---------|
| `ssrf_payloads.py` | Generates alternate IP encodings / candidate URLs. No network activity. |
| `ssrf_scan.py` | Fires payloads at `/fetch` across L0–L3; matrix mode and `--compare` (no-WAF vs via-WAF). |
| `imds_check.py` | Audits a metadata endpoint: IMDSv1 plain GET vs the IMDSv2 token flow. |

`ssrfkit` imports these — one source of truth, no duplication. They remain usable
standalone (e.g. `python toolkit/ssrf_scan.py` from the host against `:8088`).

### Standalone quick reference

```
python toolkit/ssrf_payloads.py 169.254.169.254          # list encodings
python toolkit/ssrf_scan.py                              # L0-L3 matrix (host -> :8088)
python toolkit/ssrf_scan.py --compare                    # no-WAF vs via-WAF
```

## Realism note

The `recon` OOB check uses the internal `oob-listener` service. In a real
engagement that role is an attacker-owned server such as **Burp Collaborator** or
**interactsh**. Here everything stays inside the isolated lab.
