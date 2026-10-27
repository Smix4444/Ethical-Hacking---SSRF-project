# toolkit/

**Phase 4 (seeded in Phase 2).** Our own Python toolkit that detects and
demonstrates SSRF against the lab app, organised along the **Cyber Kill Chain**.

## What's here now

| File | Purpose |
|------|---------|
| `ssrf_payloads.py` | Generates alternate IP encodings and candidate URLs to **test the lab's own filters**. No network activity — it only transforms an address you pass in. |
| `ssrf_scan.py` | Fires the payloads at the lab app's `/fetch` across levels L0–L3 and prints a BLOCKED/FETCHED/LOOT matrix. Can also compare **no-WAF vs via-WAF**. Talks **only** to the lab app you point it at. Standard library only. |

### Generate payloads

```
python toolkit/ssrf_payloads.py 169.254.169.254
```

It prints the dotted-decimal, trailing-dot, decimal-integer, hex, dotted-hex,
dotted-octal and IPv6-mapped forms of the address, each as a ready URL. These
all point at the same host at the socket layer — which is why a filter that
inspects the *text* of a URL (the L1 blocklist) can be fooled.

### Reproduce the comparison table

With the lab running (`docker compose up`), from the repo root:

```
python toolkit/ssrf_scan.py
```

It scans every payload against L0, L1, L2 and L3 and prints a matrix, so the
whole "which payload works at which level" table reproduces in one command.
`LOOT` means the fake credentials came back.

### Compare with vs without the WAF (Phase 4)

```
python toolkit/ssrf_scan.py --compare
```

Hits each payload directly (`--base`, default `:8088`, no WAF) and through the
WAF edge (`--waf-base`, default `:8090`) at one level (default L0) and prints the
two columns side by side. `WAF-403` means ModSecurity/CRS refused the request;
anything else means it passed the WAF and reached the app.

## Planned capabilities (later phases)

- Detect SSRF, including **blind** SSRF via out-of-band (OOB) callbacks.
- Automate the filter / WAF bypasses we do by hand.
- Read the mock metadata service to prove impact (fake creds only).
- Map each step to a Cyber Kill Chain stage for the report.

> ⚠️ **Lab-only.** Point this tool **exclusively** at the lab targets in this
> repository. Using it against any system you do not own or lack written
> permission to test is illegal. See [../SECURITY.md](../SECURITY.md).
