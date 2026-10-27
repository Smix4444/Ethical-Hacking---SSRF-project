# toolkit/

**Phase 4 (seeded in Phase 2).** Our own Python toolkit that detects and
demonstrates SSRF against the lab app, organised along the **Cyber Kill Chain**.

## What's here now

| File | Purpose |
|------|---------|
| `ssrf_payloads.py` | Generates alternate IP encodings and candidate URLs to **test the lab's own filters**. No network activity — it only transforms an address you pass in. |

### Try it

```
python toolkit/ssrf_payloads.py 169.254.169.254
```

It prints the dotted-decimal, trailing-dot, decimal-integer, hex, dotted-hex,
dotted-octal and IPv6-mapped forms of the address, each as a ready URL. These
all point at the same host at the socket layer — which is why a filter that
inspects the *text* of a URL (the L1 blocklist) can be fooled.

## Planned capabilities (later phases)

- Detect SSRF, including **blind** SSRF via out-of-band (OOB) callbacks.
- Automate the filter / WAF bypasses we do by hand.
- Read the mock metadata service to prove impact (fake creds only).
- Map each step to a Cyber Kill Chain stage for the report.

> ⚠️ **Lab-only.** Point this tool **exclusively** at the lab targets in this
> repository. Using it against any system you do not own or lack written
> permission to test is illegal. See [../SECURITY.md](../SECURITY.md).
