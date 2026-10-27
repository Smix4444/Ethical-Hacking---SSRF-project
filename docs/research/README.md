# Reality dossier — SSRF in the wild

How this lab maps onto **real** breaches and CVEs. This bridges the gap between
our sandbox and production software, and directly addresses the feedback to
"test the relevance of the lab against real applications."

> 🔬 **Research only.** Everything below is public-record analysis. **No real
> application was attacked, scanned, or contacted** as part of this project. The
> only systems exercised were our own lab containers. See [../../SECURITY.md](../../SECURITY.md).

---

## 1. The canonical case: Capital One (2019)

The textbook SSRF breach, and the blueprint for this entire lab.

**The attack chain:**

| Step | What happened | In our lab |
|------|---------------|------------|
| 1. SSRF | A **misconfigured WAF** (ModSecurity on EC2) was tricked into making a server-side request. | `vulnerable-app` at **L0** — the server fetches an attacker-supplied URL. |
| 2. Reach IMDS | That request hit the EC2 **Instance Metadata Service** at `169.254.169.254` (IMDSv1 — a plain GET, no auth). | `metadata-service` at `169.254.169.254`, `IMDS_MODE=v1`. |
| 3. Steal creds | IMDSv1 returned the instance role's **temporary IAM credentials**. | `GET /latest/meta-data/iam/security-credentials/…` → our fake `ASIA…` creds. |
| 4. Impact | The role had **over-broad S3 permissions**; the creds were used to list and copy data from S3 buckets (~100M records). | Represented by the "LOOT" step — reading the crown-jewel creds. |

**What would have stopped it — and what we built to prove each:**

- The WAF was *present* but was itself the SSRF'd component — a WAF is not a cure.
  Our **Fase 7A** test reproduces this: the WAF blocked the obvious IP payloads
  but was **bypassed by a hostname/redirect**.
- **Correct app-side validation** (our **L3 resolve-then-pin** + redirect
  re-validation) blocks the request regardless of encoding, DNS or redirect.
- **IMDSv2** (token via `PUT` + header) — AWS's direct hardening response —
  breaks a bare-GET SSRF. Our `IMDS_MODE=v2` proves the same attack stalls on `401`.

*Sources:* [Fastly — Preventing SSRF](https://www.fastly.com/blog/preventing-server-side-request-forgery-ssrf) ·
[AWS — Defense in depth (IMDSv2)](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)

---

## 2. Recent real SSRF vulnerabilities ↔ our lab

Every weakness our lab demonstrates has a real-world counterpart. The recurring
root cause is exactly the one our L1/L2 levels model: **checking the URL string
or a denylist instead of resolving, normalizing and pinning the destination IP.**

| Real vulnerability | What it was | Maps to our lab |
|--------------------|-------------|-----------------|
| **CVE-2024-4084** — AnythingLLM | Fix used a **regex denylist** of private ranges (`192.`,`172.`,`10.`,`127.`) + http/https only. Bypassed with **decimal/octal/hex/IPv6-mapped** IPs; the check never canonicalized the host, resolved DNS, or re-validated redirects. | **L1 + L2** bypassed by our encoding payloads; the exact gaps our **L3** closes. |
| **CVE-2024-29415** — `node-ip` (incomplete fix of **CVE-2023-42282**) | Alternate-notation IPs (`127.1`, `012.1.2.3`, `::ffff:127.0.0.1`) were wrongly classified as public by `isPublic`. | Our `decimal-integer`, `dotted-octal`, `ipv6-mapped` payloads vs a naive parser. |
| **CVE-2024-24759** — MindsDB | SSRF protection bypassed via **DNS rebinding**: the name validated as safe, then rebinds to an internal IP before the fetch. | Our **L2 DNS bypass** (`cdn-assets.lab`) and the check-vs-use flaw; fixed by **L3 pinning**. |
| **CrewAI** advisory | `validate_url` did one-shot DNS + blocklist, then returned the **original** URL; an HTTP **redirect** then reached internal metadata. | Our **L2 redirect bypass** via `preview-service.lab`. |
| **LLaMA-Factory** advisory | Guard validated the URL once, but the HTTP client **followed redirects and re-resolved DNS** without re-checking. | Our **L2 redirect + DNS**; the reason **L3 re-validates every hop**. |

*Sources:* [CVE-2024-4084 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2024-4084) ·
[CVE-2024-29415 (INCIBE)](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2024-29415) ·
[CVE-2024-24759 (MindsDB)](https://www.sentinelone.com/vulnerability-database/cve-2024-24759/) ·
[CrewAI (VulnCheck)](https://www.vulncheck.com/advisories/crewai-ssrf-filter-bypass-via-http-redirect-in-scrape-tools) ·
[LLaMA-Factory (VulnCheck)](https://www.vulncheck.com/advisories/llama-factory-ssrf-guard-bypass-via-redirect-and-dns-rebinding)

---

## 3. Blind SSRF & out-of-band detection

When a target makes the request but returns no response, you confirm it
**out-of-band**: make it call a server you control and watch for the callback.

- Industry practice: **PortSwigger / Burp Collaborator** and **interactsh**.
- In our lab: the internal **`oob-listener`** service + `ssrfkit recon`, which
  confirmed a blind callback live in Fase 7A.

*Source:* [PortSwigger — Blind SSRF](https://portswigger.net/web-security/ssrf/blind)

---

## 4. The through-line

Across Capital One and every CVE above, the lesson our lab proves end-to-end:

> **Denylists and string/regex checks lose.** Robust SSRF defense = resolve the
> host, validate the **actual** destination IP, **pin** it (no rebinding), and
> **re-validate redirects** — then back it with **IMDSv2** and **egress
> filtering**. No single layer is enough; defense-in-depth is layers covering
> each other's blind spots.

See the live evidence in [../TESTVERSLAG.md](../TESTVERSLAG.md) and the reasoning
per phase in [../../LOGBOEK.md](../../LOGBOEK.md).
