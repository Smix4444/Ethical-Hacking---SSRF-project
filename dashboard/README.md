# dashboard/

**Phase 9 · lab component.** A small, self-contained **SOC-style dashboard** that
visualises the lab live: the topology, the L0–L3 defense matrix, the WAF
comparison, the DNS-rebinding flip, and the IMDS audit.

## How it works

A tiny Flask backend serves a **self-contained** page (inline CSS/JS, **no CDN**
→ works offline) and exposes read/attack JSON APIs that **reuse the toolkit**
(`ssrf_scan`, `imds_check`) and the existing service endpoints — no duplicated
logic. The toolkit is mounted read-only at `/app/toolkit`.

- **Read-only by default:** it polls `/api/status` (service health) every 5s.
- **Attacks only on a button:** `/api/attack`, `/api/matrix`, `/api/waf`,
  `/api/rebind`, `/api/imds` run the lab's own checks server-side, lab-only.

## Open it

With the lab running (`docker compose up -d --build`):

**<http://localhost:8099>**

| What you see | Driven by |
|--------------|-----------|
| Topology with a live attack path (red = LOOT, green = blocked) | `/api/attack?level=N` |
| L0–L3 matrix, coloured | `/api/matrix` |
| WAF with vs without | `/api/waf` |
| DNS-rebinding flip (q#1 safe → q#2 internal), L2.5 vs L3 | `/api/rebind` (+ dns-rebind `/log`) |
| IMDSv1 vs IMDSv2 | `/api/imds` |

Reachable on its own host port (8099); it does not touch the other services.

> ⚠️ **Lab-only.** Every result comes from the lab's own containers; all
> credentials are fake.
