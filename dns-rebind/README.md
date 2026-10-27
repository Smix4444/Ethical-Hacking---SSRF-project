# dns-rebind/

**Phase 8 · lab component.** A small, deterministic **DNS rebinding** server for
the zone `rebind.lab`, used to demonstrate a TOCTOU (check-then-use) SSRF bypass
and to prove our **L3 resolve-then-pin** is immune.

## Behaviour

For `rebind.lab` (A records, **TTL 0**):

| A query (since last reset) | Answer |
|----------------------------|--------|
| #1 | `1.1.1.1` — a safe, public-looking IP (only *validated*, never connected to) |
| #2 and later | `169.254.169.254` — the internal metadata IP |

Every other name is **forwarded** to Docker's embedded resolver (`127.0.0.11`),
so `metadata.lab`, `cdn-assets.lab`, service names and the internet keep working.

## Control API (for deterministic demos)

Reachable internally as `dns-rebind.lab` (HTTP):

| Path | Effect |
|------|--------|
| `/reset` | reset the query counter (next A query is "safe" again) |
| `/log` | show the sequence of answers given (see the flip) |
| `/state` | current counter + configured IPs |

## Wiring

Static IP `169.254.169.53` on the lab network; the `vulnerable-app` container's
resolver is pointed at it (`dns:` in compose) so both the TOCTOU level (L2.5) and
L3 resolve `rebind.lab` through it. No published host ports.

## Realism note

In the wild the attacker owns a domain whose authoritative server rebinds like
this — e.g. **CVE-2024-24759 (MindsDB)**. Here it is fully internal and fake.

> ⚠️ **Lab-only.**
