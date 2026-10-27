# vulnerable-app/

**Phase 1.** An intentionally vulnerable Flask web application, used to
study Server-Side Request Forgery (SSRF) under controlled conditions.

## Purpose

Show how an SSRF weakness appears in a server endpoint that fetches a
user-supplied URL, and how it can be defended step by step. The app
exposes a configurable **defense level** so the same feature can be
studied from "wide open" to "properly hardened".

## Defense levels (planned)

| Level | Idea                                                           |
|-------|----------------------------------------------------------------|
| L0    | No protection — baseline vulnerable behaviour                  |
| L1    | Naive blocklist / string filtering                             |
| L2    | Scheme + host allowlisting                                     |
| L3    | DNS-resolution & redirect-aware validation, metadata denied    |

## Status

🟡 Placeholder — no code yet. Built in Phase 1.

> ⚠️ **Lab-only.** This service is deliberately insecure. Run it only on
> the isolated local Docker network; never expose it to the internet.
