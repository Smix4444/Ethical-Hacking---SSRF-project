# vulnerable-app/

**Phase 1.** An intentionally vulnerable Flask web application used to study
Server-Side Request Forgery (SSRF). Themed as a **"URL Preview Service"**: you
paste a link and the server fetches a preview for you — a perfectly normal
feature that, done naively, *is* an SSRF vulnerability.

## What's here

| File | Purpose |
|------|---------|
| `app.py` | The Flask app: a `/` page with a URL field, and `/fetch?url=` which the server fetches with **no validation** (level L0). |
| `Dockerfile` | Builds the image (Python 3.12 slim). |
| `requirements.txt` | `flask`, `requests`. |

## The vulnerability (level L0)

`/fetch` takes a user-supplied `url` and calls `requests.get(url)` on the
**server**, with zero checks — no scheme restriction, no host allow/block list,
no blocking of internal or link-local addresses. So a request for
`http://169.254.169.254/...` is happily made from inside the lab network and the
response handed back to the attacker.

## Defense levels (roadmap)

| Level | Idea | Phase |
|-------|------|-------|
| **L0** | No protection — baseline (this phase) | 1 |
| L1 | Naive blocklist / string filtering | later |
| L2 | Scheme + host allowlisting | later |
| L3 | DNS-resolution & redirect-aware validation, metadata denied | later |

## Run it

From the repository root (not this folder):

```
docker compose up --build
```

Then open <http://localhost:8088>.

> ⚠️ **Lab-only.** This service is deliberately insecure. Run it only on the
> isolated local Docker network; never expose it to the internet.
