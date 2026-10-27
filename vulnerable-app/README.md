# vulnerable-app/

**Phase 1–2.** An intentionally vulnerable Flask web application used to study
Server-Side Request Forgery (SSRF). Themed as a **"URL Preview Service"**: you
paste a link and the server fetches a preview for you — a normal feature that,
done naively, *is* an SSRF vulnerability.

## What's here

| File | Purpose |
|------|---------|
| `app.py` | Flask app with a URL field, a defense-level switcher, and `/fetch?url=&level=`. |
| `Dockerfile` | Builds the image (Python 3.12 slim). |
| `requirements.txt` | `flask`, `requests`. |

## Defense levels

Set the default with the `DEFENSE_LEVEL` env var (compose); override live per
request with the **UI dropdown** (`?level=`), so you can switch without a rebuild.

| Level | Behaviour | Result |
|-------|-----------|--------|
| **L0** | No checks. | Baseline vulnerability — everything is fetched. |
| **L1** | Blocklist of literal substrings (`169.254.169.254`, `localhost`, …) on the raw URL. | Fails: it inspects the **text**, not the destination. Alternate IP encodings (decimal/hex/octal) and DNS names don't contain the blocked strings. |
| **L2** | Parse the host; allow only `http`/`https`; block internal IP ranges (catches the encodings L1 missed). | Fails: it trusts the URL **as written** and **follows redirects**. A DNS name it never resolves, or a `302` to the internal target, defeats it — the *parse-vs-fetch / check-vs-use* discrepancy. |
| **L3** | **Resolve-then-pin:** resolve the host, validate **every** resulting IP against internal ranges, **pin** the connection to that IP (no re-resolution → no DNS rebinding), and **re-validate every redirect hop**. | Correct: blocks the direct IP, all encodings, the redirect and the DNS bypass, while legitimate hosts still work. |

> The code comments in `app.py` mark each flaw and each L3 defense step inline.
> **Residual limits (honest):** pinning here covers HTTP (HTTPS needs an
> SNI-preserving pinning adapter); and L3 only protects *this app* — the network
> and the metadata service still need IMDSv2 + egress filtering (later phases).

## Run it

From the repository root:

```
docker compose up --build
```

Then open <http://localhost:8088> and use the **Defense** dropdown to switch levels.

> ⚠️ **Lab-only.** This service is deliberately insecure. Run it only on the
> isolated local Docker network; never expose it to the internet.
