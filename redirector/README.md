# redirector/

**Phase 2 · lab component.** A tiny service that simulates an
**attacker-controlled host** which looks innocent but `302`-redirects to the
internal metadata endpoint.

## Why it exists

It demonstrates the **L2 bypass**. The L2 filter validates only the URL *as
submitted*. The submitted host here is `preview-service.lab` — not an IP, not on
any blocklist — so L2 allows it. The vulnerable app then follows the `302` to
`http://169.254.169.254/...`, which L2 never re-checks. This is the
**check-vs-use / parse-vs-fetch** discrepancy at the heart of many real SSRF
bypasses.

## Behaviour

| Path | Response |
|------|----------|
| `/` | `302` redirect to the fake IAM credentials endpoint (default) |
| `/?to=<url>` | `302` redirect to `<url>` (for custom demos) |
| `/health` | `redirector ok` |

Reachable inside the Docker network as **`preview-service.lab`**, with **no
published host ports**.

## Realism note

In a real attack the redirect host is a domain the attacker owns and submits to
a victim's "fetch this URL" feature. Nothing here touches any real system; the
redirect target is the lab's own mock metadata service.

> ⚠️ **Lab-only.**
