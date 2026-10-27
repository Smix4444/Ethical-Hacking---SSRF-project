# waf/

**Phase 4.** A Web Application Firewall placed in front of the vulnerable app as
a generic, extra defense layer, built on **ModSecurity v3** with the **OWASP
Core Rule Set (CRS) v4**.

## How it is wired

The WAF is a separate service in `docker-compose.yml` using the official OWASP
CRS image as a reverse proxy — no custom Dockerfile needed:

```yaml
image: owasp/modsecurity-crs:nginx     # ModSecurity v3 + CRS v4 (nginx variant)
environment:
  BACKEND: "http://vulnerable-app:5000"  # proxies to the app, by service name
  PORT: "8080"                           # nginx listens on 8080 in-container
  MODSEC_RULE_ENGINE: "On"               # actively block (not DetectionOnly)
  BLOCKING_PARANOIA: "1"                 # CRS paranoia level 1
ports:
  - "8090:8080"                          # host 8090 -> WAF
```

Traffic: `host:8090 → WAF → vulnerable-app:5000 → metadata`. The WAF only proxies
to the app; the metadata service and redirector stay unpublished.

## Two ways in (so the comparison stays clean)

| Path | URL | Meaning |
|------|-----|---------|
| Through the WAF | `http://localhost:8090` | ModSecurity + CRS inspects every request |
| Direct (bypass) | `http://localhost:8088` | Straight to the app, no WAF (as before) |

Keep the app on a **weak** level (L0/L1) when studying the WAF, so you isolate
what the WAF itself contributes.

## ⚠️ Image tag — pin before the Phase 7 live test

`owasp/modsecurity-crs:nginx` is a **rolling** tag (it changes over time). For a
reproducible final test, pin a dated/LTS tag. List what's available with:

```
docker run --rm owasp/modsecurity-crs:nginx cat /etc/modsecurity.d/... 2>/dev/null; \
docker image ls owasp/modsecurity-crs
```

or browse the tags on Docker Hub (`owasp/modsecurity-crs`) and set e.g.
`owasp/modsecurity-crs:4.x.x-nginx-<date>` in `docker-compose.yml`.

## Expected behaviour — **to verify live in Phase 7**

CRS is **generic and pattern-based**. Our expectation (not yet confirmed):

| Payload | Expected at the WAF | Why |
|---------|--------------------|-----|
| `http://169.254.169.254/...` (literal) | likely **blocked** | CRS v4 has an SSRF rule family (REQUEST-934) and many WAFs string-match the metadata IP. |
| `file://...` | possibly **blocked** | may trip LFI/RFI/scheme rules. |
| decimal/hex/octal IP encodings | likely **passes** | they don't contain the metadata string; look like ordinary args. |
| innocent DNS (`cdn-assets.lab`) | likely **passes** | a normal-looking GET to a normal-looking host. |
| `preview-service.lab` (redirect) | likely **passes** | pattern looks innocent. |

**Lesson:** a WAF is a useful extra layer but is **not** a replacement for correct
application logic (L3). This mirrors the 2019 **Capital One** breach, where the
vulnerable component *was* a WAF and the SSRF went straight through it to the
metadata endpoint.

> ⚠️ **Lab-only.** The WAF guards the lab app on the isolated Docker network.
