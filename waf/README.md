# waf/

**Phase 3.** A Web Application Firewall placed in front of the vulnerable
app, built on **ModSecurity** with the **OWASP Core Rule Set (CRS)**.

## Purpose

Study how a WAF detects and blocks SSRF-style requests: where it genuinely
helps, where it produces false positives, and where a determined request
can slip past it. This is our "defense in depth" layer.

## Status

🟡 Placeholder — no configuration yet. Built in Phase 3.

> ⚠️ **Lab-only.** The WAF guards the lab app on the isolated Docker
> network; it is not a production deployment.
