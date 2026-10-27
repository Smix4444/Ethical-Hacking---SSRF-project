#!/usr/bin/env python3
"""
SSRF Lab — IMDS mode checker (toolkit, audit-style)
===================================================
LAB-ONLY. Probes a metadata endpoint two ways and reports which IMDS mode it
enforces:

  (a) IMDSv1 style — a plain GET of the credentials path (what a basic SSRF
      primitive can do).
  (b) IMDSv2 style — PUT /latest/api/token (with the TTL header) to obtain a
      session token, then GET the credentials with the token header (what a
      real HTTP client can do, but a bare SSRF GET cannot).

In the real world this is exactly the kind of check you would run to AUDIT
whether an instance enforces IMDSv2. Point it ONLY at the lab's own metadata
service. Uses the standard library only. See ../SECURITY.md.

The metadata service has no host port, so run this from INSIDE the lab network,
e.g. (from the repo root, with the lab running):

    docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" \
        python:3.12-slim python /t/imds_check.py http://169.254.169.254
"""
from __future__ import annotations

import argparse
import urllib.error
import urllib.request

CREDS_PATH = "/latest/meta-data/iam/security-credentials/lab-ec2-demo-role"
TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"
TOKEN_HEADER = "X-aws-ec2-metadata-token"


def _do(req: urllib.request.Request, timeout: int = 5):
    """Return (status_code, body_text). HTTP errors are captured, not raised."""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — report transport errors compactly
        return None, f"{type(exc).__name__}: {exc}"


def _leaked(status, body) -> bool:
    return status == 200 and '"AccessKeyId"' in body


def probe_v1(base: str):
    status, body = _do(urllib.request.Request(base + CREDS_PATH, method="GET"))
    return status, body, _leaked(status, body)


def probe_v2(base: str, ttl: int = 21600):
    status, body = _do(urllib.request.Request(
        base + "/latest/api/token", headers={TTL_HEADER: str(ttl)}, method="PUT"))
    if status != 200 or not body.strip():
        return status, None, None, False
    token = body.strip()
    st2, body2 = _do(urllib.request.Request(
        base + CREDS_PATH, headers={TOKEN_HEADER: token}, method="GET"))
    return status, token, (st2, body2), _leaked(st2, body2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check whether a LAB metadata endpoint enforces IMDSv2.")
    parser.add_argument("base", nargs="?", default="http://169.254.169.254",
                        help="metadata base URL (default http://169.254.169.254)")
    parser.add_argument("--ttl", type=int, default=21600, help="token TTL seconds")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    print(f"# IMDS check against {base}  (LAB-ONLY)\n")

    v1_status, v1_body, v1_leaked = probe_v1(base)
    print("[1] IMDSv1 probe — plain GET, no token:")
    print(f"    GET {CREDS_PATH}")
    if v1_leaked:
        key = v1_body.split('"AccessKeyId"')[1].split('"')[2]
        print(f"    -> {v1_status}: credentials LEAKED (AccessKeyId={key})\n")
    else:
        print(f"    -> {v1_status}: no credentials ({(v1_body or '').strip().splitlines()[:1]})\n")

    tok_status, token, v2_get, v2_leaked = probe_v2(base, args.ttl)
    print("[2] IMDSv2 flow — PUT token, then GET with header:")
    print(f"    PUT /latest/api/token ({TTL_HEADER}: {args.ttl}) -> {tok_status}"
          + (f", token={token[:12]}..." if token else ""))
    if v2_get is not None:
        print(f"    GET {CREDS_PATH} with {TOKEN_HEADER} -> {v2_get[0]}: "
              + ("credentials returned" if v2_leaked else "no credentials"))
    print()

    print("Conclusion:")
    if v1_leaked:
        print("  IMDSv1 behaviour — a bare GET leaks credentials. A basic SSRF")
        print("  (plain GET of a URL) is enough to steal them. VULNERABLE.")
    elif v1_status in (401, 403) and v2_leaked:
        print("  IMDSv2 ENFORCED — the plain GET was denied; only the PUT-token")
        print("  flow works. A basic SSRF GET cannot do the token dance, so the")
        print("  credential-theft chain breaks here.")
    else:
        print("  Inconclusive — see the raw responses above.")


if __name__ == "__main__":
    main()
