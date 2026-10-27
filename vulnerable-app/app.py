"""
SSRF Lab — Vulnerable App (Phase 2: configurable defense levels L0 / L1 / L2)
============================================================================
⚠️  INTENTIONALLY VULNERABLE.  LAB-ONLY.  Do NOT deploy anywhere public.

A tiny "URL Preview Service": you paste a link and the server fetches it for
you. That convenience feature is where Server-Side Request Forgery (SSRF) lives.

This phase adds *configurable, deliberately weak* defenses so we can study WHY
naive filters fail — the whole point of building better ones later:

  L0  No protection. Baseline.
  L1  Naive blocklist on the raw URL string. Weak: checks the TEXT, not the
      real destination, so alternate encodings / DNS names slip past.
  L2  Parse the host, allow only http/https, block internal IP ranges. Better,
      but still flawed: it trusts the URL *as written* and blindly follows
      redirects, so it never re-checks the address it actually connects to
      (the "parse-vs-fetch" / "check-vs-use" discrepancy).

The active level comes from the ?level= query parameter (so you can switch live
in the UI), falling back to the DEFENSE_LEVEL environment variable. Correct
validation and a WAF arrive in later phases. See ../SECURITY.md.
"""
import html
import ipaddress
import os
import re
import socket
from urllib.parse import quote, urljoin, urlparse, urlunparse

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

DEFAULT_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))

LEVELS = {
    0: ("L0 — No protection", "Every URL is fetched. Baseline vulnerability."),
    1: ("L1 — Naive blocklist", "Rejects URLs containing blocked literal strings. "
        "Checks the raw text, not the real destination."),
    2: ("L2 — Parsed host + scheme check", "Parses the hostname, allows only "
        "http/https, blocks internal IP ranges. But it trusts the URL as written "
        "and still follows redirects without re-checking."),
    25: ("L2.5 — TOCTOU (check-then-use, VULNERABLE)", "Resolves and validates the "
        "host, then hands the HOSTNAME to the HTTP client, which resolves AGAIN at "
        "connect — defeated by DNS rebinding. Models the MindsDB/CrewAI bug."),
    3: ("L3 — Resolve-then-pin (correct)", "Resolves the host, validates EVERY "
        "resulting IP against internal ranges, pins the connection to that IP so "
        "DNS cannot rebind, and re-validates every redirect hop."),
}

# Quick-demo example URLs shown as clickable chips in the UI.
EXAMPLES = [
    ("🌐 Normal page", "https://example.com/"),
    ("📂 Metadata root", "http://169.254.169.254/latest/meta-data/"),
    ("🔑 IAM credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-ec2-demo-role"),
]

# --------------------------------------------------------------------------- #
#  Filters. Each is intentionally imperfect; the comments say exactly why.     #
# --------------------------------------------------------------------------- #

# L1: a blocklist of literal substrings. The flaw is right here: it matches the
# TEXT of the URL. "http://169.254.169.254/" is caught, but any representation
# that does not contain these exact strings (a decimal/hex IP, a DNS name that
# resolves to the same host) sails straight through.
BLOCKLIST_L1 = ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0"]

# L2: known-bad hostnames and a regex for "suspicious looking" ones. Still flawed
# (see check_level_2): DNS names are never resolved, and redirects are followed
# without re-validating the final target.
BLOCKED_HOSTS_L2 = {"169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata"}
SUSPICIOUS_RE_L2 = re.compile(r"169\.254\.|metadata", re.IGNORECASE)


def _parse_octet(part):
    """Parse one dotted part as decimal, hex (0x..) or octal (0..) — inet_aton
    style. Raises ValueError on anything invalid."""
    low = part.lower()
    if low.startswith("0x"):
        return int(part, 16)
    if part.startswith("0") and len(part) > 1:
        return int(part, 8)
    return int(part, 10)


def _host_to_ip(host):
    """Best-effort: interpret a host literal as an IP given in various encodings
    (dotted-decimal, integer, hex 0x…, octal 0…, dotted-hex/octal, IPv4-mapped
    IPv6). Returns an ip_address or None. This is what lets L2 catch the
    alternate-notation tricks that fool L1."""
    # Direct forms, incl. IPv4-mapped IPv6 (::ffff:a.b.c.d -> a.b.c.d).
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        pass
    # Single integer: decimal, hex (0x..) or octal (0..).
    try:
        if host.lower().startswith("0x"):
            return ipaddress.ip_address(int(host, 16))
        if host.isdigit():
            base = 8 if host.startswith("0") and len(host) > 1 else 10
            return ipaddress.ip_address(int(host, base))
    except ValueError:
        pass
    # Dotted form where each octet may be decimal/hex/octal.
    parts = host.split(".")
    if len(parts) == 4:
        try:
            octets = [_parse_octet(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.ip_address(".".join(str(o) for o in octets))
        except ValueError:
            pass
    return None


def check_level_1(url):
    low = url.lower()
    for bad in BLOCKLIST_L1:
        if bad in low:
            return False, f"L1 blocklist matched the literal string '{bad}' in the URL."
    return True, ""


def check_level_2(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"L2 allows only http/https schemes, not '{parsed.scheme or '(none)'}'."
    host = (parsed.hostname or "").rstrip(".")
    ip = _host_to_ip(host)
    if ip is not None:
        # It is an IP literal (in some encoding): block internal ranges.
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False, f"L2: host decodes to internal IP {ip} (blocked range)."
        return True, ""
    # It is a DNS name. FLAW: we only pattern-match the name; we never resolve it,
    # so a name that resolves to an internal IP is allowed. And because the real
    # fetch follows redirects, the final destination is never re-checked here.
    if host.lower() in BLOCKED_HOSTS_L2 or SUSPICIOUS_RE_L2.search(host):
        return False, f"L2: host '{host}' looks internal/blocked."
    return True, ""


def apply_filter(url, level):
    """Return (allowed, reason). Reason is only meaningful when blocked."""
    if level == 2:
        return check_level_2(url)
    if level == 1:
        return check_level_1(url)
    return True, ""  # L0 (L3 has its own safe fetch, see below)


# --------------------------------------------------------------------------- #
#  L3 — the CORRECT defense: resolve-then-pin + per-hop redirect revalidation.  #
#  This is what actually closes the Phase 2 bypasses. Each step is annotated    #
#  with the specific bypass it defeats.                                         #
# --------------------------------------------------------------------------- #

class BlockedError(Exception):
    """Raised when L3 refuses a URL for policy reasons (not a network error)."""


def _is_blocked_ip(ip):
    """True if an address is one we must never let the server reach."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # unwrap ::ffff:a.b.c.d so the IPv4 checks apply
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _resolve_and_validate(host, port):
    """Resolve `host` and validate EVERY resulting address against internal
    ranges, then return ONE validated IP to connect to (the "pin").

    - Numeric hosts (any encoding) are canonicalised first, so 2852039166,
      0xa9fea9fe, 0251.0376.0251.0376, [::ffff:169.254.169.254] etc. all reduce
      to the same IP and are checked (defeats the L1 encoding bypass).
    - DNS names are resolved and ALL answers are checked, so a name that points
      to an internal IP (cdn-assets.lab) is rejected (defeats the L2 DNS bypass).
    - We return a concrete IP so the caller connects to it directly; the name is
      never resolved again at connect time (defeats DNS rebinding / TOCTOU)."""
    literal = _host_to_ip(host)
    if literal is not None:
        if _is_blocked_ip(literal):
            raise BlockedError(f"L3: host decodes to internal IP {literal} (blocked range).")
        return str(literal)

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise requests.exceptions.ConnectionError(f"DNS resolution failed for {host}: {exc}")

    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_blocked_ip(ip):
            raise BlockedError(f"L3: host '{host}' resolves to internal IP {ip} (blocked range).")
        addrs.append(ip)

    # Prefer an IPv4 for reliable container connectivity; pin to one address.
    ipv4 = [a for a in addrs if a.version == 4]
    return str((ipv4 or addrs)[0])


def l3_fetch(url, max_redirects=5):
    """SSRF-safe fetch. Raises BlockedError on policy refusal, RequestException
    on network errors, otherwise returns the final requests.Response.

    NOTE (honest residual limitation): pinning by rewriting the host to the IP
    and carrying the Host header works for HTTP. For HTTPS it would break SNI /
    certificate validation; a production implementation needs a pinning adapter
    that keeps the original SNI. The lab targets are HTTP."""
    current = url
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https"):
            raise BlockedError(f"L3: scheme '{parsed.scheme or '(none)'}' not allowed (http/https only).")
        host = (parsed.hostname or "").rstrip(".")
        if not host:
            raise BlockedError("L3: URL has no host.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        ip = _resolve_and_validate(host, port)             # may raise BlockedError
        netloc_ip = f"[{ip}]" if ":" in ip else ip         # bracket IPv6
        pinned = urlunparse((parsed.scheme, f"{netloc_ip}:{port}",
                             parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

        # Connect to the validated IP; keep the real Host header for vhosts.
        # allow_redirects=False so we re-validate each hop ourselves.
        resp = requests.get(pinned, headers={"Host": parsed.netloc},
                            timeout=5, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            current = urljoin(current, resp.headers["Location"])  # re-validate next loop
            continue
        return resp

    raise BlockedError("L3: too many redirects.")


def toctou_fetch(url):
    """L2.5 — DELIBERATELY TOCTOU-VULNERABLE (check-then-use). Models the
    MindsDB/CrewAI bug.

    CHECK: resolve the host once and validate the IP looks safe.
    USE:   hand the HOSTNAME back to requests, which RESOLVES AGAIN at connect.

    With a rebinding DNS (TTL 0) the second resolution differs, so a name that
    validated as safe reaches an internal IP. The fix is L3 (resolve-then-pin):
    resolve once and connect to THAT IP, never re-resolving."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedError(f"L2.5: scheme '{parsed.scheme or '(none)'}' not allowed.")
    host = (parsed.hostname or "").rstrip(".")
    if not host:
        raise BlockedError("L2.5: URL has no host.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # --- CHECK: one resolution, validate it ---
    literal = _host_to_ip(host)
    if literal is not None:
        checked = literal
    else:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        checked = ipaddress.ip_address(infos[0][4][0])
    if _is_blocked_ip(checked):
        raise BlockedError(f"L2.5: validated IP {checked} is internal (blocked).")

    # --- USE: hand the HOSTNAME back; requests re-resolves at connect (the flaw) ---
    return requests.get(url, timeout=5, allow_redirects=False)


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>URL Preview Service</title>
<style>
  :root {
    --bg: #0f172a; --card: #1e293b; --line: #334155; --text: #e2e8f0;
    --muted: #94a3b8; --accent: #38bdf8; --accent2: #818cf8;
    --ok: #34d399; --warn: #fbbf24; --danger: #f87171;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: radial-gradient(1200px 600px at 20% -10%, #1e293b 0%, var(--bg) 55%);
    color: var(--text); min-height: 100vh; padding: 32px 16px;
  }
  .wrap { max-width: 820px; margin: 0 auto; }
  .lab-badge {
    display: inline-flex; gap: 8px; align-items: center; font-size: 12px;
    font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
    color: #0f172a; background: var(--warn); padding: 6px 12px;
    border-radius: 999px; margin-bottom: 18px;
  }
  h1 { margin: 0 0 6px; font-size: 30px; }
  h1 .emoji { filter: saturate(1.3); }
  .sub { color: var(--muted); margin: 0 0 22px; line-height: 1.5; }
  .card {
    background: var(--card); border: 1px solid var(--line);
    border-radius: 16px; padding: 22px; box-shadow: 0 20px 40px -24px #000;
  }
  .levelbar {
    display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
    padding: 12px 14px; margin-bottom: 18px; border-radius: 12px;
    background: #0b1220; border: 1px solid var(--line);
  }
  .levelbar select {
    padding: 8px 10px; border-radius: 8px; background: #0f172a;
    color: var(--text); border: 1px solid var(--line); font-size: 14px;
  }
  .levelbar .desc { font-size: 13px; color: var(--muted); flex: 1 1 240px; }
  .lvl-tag {
    font-weight: 700; font-size: 13px; padding: 4px 10px; border-radius: 999px;
    background: var(--accent2); color: #0b1220;
  }
  form.main { display: flex; gap: 10px; flex-wrap: wrap; }
  input[type=text] {
    flex: 1 1 320px; padding: 13px 15px; border-radius: 10px;
    border: 1px solid var(--line); background: #0b1220; color: var(--text);
    font-size: 15px; outline: none;
  }
  input[type=text]:focus { border-color: var(--accent); }
  button {
    padding: 13px 20px; border: none; border-radius: 10px; cursor: pointer;
    font-size: 15px; font-weight: 600; color: #04121f;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
  }
  button:hover { filter: brightness(1.08); }
  .chips { margin: 16px 0 4px; display: flex; flex-wrap: wrap; gap: 8px; }
  .chip {
    font-size: 13px; text-decoration: none; color: var(--text);
    background: #0b1220; border: 1px solid var(--line);
    padding: 7px 11px; border-radius: 999px;
  }
  .chip:hover { border-color: var(--accent); color: var(--accent); }
  .result { margin-top: 22px; }
  .meta {
    display: flex; flex-wrap: wrap; gap: 8px 18px; font-size: 13px;
    color: var(--muted); margin-bottom: 10px;
  }
  .meta b { color: var(--text); font-weight: 600; }
  pre {
    background: #0b1220; border: 1px solid var(--line); border-radius: 12px;
    padding: 16px; overflow: auto; max-height: 420px; font-size: 13px;
    line-height: 1.5; color: #cbd5e1; white-space: pre-wrap; word-break: break-word;
  }
  .error, .blocked {
    border-radius: 12px; padding: 14px 16px; font-size: 14px;
  }
  .error { background: #2a0f12; border: 1px solid #7f1d1d; color: #fecaca; }
  .blocked { background: #27200a; border: 1px solid #a16207; color: #fde68a; }
  .ok-tag { color: var(--ok); font-weight: 700; }
  .footer { color: var(--muted); font-size: 12px; margin-top: 22px; line-height: 1.5; }
  code { background: #0b1220; padding: 1px 6px; border-radius: 6px; }
</style>
</head>
<body>
  <div class="wrap">
    <span class="lab-badge">⚠️ Lab only · {{ level_name|safe }}</span>
    <h1><span class="emoji">🔎</span> URL Preview Service</h1>
    <p class="sub">
      Paste any link and we'll fetch a quick preview on the server for you.
    </p>

    <div class="card">
      <!-- Defense level switcher (changes take effect immediately, no rebuild) -->
      <form class="levelbar" action="/fetch" method="get">
        <span class="lvl-tag">Defense</span>
        <select name="level" onchange="this.form.submit()">
          {% for lvl, (name, _d) in levels.items() %}
            <option value="{{ lvl }}" {{ 'selected' if lvl == level else '' }}>{{ name }}</option>
          {% endfor %}
        </select>
        <input type="hidden" name="url" value="{{ url|safe }}">
        <span class="desc">{{ level_desc|safe }}</span>
      </form>

      <form class="main" action="/fetch" method="get">
        <input type="text" name="url" value="{{ url|safe }}"
               placeholder="https://example.com/page" autofocus>
        <input type="hidden" name="level" value="{{ level }}">
        <button type="submit">Fetch preview</button>
      </form>
      <div class="chips">
        {% for label, href in chips %}
          <a class="chip" href="{{ href|safe }}">{{ label }}</a>
        {% endfor %}
      </div>

      {% if url %}
      <div class="result">
        {% if blocked %}
          <div class="blocked"><b>🛡️ Blocked by filter:</b> {{ blocked|safe }}</div>
        {% elif error %}
          <div class="error"><b>Could not fetch:</b> {{ error|safe }}</div>
        {% else %}
          <div class="meta">
            <span class="ok-tag">✓ Fetched</span>
            <span><b>URL:</b> {{ url|safe }}</span>
            <span><b>Status:</b> {{ status|safe }}</span>
            <span><b>Content-Type:</b> {{ content_type|safe }}</span>
          </div>
          <pre>{{ body|safe }}</pre>
        {% endif %}
      </div>
      {% endif %}
    </div>

    <p class="footer">
      SSRF Lab · Phase 3 · L0–L2 are <b>deliberately weak</b>; L3 is the correct
      resolve-then-pin defense. Learning only — see <code>SECURITY.md</code>.
      Never expose this app to the internet.
    </p>
  </div>
</body>
</html>
"""


def _render(url="", status="", content_type="", body="", error="", blocked="", level=0):
    """Render the page. Everything dynamic is HTML-escaped here then marked safe,
    so a fetched page is always shown as TEXT (never rendered)."""
    name, desc = LEVELS.get(level, LEVELS[0])
    chips = [(label, f"/fetch?level={level}&url=" + quote(href, safe="")) for label, href in EXAMPLES]
    return render_template_string(
        PAGE,
        url=html.escape(url),
        status=html.escape(str(status)),
        content_type=html.escape(content_type),
        body=html.escape(body),
        error=html.escape(error),
        blocked=html.escape(blocked),
        level=level,
        level_name=html.escape(name),
        level_desc=html.escape(desc),
        levels=LEVELS,
        chips=chips,
    )


def _current_level():
    raw = request.args.get("level")
    try:
        lvl = int(raw) if raw is not None else DEFAULT_LEVEL
    except ValueError:
        lvl = DEFAULT_LEVEL
    if lvl == 25:            # L2.5 — the deliberately TOCTOU-vulnerable level
        return 25
    return max(0, min(3, lvl))


@app.route("/")
def index():
    return _render(level=_current_level())


@app.route("/fetch")
def fetch():
    level = _current_level()
    url = request.args.get("url", "").strip()
    if not url:
        return _render(level=level)

    # L2.5 — deliberately TOCTOU-vulnerable (check-then-use), for the rebind demo.
    if level == 25:
        try:
            resp = toctou_fetch(url)
        except BlockedError as blocked:
            return _render(url=url, level=level, blocked=str(blocked))
        except requests.RequestException as exc:
            return _render(url=url, level=level, error=f"{type(exc).__name__}: {exc}")
        body = resp.text[:20000]
        return _render(
            url=url, level=level,
            status=f"{resp.status_code} {resp.reason}",
            content_type=resp.headers.get("Content-Type", "unknown"),
            body=body,
        )

    # L3 does its own SSRF-safe fetch (resolve-then-pin + redirect revalidation).
    if level >= 3:
        try:
            resp = l3_fetch(url)
        except BlockedError as blocked:
            return _render(url=url, level=level, blocked=str(blocked))
        except requests.RequestException as exc:
            return _render(url=url, level=level, error=f"{type(exc).__name__}: {exc}")
        body = resp.text[:20000]
        return _render(
            url=url, level=level,
            status=f"{resp.status_code} {resp.reason}",
            content_type=resp.headers.get("Content-Type", "unknown"),
            body=body,
        )

    # L0/L1/L2: deliberately weak string/parse filter, then a naive fetch that
    # follows redirects blindly (the L2 flaw).
    allowed, reason = apply_filter(url, level)
    if not allowed:
        return _render(url=url, level=level, blocked=reason)
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        body = resp.text[:20000]  # cap so huge/binary responses stay readable
        return _render(
            url=url,
            level=level,
            status=f"{resp.status_code} {resp.reason}",
            content_type=resp.headers.get("Content-Type", "unknown"),
            body=body,
        )
    except requests.RequestException as exc:
        return _render(url=url, level=level, error=f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    # Bind on all interfaces inside the container; port 5000 is published to the
    # host as 8088 by docker-compose. debug=False to avoid the Werkzeug debugger.
    app.run(host="0.0.0.0", port=5000, debug=False)
