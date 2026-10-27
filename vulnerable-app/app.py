"""
SSRF Lab — Vulnerable App (Phase 1, defense level L0)
=====================================================
⚠️  INTENTIONALLY VULNERABLE.  LAB-ONLY.  Do NOT deploy anywhere public.

This is a tiny "URL Preview Service": you paste a link and the server fetches
it for you and shows a preview. That convenience feature is exactly where
Server-Side Request Forgery (SSRF) lives: the *server* makes the request, so an
attacker can point it at internal systems they could never reach directly —
such as the cloud metadata endpoint at http://169.254.169.254/.

Defense level L0 = NO protection at all. We validate nothing, block nothing.
Later phases add L1–L3 and a WAF in front. See ../SECURITY.md.
"""
import html
from urllib.parse import quote

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Quick-demo example URLs shown as clickable chips in the UI.
EXAMPLES = [
    ("🌐 Normal page", "https://example.com/"),
    ("📂 Metadata root", "http://169.254.169.254/latest/meta-data/"),
    ("🪪 IAM role name", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("🔑 IAM credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-ec2-demo-role"),
]

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
  .sub { color: var(--muted); margin: 0 0 26px; line-height: 1.5; }
  .card {
    background: var(--card); border: 1px solid var(--line);
    border-radius: 16px; padding: 22px; box-shadow: 0 20px 40px -24px #000;
  }
  form { display: flex; gap: 10px; flex-wrap: wrap; }
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
  .error {
    background: #2a0f12; border: 1px solid #7f1d1d; color: #fecaca;
    border-radius: 12px; padding: 14px 16px; font-size: 14px;
  }
  .footer { color: var(--muted); font-size: 12px; margin-top: 22px; line-height: 1.5; }
  code { background: #0b1220; padding: 1px 6px; border-radius: 6px; }
</style>
</head>
<body>
  <div class="wrap">
    <span class="lab-badge">⚠️ Lab only · Defense level L0</span>
    <h1><span class="emoji">🔎</span> URL Preview Service</h1>
    <p class="sub">
      Paste any link and we'll fetch a quick preview on the server for you.
      Handy for checking where a shortened link goes, previewing a webhook, and more.
    </p>

    <div class="card">
      <form action="/fetch" method="get">
        <input type="text" name="url" value="{{ url|safe }}"
               placeholder="https://example.com/page" autofocus>
        <button type="submit">Fetch preview</button>
      </form>
      <div class="chips">
        {% for label, href in chips %}
          <a class="chip" href="{{ href|safe }}">{{ label }}</a>
        {% endfor %}
      </div>

      {% if url %}
      <div class="result">
        {% if error %}
          <div class="error"><b>Could not fetch:</b> {{ error|safe }}</div>
        {% else %}
          <div class="meta">
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
      SSRF Lab · Phase 1 · This service performs <b>no</b> validation on the URL
      (level L0). That is intentional and for learning only — see
      <code>SECURITY.md</code>. Never expose this app to the internet.
    </p>
  </div>
</body>
</html>
"""


def _render(url="", status="", content_type="", body="", error=""):
    """Render the page. Everything dynamic is HTML-escaped here, then marked
    safe in the template, so a fetched page is shown as TEXT (never rendered)."""
    chips = [(label, "/fetch?url=" + quote(href, safe="")) for label, href in EXAMPLES]
    return render_template_string(
        PAGE,
        url=html.escape(url),
        status=html.escape(str(status)),
        content_type=html.escape(content_type),
        body=html.escape(body),
        error=html.escape(error),
        chips=chips,
    )


@app.route("/")
def index():
    return _render()


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "").strip()
    if not url:
        return _render()

    # ============================================================= #
    #  THE VULNERABILITY (defense level L0)                          #
    #  The user-controlled URL is fetched by the SERVER with ZERO    #
    #  validation: no scheme check, no host allow/block list, no     #
    #  blocking of internal / link-local addresses. This is what     #
    #  lets an attacker reach http://169.254.169.254/ and read the   #
    #  (fake) cloud credentials. Later phases will harden this.      #
    # ============================================================= #
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        body = resp.text[:20000]  # cap so huge/binary responses stay readable
        return _render(
            url=url,
            status=f"{resp.status_code} {resp.reason}",
            content_type=resp.headers.get("Content-Type", "unknown"),
            body=body,
        )
    except requests.RequestException as exc:
        return _render(url=url, error=f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    # Bind on all interfaces inside the container; port 5000 is published
    # to the host as 8080 by docker-compose. debug=False to avoid exposing
    # the interactive Werkzeug debugger.
    app.run(host="0.0.0.0", port=5000, debug=False)
