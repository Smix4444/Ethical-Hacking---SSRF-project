"""
SSRF Lab — Out-of-Band (OOB) Listener  (lab component)
======================================================
⚠️  LAB-ONLY.  Internal callback collector for detecting BLIND SSRF.

When an SSRF target makes a request but does NOT return the response to the
attacker ("blind" SSRF), you confirm the vulnerability out-of-band: you make the
target call a server you control, carrying a unique token, and then check whether
that server saw the callback.

This service is that collector. It records every token it is called with and
answers whether a given token has been seen. The toolkit (`ssrfkit recon`) uses
it to confirm blind SSRF against the lab app.

Realism note: in a real engagement this role is played by an attacker-owned
server such as Burp Collaborator or interactsh. Here it is a clearly-labelled
INTERNAL lab service with no host port — it cannot be reached from outside the
Docker network and holds nothing sensitive (just tokens it was pinged with).
"""
import threading
import time

from flask import Flask, jsonify

app = Flask(__name__)

_seen = {}            # token -> first-seen epoch seconds
_lock = threading.Lock()


@app.route("/cb/<path:token>")
def callback(token):
    """The target hits this (via SSRF) with a unique token. We record it."""
    with _lock:
        _seen.setdefault(token, time.time())
    return "ok\n"


@app.route("/seen/<path:token>")
def seen(token):
    """The toolkit polls this to learn whether the callback arrived."""
    with _lock:
        hit = token in _seen
    return jsonify({"token": token, "seen": hit})


@app.route("/hits")
def hits():
    with _lock:
        return jsonify({"count": len(_seen), "tokens": sorted(_seen)})


@app.route("/")
def root():
    return (
        "SSRF Lab OOB listener (lab-only).\n"
        "callback: /cb/<token>   query: /seen/<token>   list: /hits\n"
    )


if __name__ == "__main__":
    # Internal only (no published host port); reachable as oob-listener.lab.
    app.run(host="0.0.0.0", port=80, debug=False)
