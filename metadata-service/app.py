"""
SSRF Lab — Mock Cloud Metadata Service
======================================
⚠️  EVERYTHING HERE IS FAKE.  LAB-ONLY.

This mimics the *shape* of the AWS EC2 Instance Metadata Service (IMDS v1):
the internal-only endpoint at http://169.254.169.254/ that real EC2 instances
query to discover their configuration — including TEMPORARY IAM credentials.

Why this matters: in the 2019 Capital One breach, an SSRF vulnerability let an
attacker reach exactly this endpoint, read the instance's IAM credentials, and
use them to list and download data from S3 buckets. We reproduce the shape of
that endpoint with INVENTED credentials so the lab can demonstrate why an SSRF
that reaches metadata is so dangerous — without touching any real cloud.

The credentials below are fake. The AccessKeyId/SecretAccessKey deliberately
match AWS's own *public documentation example* values, so they are unmistakably
not real and authenticate to nothing.
"""
import json
import os
import secrets
import time

from flask import Flask, Response, request

app = Flask(__name__)

# IMDS mode: "v1" (default, legacy — a plain GET returns everything) or "v2"
# (token-required — a PUT must first obtain a session token, which is then sent
# as a header on every read). Default v1 keeps the earlier phases working
# unchanged; set IMDS_MODE=v2 in docker-compose to require the token dance.
IMDS_MODE = os.environ.get("IMDS_MODE", "v1").strip().lower()

# IMDSv2 session tokens we have issued: token -> expiry epoch seconds. FAKE.
_ISSUED_TOKENS = {}
TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"
TOKEN_HEADER = "X-aws-ec2-metadata-token"

# The IAM role "attached" to this fake instance.
ROLE_NAME = "lab-ec2-demo-role"

# --- FAKE temporary IAM credentials (IMDSv1 shape). NOT REAL. -------------- #
# "ASIA..." = short-lived STS credentials (vs. "AKIA..." long-term). The secret
# key is AWS's published example value. None of this unlocks anything.
FAKE_CREDENTIALS = {
    "Code": "Success",
    "LastUpdated": "2026-10-27T10:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAZ4LAB5EXAMPLE999",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "FAKESESSIONTOKEN-lab-only-not-real-do-not-use-EXAMPLE==",
    "Expiration": "2026-10-28T10:00:00Z",
}

# A fake instance-identity document, like /latest/dynamic/instance-identity/.
IDENTITY_DOC = {
    "accountId": "000000000000",
    "region": "eu-west-1",
    "availabilityZone": "eu-west-1a",
    "instanceId": "i-0fakelab1234567890",
    "instanceType": "t3.micro",
    "imageId": "ami-0fakelabexample00",
    "privateIp": "10.0.1.37",
    "pendingTime": "2026-10-27T09:59:00Z",
    "version": "2017-09-30",
}

# Top-level metadata keys exposed under /latest/meta-data/.
META = {
    "ami-id": "ami-0fakelabexample00",
    "instance-id": "i-0fakelab1234567890",
    "instance-type": "t3.micro",
    "local-ipv4": "10.0.1.37",
    "public-ipv4": "203.0.113.37",          # TEST-NET-3: a documentation IP, fake
    "hostname": "ip-10-0-1-37.eu-west-1.compute.internal",
    "local-hostname": "ip-10-0-1-37.eu-west-1.compute.internal",
    "placement/availability-zone": "eu-west-1a",
}


def text(body, status=200):
    """IMDS serves plain text (even for the JSON credential document)."""
    return Response(body, status=status, mimetype="text/plain")


def _issue_token(ttl_seconds):
    token = secrets.token_urlsafe(32)
    _ISSUED_TOKENS[token] = time.time() + ttl_seconds
    return token


def _token_is_valid():
    token = request.headers.get(TOKEN_HEADER)
    if not token:
        return False
    expiry = _ISSUED_TOKENS.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        _ISSUED_TOKENS.pop(token, None)
        return False
    return True


@app.before_request
def _enforce_imdsv2():
    """In v2 mode, EVERY metadata read requires a valid session token (as AWS
    IMDSv2 with HttpTokens=required does). A plain SSRF GET cannot supply one,
    so the credential-theft chain breaks right here. In v1 mode: a no-op."""
    if IMDS_MODE != "v2":
        return None
    path = request.path
    if request.method == "GET" and (
        path.startswith("/latest/meta-data") or path.startswith("/latest/dynamic")
    ):
        if not _token_is_valid():
            return text(
                "401 - Unauthorized. IMDSv2 requires a session token:\n"
                f"  PUT /latest/api/token  with header '{TOKEN_TTL_HEADER}: 21600'\n"
                f"  then resend the GET with header '{TOKEN_HEADER}: <token>'.\n",
                status=401,
            )
    return None


@app.route("/latest/api/token", methods=["PUT"])
def imds_token():
    """IMDSv2 token endpoint. Real IMDSv2 only answers to PUT and requires the
    TTL header — exactly what a basic SSRF primitive (a plain GET of a URL)
    cannot produce. The token is FAKE."""
    ttl_raw = request.headers.get(TOKEN_TTL_HEADER)
    if ttl_raw is None:
        return text(f"400 - missing {TOKEN_TTL_HEADER} header\n", status=400)
    try:
        ttl = max(1, min(21600, int(ttl_raw)))
    except ValueError:
        return text("400 - invalid TTL\n", status=400)
    return text(_issue_token(ttl))


@app.route("/")
def root():
    return text(
        "FAKE cloud metadata service - SSRF Lab, lab-only.\n"
        f"Active mode: IMDS{IMDS_MODE}. All data is invented.\n"
        "Try: /latest/meta-data/\n"
    )


@app.route("/latest/meta-data/")
def meta_index():
    keys = sorted({k.split("/")[0] for k in META})
    listing = "\n".join(keys + ["iam/"]) + "\n"
    return text(listing)


@app.route("/latest/meta-data/<path:key>")
def meta_key(key):
    if key in META:
        return text(META[key])
    # Allow listing an intermediate "directory" like placement/.
    prefix = key.rstrip("/") + "/"
    children = sorted({k[len(prefix):].split("/")[0] for k in META if k.startswith(prefix)})
    if children:
        return text("\n".join(children) + "\n")
    return text("Not Found\n", status=404)


@app.route("/latest/meta-data/iam/")
def iam_index():
    return text("security-credentials/\n")


@app.route("/latest/meta-data/iam/security-credentials/")
def iam_roles():
    # Returns the role name(s). This single line is the attacker's next hop.
    return text(ROLE_NAME + "\n")


@app.route("/latest/meta-data/iam/security-credentials/<role>")
def iam_credentials(role):
    # The crown jewels: temporary IAM credentials for the role. FAKE.
    if role == ROLE_NAME:
        return text(json.dumps(FAKE_CREDENTIALS, indent=2) + "\n")
    return text("Not Found\n", status=404)


@app.route("/latest/dynamic/instance-identity/document")
def identity_document():
    return text(json.dumps(IDENTITY_DOC, indent=2) + "\n")


if __name__ == "__main__":
    # Real IMDS lives on port 80 at 169.254.169.254. We bind 0.0.0.0:80 inside
    # the container; docker-compose pins this container to IP 169.254.169.254.
    # Deliberately NOT published to the host — reachable only via SSRF.
    app.run(host="0.0.0.0", port=80, debug=False)
