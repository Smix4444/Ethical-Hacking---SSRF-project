# metadata-service/

**Phase 1–5.** A mock cloud metadata service that imitates the *shape* of the
AWS EC2 Instance Metadata Service (IMDSv1 **and** IMDSv2) at
`http://169.254.169.254/`, using entirely **fake, invented IAM credentials**.

## What's here

| File | Purpose |
|------|---------|
| `app.py` | Flask app serving realistic IMDS paths with fake data. |
| `Dockerfile` | Builds the image; listens on port 80. |
| `requirements.txt` | `flask`. |

## Endpoints (all fake data)

| Path | Returns |
|------|---------|
| `/latest/meta-data/` | List of metadata categories |
| `/latest/meta-data/instance-id` | `i-0fakelab1234567890` |
| `/latest/meta-data/iam/security-credentials/` | the role name `lab-ec2-demo-role` |
| `/latest/meta-data/iam/security-credentials/lab-ec2-demo-role` | **fake temporary IAM credentials (JSON)** |
| `/latest/dynamic/instance-identity/document` | fake instance identity document |
| `PUT /latest/api/token` | IMDSv2 session token (requires the TTL header) |

## IMDS mode — v1 vs v2 (`IMDS_MODE` env)

Switchable via the `IMDS_MODE` env var on the service in `docker-compose.yml`:

| Mode | Behaviour |
|------|-----------|
| **`v1`** (default) | Legacy. A plain `GET` of any metadata path returns the data — a basic SSRF (a bare GET) steals the creds. Keeps Phases 1–4 working unchanged. |
| **`v2`** | A metadata `GET` **without** a valid token → `401`. You must first `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then resend the `GET` with header `X-aws-ec2-metadata-token: <token>`. |

**Why it matters:** a basic SSRF primitive can only make a plain `GET`; it cannot
do the `PUT`-then-header token dance. So in `v2` mode the credential-theft chain
breaks *even at app level L0*. This is AWS's direct answer to Capital One.

**Residual risk (honest):** IMDSv2 does **not** help if the app hands the attacker
a full HTTP client that can send a `PUT` and custom headers, nor against already
-leaked v1 credentials, nor certain proxy/redirect tricks. It is one layer, not a
cure.

Check which mode is active with `toolkit/imds_check.py` (see `../toolkit/README.md`).

## 🔑 The (fake) credentials served

```
Role            : lab-ec2-demo-role
AccessKeyId     : ASIAZ4LAB5EXAMPLE999
SecretAccessKey : wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Token           : FAKESESSIONTOKEN-lab-only-not-real-do-not-use-EXAMPLE==
Expiration      : 2026-10-28T10:00:00Z
```

These are invented. `ASIA...` marks short-lived STS credentials; the secret key
is AWS's own published *example* value. **They authenticate to nothing.**

## Why this exists

This is the "crown jewel" an SSRF attack pivots to. It reproduces the exact
situation behind the **2019 Capital One breach**, where an SSRF reached the
metadata endpoint, leaked IAM credentials, and those were used against S3 — but
here everything is fake and isolated.

## Reachability

Pinned to IP `169.254.169.254` on the internal Docker network, with **no
published host ports**. Reachable only from inside the lab (i.e. via SSRF from
the vulnerable app), never from your host or the internet.

> ⚠️ **Lab-only.** Contains no real secrets and talks to no real cloud.
