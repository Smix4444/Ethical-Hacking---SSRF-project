# metadata-service/

**Phase 1–2.** A mock cloud metadata service that imitates the *shape* of the
AWS EC2 Instance Metadata Service (IMDSv1) at `http://169.254.169.254/`, using
entirely **fake, invented IAM credentials**.

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
