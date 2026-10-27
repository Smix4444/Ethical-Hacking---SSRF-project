# metadata-service/

**Phase 2.** A mock cloud metadata service that imitates the *shape* of a
cloud provider's instance-metadata endpoint — using entirely **fake,
invented IAM credentials**.

## Purpose

Give the lab a realistic "crown-jewel" internal target, so we can show
*why* an SSRF that reaches a metadata endpoint is so damaging — without
ever touching a real cloud account.

## Important

- Every credential served here is **fake** and meaningless outside this lab.
- It is reachable **only** from inside the Docker network, never from the
  host's real network or the internet.

## Status

🟡 Placeholder — no code yet. Built in Phase 2.

> ⚠️ **Lab-only.** Contains no real secrets and talks to no real cloud.
