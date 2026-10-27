# Security & Ethics Policy

This document defines the ethical boundaries of the **SSRF Lab** project. It
applies to every file, script and tool in this repository.

## 1. Purpose

This project exists **solely** for education and authorized security training, as
part of an Ethical Hacking course. It teaches how Server-Side Request Forgery
(SSRF) works, how it is exploited, and — equally — how it is defended against.

Understanding offensive techniques is a prerequisite for building effective
defenses. That is the only reason the offensive material here exists.

## 2. Lab-only — the hard rules

1. **Isolation.** Every component runs locally, on a private Docker network. No
   service is ever published to the public internet or a production environment.
2. **Fake credentials only.** All "cloud" / IAM credentials in this lab are
   invented strings. They authenticate to nothing in the real world.
3. **No real targets.** The tooling in `toolkit/` is pointed **exclusively** at
   the lab's own containers. It is never aimed at any third-party system.
4. **Permission.** Use any technique shown here only against systems you own or
   have **explicit, written authorization** to test.

## 3. What this project is NOT

- ❌ Not a tool for attacking live websites, cloud accounts or networks.
- ❌ Not a store of real secrets, access keys or personal data.
- ❌ Not something to deploy, host publicly, or run outside the lab.

## 4. Legal note

Accessing computer systems without authorization is illegal in virtually every
jurisdiction (in Belgium, e.g. the Computer Crime Act / *Strafwetboek* art. 550bis).
The author accepts no liability for misuse of this material. If you did not create
the target and were not authorized to test it, **do not**.

## 5. Responsible handling of credentials

- Real-valued secrets are kept only in **git-ignored** files (`.env`,
  `*.local.md`) and never committed.
- Example templates (`*.example`) contain placeholders only.
- Even though this lab's credentials are fake, we practice good hygiene with them,
  so the habit carries over to real work.

## 6. Reporting

This is a self-contained educational lab with no external users. If you fork or
reuse it and find an issue worth noting, document it in `docs/` rather than in any
public tracker tied to a real system.

---

*By using this repository you agree to use it ethically, legally, and only within
an isolated lab. See [LICENSE](LICENSE).*
