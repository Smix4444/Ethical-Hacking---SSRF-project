# oob-listener/

**Phase 6 · lab component.** An internal **out-of-band (OOB) callback collector**
used to detect **blind SSRF** — where the vulnerable app makes a request but does
not return the response to you.

## How it is used

`ssrfkit recon` generates a unique token, makes the app fetch
`http://oob-listener.lab/cb/<token>`, then polls `http://oob-listener.lab/seen/<token>`.
If the callback arrived, SSRF is confirmed **even with no direct response body**.

| Path | Purpose |
|------|---------|
| `/cb/<token>` | the target calls this via SSRF; the token is recorded |
| `/seen/<token>` | the toolkit polls this (`{"seen": true/false}`) |
| `/hits` | list all tokens seen |

## Safety

Reachable only inside the Docker network as **`oob-listener.lab`**, with **no
published host port**. It holds nothing sensitive — only tokens it was pinged
with.

## Realism note

In a real engagement this role is an attacker-owned server such as **Burp
Collaborator** or **interactsh**. Here it is an internal lab service; no real
external callbacks ever happen.

> ⚠️ **Lab-only.**
