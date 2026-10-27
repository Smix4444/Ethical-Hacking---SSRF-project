# Testverslag — Live end-to-end slottest (Fase 7A)

**Datum:** 2026-10-27 · **Lab-only, alle credentials nep.**

Eerste keer dat alle componenten tegelijk live draaiden (app L0–L3, WAF,
IMDSv1/v2, redirector, OOB-listener, `ssrfkit`). Hieronder per onderdeel de
**verwachting** vs. het **echte resultaat**, met de werkelijke output.

## Omgeving

| Item | Waarde |
|------|--------|
| Docker engine | 28.0.1 |
| Host-poorten | `8088` (app direct), `8090` (app via WAF) — beide vrij, Moodle (8080) ongemoeid |
| Netwerk | `ssrf-lab_ssrflab` (169.254.169.0/24), metadata intern op `169.254.169.254` |
| Services (5) | vulnerable-app, metadata-service, redirector, oob-listener, waf — alle gestart |
| WAF-image | `owasp/modsecurity-crs:nginx` (ModSecurity v3 + CRS v4), image-label versie `1.30.6` |
| WAF-digest (reproduceerbaar pinnen) | `owasp/modsecurity-crs@sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d` |

> De `:nginx`-tag is rolling; voor exacte reproduceerbaarheid pin je op de digest
> hierboven, of op een dated tag `4.x-nginx-<YYYYMMDDHHMM>` van Docker Hub.

## a. App-niveaus L0–L3 (zonder WAF)

**Verwachting:** L0 lekt alles; L1 vangt enkel de letterlijke IP; L2 vangt de
encodings maar niet redirect/DNS; L3 vangt alles, legitiem blijft werken.

**Echt resultaat** (`python toolkit/ssrf_scan.py`):

| payload | L0 | L1 | L2 | L3 |
|---|:--:|:--:|:--:|:--:|
| dotted-decimal | LOOT | BLOCKED | BLOCKED | BLOCKED |
| trailing-dot | ERROR | BLOCKED | BLOCKED | BLOCKED |
| decimal-integer | LOOT | LOOT | BLOCKED | BLOCKED |
| hex | LOOT | LOOT | BLOCKED | BLOCKED |
| dotted-hex | LOOT | LOOT | BLOCKED | BLOCKED |
| dotted-octal | LOOT | LOOT | BLOCKED | BLOCKED |
| ipv6-mapped | LOOT | BLOCKED | BLOCKED | BLOCKED |
| 302-redirect | LOOT | LOOT | LOOT | BLOCKED |
| dns-innocent | LOOT | LOOT | LOOT | BLOCKED |
| legit-example | FETCHED | FETCHED | FETCHED | FETCHED |

**Oordeel:** ✅ **komt overeen** met de verwachting (identiek aan Fase 3).
(`trailing-dot` geeft op L0 ERROR i.p.v. LOOT omdat die vorm niet resolvet in de
container — randgeval, geen bug.)

## b. Met vs. zonder WAF (L0)

**Verwachting (Fase 4):** de WAF blokkeert de letterlijke `169.254.169.254` en
misschien `file://`, maar laat de encodings en onschuldige DNS-namen door.

**Echt resultaat** (`python toolkit/ssrf_scan.py --compare`):

| payload | no-WAF | via-WAF |
|---|:--:|:--:|
| dotted-decimal | LOOT | **WAF-403** |
| trailing-dot | ERROR | **WAF-403** |
| decimal-integer | LOOT | **WAF-403** |
| hex | LOOT | **WAF-403** |
| dotted-hex | LOOT | **WAF-403** |
| dotted-octal | LOOT | **WAF-403** |
| ipv6-mapped | LOOT | **WAF-403** |
| 302-redirect | LOOT | **LOOT** |
| dns-innocent | LOOT | **LOOT** |
| legit-example | FETCHED | FETCHED |

**Oordeel:** ⚠️ **week deels af — waardevolle bevinding (geen bug).**
De WAF (CRS v4) blokkeerde **álle IP-gebaseerde payloads in elke encoding**, niet
enkel de letterlijke string — dus sterker dan verwacht op die as. MAAR hij liet
de **hostnaam-gebaseerde** aanvallen door: de 302-redirect via
`preview-service.lab` en de onschuldige DNS-naam `cdn-assets.lab` gaven via de
WAF nog steeds **LOOT**. Legitiem verkeer (`example.com`) passeerde ook.

**Betekenis:** een WAF is generiek en patroon-gebaseerd. Hij vangt het "IP-in-URL"
-patroon goed, maar is blind voor SSRF via een gewone hostnaam of een open
redirect. Een aanvaller omzeilt de WAF simpelweg met een DNS-naam en haalt op L0
alsnog de creds — **exact het Capital One-patroon** (WAF aanwezig, SSRF ging er
doorheen). Bevestigt: de WAF is een extra laag, geen vervanging voor correcte
app-logica (L3) of IMDSv2.

## c. `ssrfkit` volledige kill-chain

**Echt resultaat** (`ssrfkit full` + `recon`/`audit`, binnen het lab-netwerk):

- **RECON (blind SSRF / OOB):** `OOB callback RECEIVED — blind SSRF CONFIRMED`.
  De app belde `http://oob-listener.lab/cb/<token>`; de listener zag het token.
- **WEAPONIZE:** payloads correct gegenereerd.
- **EXPLOIT:** matrix no-WAF vs via-WAF identiek aan (b).
- **LOOT:** `ASIAZ4LAB5EXAMPLE999` + secret/token geëxfiltreerd (IMDSv1).
- **AUDIT:** `IMDSv1 behaviour: a bare GET leaks creds. VULNERABLE.`

**Oordeel:** ✅ **komt overeen.** De OOB-callback werd echt waargenomen — blinde
SSRF-detectie werkt live.

## d. IMDSv2-test

**Verwachting:** dezelfde kale SSRF die bij v1 de creds lekt, strandt bij v2 op
401; de correcte PUT-token-flow werkt wél.

**Echt resultaat** (`IMDS_MODE=v2`, metadata-service herstart):

- `ssrfkit loot` op L0 → `No credentials returned. endpoint said: 401 -
  Unauthorized. IMDSv2 requires a session token`.
- `ssrfkit audit` → `IMDSv1 plain GET -> status 401, creds leaked: False` /
  `IMDSv2 token flow -> PUT 200 ... GET 200, creds: True` → **IMDSv2 ENFORCED**.
- Daarna teruggezet naar v1.

**Oordeel:** ✅ **komt overeen.** Een kale SSRF-GET kan de PUT-token-dans niet
doen en strandt op 401, zelfs zonder enige app-bescherming.

## Eindoordeel

> **Werkt het hele lab end-to-end: JA.** ✅
>
> Alle vijf de services draaien samen; de app-niveaus L0–L3, de WAF-laag,
> IMDSv1/v2 en de `ssrfkit`-kill-chain (incl. blinde SSRF via OOB) gedragen zich
> zoals bedoeld. Geen bugs gevonden. Eén verwachting bijgesteld: de WAF blokkeert
> IP-encodings sterker dan verwacht, maar wordt omzeild via een DNS-naam/redirect
> — wat de defense-in-depth-boodschap net versterkt.
