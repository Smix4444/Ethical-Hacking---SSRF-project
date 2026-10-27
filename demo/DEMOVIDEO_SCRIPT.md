# 🎬 Demovideo-script — SSRF Lab (~7-9 min)

Draaiboek voor een vloeiende demo. Verhaallijn: **de aanval lukt → de
verdediging bouwt op → de kill-chain-tool**. Per segment: *wat je toont*, *welk
commando je typt*, *wat je zegt* (NL spreektekst), en *wat de kijker ziet*.

> Tip vooraf: open één PowerShell-venster in de repo-root en één browser. Zorg dat
> Docker Desktop draait en dat je **OneDrive even pauzeert**. Alles is nep & lab-only.

---

## 0 · Intro (~30s)
- **Zeg:** "Dit is mijn SSRF-lab voor Ethical Hacking. Server-Side Request Forgery
  laat een server verzoeken doen namens de aanvaller — richting interne systemen
  die je normaal nooit bereikt. Het is de kwetsbaarheid achter de Capital
  One-hack. Ik laat de aanval zien én, belangrijker, hoe je hem laag per laag
  tegenhoudt. Alles draait lokaal in Docker, alle credentials zijn verzonnen."

## 1 · Het lab starten (~30s)
- **Toon:** de terminal.
- **Commando:**
  ```powershell
  docker compose up -d --build
  docker compose ps
  ```
- **Zeg:** "Eén commando start vijf services: de kwetsbare app, een nep
  AWS-metadata-service, een WAF, een redirector en een out-of-band listener."
- **Kijker ziet:** vijf containers `Up`.

## 2 · De aanval lukt — L0 (~1 min)
- **Toon:** browser op **http://localhost:8088** (de "URL Preview Service", niveau L0).
- **Commando (in het URL-veld plakken):**
  ```
  http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-ec2-demo-role
  ```
- **Zeg:** "Dit is een onschuldig ogende 'preview'-functie. Maar ik geef haar het
  interne cloud-metadata-adres, 169.254.169.254 — dat ik zelf nooit kan bereiken.
  De server haalt het wél op… en geeft me de tijdelijke IAM-credentials terug.
  Dat is exact wat bij Capital One gebeurde."
- **Kijker ziet:** JSON met `ASIAZ4LAB5EXAMPLE999` — de buit.

## 3 · De verdediging klimt — L0→L3 in één tabel (~1.5 min)
- **Toon:** de terminal.
- **Commando:**
  ```powershell
  python toolkit/ssrf_scan.py
  ```
- **Zeg:** "Nu zet ik vier verdedigingsniveaus naast elkaar. **L1** is een naïeve
  blocklist — die blokkeert het letterlijke IP, maar ik omzeil het met het IP in
  decimale of hex-vorm. **L2** decodeert die trucjes wél, maar ik omzeil het met
  een redirect of een onschuldige DNS-naam. **L3** doet het juist: de hostnaam
  resolven, het échte IP controleren, daarop pinnen, en redirects hervalideren —
  die houdt álles tegen, terwijl gewoon verkeer blijft werken."
- **Kijker ziet:** de matrix — LOOT schuift naar BLOCKED naarmate je naar L3 gaat;
  `legit-example` blijft FETCHED.

## 4 · De WAF-nuance (~1.5 min)
- **Toon:** de terminal.
- **Commando:**
  ```powershell
  python toolkit/ssrf_scan.py --compare
  ```
- **Zeg:** "Veel mensen denken: zet er een WAF voor en klaar. Kijk wat er gebeurt.
  De WAF — ModSecurity met de OWASP Core Rule Set — blokkeert álle IP-vormen netjes
  met een 403. Maar de aanval via een nette hostnaam of een redirect wandelt er
  gewoon doorheen en haalt alsnog de creds. Dat is precies waarom Capital One
  misging: er stónd een WAF. Een WAF is een extra laag, geen vervanging voor
  correcte app-logica."
- **Kijker ziet:** `via-WAF`-kolom: IP-payloads = WAF-403, maar `302-redirect` en
  `dns-innocent` = LOOT.

## 5 · De platform-laag — IMDSv2 (~1.5 min)
- **Toon:** de terminal.
- **Commando's:**
  ```powershell
  $env:IMDS_MODE="v2"; docker compose up -d metadata-service
  ```
  ```powershell
  docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" python:3.12-slim python /t/ssrfkit.py loot
  ```
- **Zeg:** "AWS' eigen antwoord op Capital One was IMDSv2. Dat eist eerst een
  token via een PUT-verzoek plus een header bij elke read. Een kale SSRF-GET kan
  dat niet. Ik zet de metadata op IMDSv2 en voer exact dezelfde aanval opnieuw
  uit…"
- **Kijker ziet:** `No credentials returned … 401 - Unauthorized. IMDSv2 requires
  a session token`.
- **Zeg (afrondend) + commando:**
  ```powershell
  $env:IMDS_MODE="v1"; docker compose up -d metadata-service
  ```
  "De aanval strandt op 401 — zelfs zonder app-bescherming. Ik zet het weer terug."

## 6 · De toolkit — hele kill chain in één run (~1.5 min)
- **Toon:** de terminal.
- **Commando:**
  ```powershell
  docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" python:3.12-slim python /t/ssrfkit.py full
  ```
- **Zeg:** "Tot slot mijn eigen tool, `ssrfkit`, die alles langs de Cyber Kill
  Chain legt: **recon** — hier bevestig ik zelfs *blinde* SSRF out-of-band: de app
  belt mijn listener met een uniek token, zonder dat ik de respons zie.
  **weaponize** maakt de payloads, **exploit** vuurt ze af met en zonder WAF, en
  **loot** haalt de creds. Zo denk je gestructureerd als pentester in plaats van
  willekeurig te proberen."
- **Kijker ziet:** RECON → `blind SSRF CONFIRMED`, en de volledige keten tot LOOT.

## 6b · DNS rebinding — de ultieme TOCTOU-test (~1 min)
- **Toon:** de terminal.
- **Commando:**
  ```powershell
  docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" python:3.12-slim python /t/ssrfkit.py rebind
  ```
- **Zeg:** "Tot slot de slimste aanval: DNS rebinding. Een filter dat de naam
  controleert en dan de HTTP-client opnieuw laat resolven, wordt verslagen — kijk
  naar de flip: query 1 is een veilig IP dat de check passeert, query 2 is het
  interne metadata-IP waar de app dan mee verbindt. Mijn L2.5-niveau lekt daardoor
  de creds. Maar mijn echte L3 resolvet één keer en pint op dat IP — die
  blokkeert het. Dit is exact CVE-2024-24759 bij MindsDB, nu live in mijn lab."
- **Kijker ziet:** `A query #1 -> 1.1.1.1`, `A query #2 -> 169.254.169.254`;
  L2.5 = LOOT, L3 = BLOCKED.

## 6c · Finale — live dashboard + pentestrapport (~1.5 min)
- **Toon:** de browser op **http://localhost:8099** (het dashboard).
- **Zeg:** "Om alles samen te brengen heb ik een live dashboard gebouwd. Hier zie
  je de topologie van het lab met alle services groen/up."
- **Doe:** kies niveau **L0** en klik **🚀 Launch SSRF**.
- **Kijker ziet:** het pad app→metadata kleurt **rood** ("LOOT"), de teller
  "credentials exfiltrated" springt omhoog.
- **Doe:** zet op **L3** en klik opnieuw.
- **Kijker ziet:** het pad wordt **groen/BLOCKED** met de reden. "Zelfde aanval,
  andere verdediging — visueel het verschil."
- **Doe:** klik **Run** bij de matrix, de WAF-vergelijking en de rebind-panel.
- **Kijker ziet:** de gekleurde L0-L3-matrix (rood=LOOT, groen=BLOCKED), de
  WAF-kolommen, en de rebind-flip (query #1 veilig → query #2 intern).
- **Zeg + commando (terminal):** "En als pentester lever je een rapport. Dit
  commando test het hele lab en genereert een professionele scorecard."
  ```powershell
  docker run --rm --network ssrf-lab_ssrflab -v "${PWD}/toolkit:/t" -v "${PWD}/reports:/out" python:3.12-slim python /t/ssrfkit.py report --out /out
  ```
- **Doe:** open **`reports/report.html`** in de browser.
- **Kijker ziet:** een nette pentest-scorecard met executive summary, bevindingen
  met severity, bewijs, remediation, en de MITRE ATT&CK-mapping. "Dit is wat een
  consultant zou opleveren — gegenereerd uit echte testdata van mijn lab."

## 7 · Afsluiten (~45s)
- **Zeg:** "Samengevat: SSRF lukt moeiteloos zonder verdediging, filters en zelfs
  een WAF zijn te omzeilen, en enkel correcte validatie (resolve-then-pin) plus
  platform-hardening (IMDSv2) stoppen de aanval echt — defense-in-depth. Ik heb
  dit ook gekoppeld aan echte CVE's en de Capital One-casus in mijn
  reality-dossier, zonder ooit een echte applicatie aan te vallen."
- **Commando:**
  ```powershell
  docker compose down
  ```
- **Kijker ziet:** de services netjes afgebroken.

---

### Opnametips
- Zoom in op de terminal (lettergrootte omhoog) en op de JSON-buit in de browser.
- Houd per segment de **rode draad** aan: *lukt het? → waarom? → hoe stop je het?*
- Toon de matrix-tabellen even stil zodat de kijker LOOT→BLOCKED ziet verschuiven.
- Noem minstens één keer expliciet "alles is nep en lab-only".
- Totale richttijd: 7-9 minuten. Oefen de overgangen één keer droog.
