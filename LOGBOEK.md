# 📓 Logboek — SSRF Lab

Mijn persoonlijke leerdagboek bij dit project. Per stap noteer ik niet alleen
*wát* ik deed, maar vooral *wat ik nu pas snap* (het inzicht) en *waarom het ertoe
doet* in de echte wereld. Nieuwe entries komen **bovenaan**.

---

## ✍️ Sjabloon (kopieer dit blok voor een nieuwe entry)

```markdown
## [####] — JJJJ-MM-DD — <korte titel>

**Fase:** <0–6>

**Wat probeerde ik?**
<Wat was het doel? Welke stappen/commando's heb ik uitgevoerd?>

**Wat gebeurde er / wat snap ik nu pas? (het inzicht)**
<Wat was het resultaat? Welke "aha" had ik? Wat verraste me?>

**Waarom is dit belangrijk? (koppeling echte wereld / verdediging)**
<Hoe hangt dit samen met een echte aanval of verdediging? Welk risico of
welke mitigatie illustreert dit?>
```

---

## [0004] — 2026-10-27 — De juiste verdediging: L3 "resolve-then-pin" (Fase 3)

**Fase:** 3

**Wat probeerde ik?**
Een L3-niveau bouwen dat SSRF-bescherming doet zoals het hoort, en live bewijzen
dat álle Fase 2-bypasses er niet meer doorkomen terwijl legitiem verkeer blijft
werken. L3 doet: scheme-allowlist (enkel http/https) → hostnaam resolven → élk
resulterend IP valideren tegen interne ranges → de verbinding **pinnen** op dat
gevalideerde IP → redirects niet blind volgen maar elke hop hervalideren. Ook
een toolkit-scanner (`ssrf_scan.py`) gemaakt die de hele vergelijkingstabel met
één commando reproduceert.

**Wat gebeurde er / wat snap ik nu pas? (het inzicht)**
De vergelijkingstabel (L0–L3) maakte het visueel: L3 blokkeert de directe
payload, álle encodings, de 302-redirect (`preview-service.lab` → intern IP) en
de onschuldige DNS-naam (`cdn-assets.lab` → 169.254.169.254), terwijl
`example.com` gewoon werkt. Het kerninzicht: het verschil tussen L2 en L3 is
*wat* je valideert. L2 keurt de URL-string/host goed; L3 keurt het **IP goed
waarmee je effectief verbindt** — en verbindt daar dan ook mee (pinnen), zodat
DNS niet kan rebinden tussen controle en connect, en elke redirect-hop opnieuw
door dezelfde poort moet. Je verschuift van "de input proberen te herkennen"
(een wedloop die je verliest) naar "de bestemming bewijzen vóór je ernaartoe
gaat".

Even eerlijk over de grenzen van L3: pinnen werkt hier voor http; voor https
breekt het SNI/cert-validatie (dan heb je een pinning-adapter nodig die de
originele SNI bewaart). Een geavanceerde rebinding-race met TTL=0 blijft
theoretisch lastig. En — het belangrijkste — L3 beschermt enkel déze app.

**Waarom is dit belangrijk? (koppeling echte wereld / verdediging)**
App-niveau-verdediging alleen is onvoldoende: als één endpoint ooit een
URL-fetch mist, ligt het metadata-endpoint weer open. Daarom is *defense in
depth* nodig, en dat is precies wat de volgende fases dekken:
- **IMDSv2** — vereist een sessietoken via een `PUT`-request, dus een kale
  GET-only SSRF (zoals de onze, zoals Capital One) kan de creds niet meer halen.
  Moet wel expliciet afgedwongen worden (`http_tokens=required`; audit met de
  AWS Config-regel `ec2-imdsv2-check`).
- **Netwerk-egress-filtering** en het blokkeren van `169.254.0.0/16` beperken de
  blast radius als SSRF tóch lukt; een strak-geschopte instance-role lekt dan
  minimale rechten.
- OWASP-lijn: mitigeer SSRF met **allowlists, niet denylists** (denylists sneuvelen
  op encodings/rebinding) — wat onze L1→L3-reis empirisch aantoont.

(Bronnen puur als research gelezen; niets aangevallen. Autoritatief: de OWASP
SSRF Prevention Cheat Sheet en AWS' IMDSv2-documentatie.)

---

## [0003] — 2026-10-27 — Waarom blocklists falen: L1/L2 omzeild (Fase 2)

**Fase:** 2

**Wat probeerde ik?**
Twee bewust zwakke verdedigingen in de app bouwen (L1 = substring-blocklist,
L2 = hostname parsen + scheme-check + interne-IP-check) met een live niveau-
schakelaar (env `DEFENSE_LEVEL` + UI-dropdown via `?level=`), en voor elk niveau
de omzeiling aantonen. Toolkit-seed geschreven (`toolkit/ssrf_payloads.py`) die
alternatieve IP-notaties genereert, en een "attacker redirector" + onschuldige
DNS-alias toegevoegd aan het lab. Alles live geverifieerd met `docker compose`.

**Wat gebeurde er / wat snap ik nu pas? (het inzicht)**
- **L1** blokkeert de letterlijke string `169.254.169.254`, maar `http://2852039166/`
  (decimaal), `0xa9fea9fe` (hex), `0251.0376.0251.0376` (octaal) én de DNS-naam
  `cdn-assets.lab` geven allemaal gewoon de nep-creds terug. De filter keek naar
  de *tekst*, niet naar waar de request écht heen ging.
- **L2** dicht die encodings (decodeert de host en blokkeert interne IP-ranges),
  maar valt alsnog door twee gaten: een **302-redirect** vanaf een onschuldig
  ogende host, en een **DNS-naam die L2 nooit opzoekt**. Het kerninzicht — de
  *parse-vs-fetch / check-vs-use* discrepantie: L2 valideert de URL *zoals
  ingegeven*, maar `requests` haalt een ander, intern adres op (na redirect of
  DNS-resolutie) dat nooit opnieuw gecontroleerd wordt.
- Grote les: een blocklist/parse-aanpak is fundamenteel een wedloop die je
  verliest. De juiste verdediging valideert het IP waar je *effectief* mee
  verbindt (resolve-then-pin), volgt geen redirects blind, en segmenteert het
  netwerk. Dat bouwen we in Fase 3/4.

**Waarom is dit belangrijk? (koppeling echte wereld / verdediging)**
Dit is geen theorie — exact deze fouten zitten in recente software:
- **CVE-2024-24759 (MindsDB)**: SSRF-bescherming te omzeilen via **DNS rebinding**
  (validatie slaagt, daarna rebindt de naam naar een intern IP). Precies onze
  "L2 resolvet de naam niet / hercontroleert niet"-fout.
- Advisories bij **CrewAI** en **LLaMA-Factory** (2025): hun `validate_url` keurt
  de URL één keer goed, maar de HTTP-library **volgt redirects en her-resolvet DNS
  zonder hercontrole** → metadata-endpoints bereikbaar. Dat is letterlijk onze
  redirect-bypass. Dit bewijst dat "we valideren toch de URL?" in productie
  structureel misgaat. (Puur als research gelezen; niets aangevallen.)

---

## [0002] — 2026-10-27 — Eerste end-to-end SSRF naar metadata (Fase 1)

**Fase:** 1

**Wat probeerde ik?**
Eén volledige SSRF-aanval op het makkelijkste niveau (L0) laten draaien, zonder
enige bescherming. Concreet: een kwetsbare Flask-app ("URL Preview Service")
gebouwd die een door mij opgegeven URL *server-side* ophaalt; een mock
AWS-metadata-service die op het nagebootste `169.254.169.254` nep IAM-credentials
teruggeeft; en een `docker-compose.yml` die beide op één geïsoleerd Docker-netwerk
(`169.254.169.0/24`) start. Daarna via de browser de metadata uitgelezen en de
nep-credentials "buitgemaakt".

**Wat gebeurde er / wat snap ik nu pas? (het inzicht)**
Dat de kracht van SSRF niet in de app zelf zit, maar in *wie* het verzoek doet.
Vanaf mijn host kan ik `169.254.169.254` niet bereiken (de metadata-service heeft
bewust geen gepubliceerde poort). Maar ik hoef er ook niet bij — ik laat de
*server* het voor me doen. De app wordt mijn proxy naar het interne netwerk. Eén
onschuldig ogende feature ("haal even een preview van deze link op") geeft zo
toegang tot een endpoint dat voor de buitenwereld onzichtbaar hoort te zijn. En
IMDSv1 vraagt geen enkele authenticatie: één GET en de tijdelijke sleutels liggen
op straat.

**Waarom is dit belangrijk? (koppeling echte wereld / verdediging)**
Dit is exact het patroon van de **Capital One-breach (2019)**: een SSRF in een
webtoepassing bereikte het EC2-metadata-endpoint, las de IAM-credentials van de
instance, en die werden gebruikt om data uit S3-buckets te halen (~100 miljoen
klantgegevens). De les voor verdediging die nu al zichtbaar wordt: vertrouw nooit
een door de gebruiker opgegeven URL die de server zelf ophaalt, en behandel
`169.254.169.254` als een te beschermen *interne* asset (netwerksegmentatie,
IMDSv2 met token, egress-filtering). Precies die verdedigingen bouwen we in de
volgende fases als L1–L3 + WAF.

---

## [0001] — 2026-10-27 — Projectskelet & ethiek (Fase 0)

**Fase:** 0

**Wat probeerde ik?**
Een propere, professionele projectstructuur opzetten *voordat* er ook maar één
regel kwetsbare code bestaat. Concreet: de component-mappen aangemaakt
(`vulnerable-app/`, `metadata-service/`, `waf/`, `toolkit/`, `docs/`, `demo/`),
elk met een README; een hoofd-`README.md` met architectuurdiagram en 7-fasen-
roadmap; dit logboek; een ethiek-nota (`SECURITY.md`) en `LICENSE`; en de
hygiëne-bestanden `.gitignore`, `.gitattributes` en `.editorconfig`. Daarna git
geïnitialiseerd op branch `main` met logische tussencommits.

**Wat gebeurde er / wat snap ik nu pas? (het inzicht)**
Dat "setup" niet saai bijwerk is maar al **security-denken** is. Twee dingen
vielen me op:
- `.gitattributes` die LF forceert, lijkt triviaal, maar zonder dat breken straks
  shell-scripts en Dockerfiles *binnenin* de Linux-containers omdat Windows er
  stiekem CRLF in zet. Je bug zit dan niet in je code maar in je line endings.
- Door nú al in `.gitignore` te zetten dat `.env` en `*.local.md` nooit mee
  committen, maak ik het "per ongeluk een secret lekken" structureel onmogelijk —
  in plaats van erop te moeten *opletten*.

**Waarom is dit belangrijk? (koppeling echte wereld / verdediging)**
Gelekte secrets via version control is een van de meest voorkomende echte
incidenten (keys in een publieke commit). De verdediging begint dus niet bij de
firewall maar bij hoe je je repo inricht. En de hele toon van het project —
duidelijk "lab-only", nep-credentials, geïsoleerd Docker-netwerk — zet meteen
vast dat offensieve kennis hier dient om **verdediging** te begrijpen. Dat kader
is precies wat echte ethical hackers onderscheidt van aanvallers.
