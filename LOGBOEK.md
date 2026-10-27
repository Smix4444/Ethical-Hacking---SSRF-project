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
