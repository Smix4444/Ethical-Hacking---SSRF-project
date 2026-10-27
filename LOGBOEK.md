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
