# ROUT QA-draaiboek — praktijktests op het Vercel-deploy

Versie 2026-11-13 · schemaversie 0254 · uit te voeren door de eigenaar op het eigen Vercel-deploy.

Dit draaiboek test wat alleen met echte toestellen, echte kaarten en een echte database kan. Elke stap heeft een verwacht resultaat. Wijkt het af, noteer dan wat je zag en stop met dat onderdeel.

## Spelregels tijdens het testen

- Plak nooit een volledige `/t`-link, code of token in een notitie, chat of ticket. Noteer alleen tijdstip, toestel en resultaat.
- Maak schermafbeeldingen zonder adresbalk als die een kaartlink toont.
- Gebruik een apart testaccount voor registratie. Gebruik je eigen beheeraccount alleen voor de beheerstappen.
- Test op het deploy dat de nieuwste code draait (zie stap 0).

## Nodig

| Wat | Waarvoor |
| --- | --- |
| Android-telefoon met NFC aan, Chrome | NFC-tik, passkey |
| iPhone met NFC (XS of nieuwer), Safari | `/t`-route, passkey |
| Computer met Chrome of Safari | registratie, beheer, boekingen |
| Twee geactiveerde NTAG 424 DNA-kaarten (A en B) | tik-tests; B wordt als verloren geblokkeerd |
| Eén testaccount zonder beheerrechten, je eigen beheeraccount | registratie, toegangscontrole |

## Logboek per test

`ID · datum/tijd · toestel + OS + browser · geslaagd / mislukt · korte omschrijving · schermafbeelding ja/nee`

---

## 0. Gezondheid van het deploy

| ID | Stap | Verwacht |
| --- | --- | --- |
| 0.1 | Open `https://<jouw-domein>/api/public/health` | `status` is `operational`, `schema` is `0254` |
| 0.2 | Staat `schema` lager dan `0254`? | Het deploy draait oude code: eerst opnieuw deployen, dan pas verder |

## 1. Registratie met passkey

| ID | Stap | Verwacht |
| --- | --- | --- |
| 1.1 | Computer, privévenster: start een nieuwe registratie met het testaccount | De browser vraagt een passkey aan te maken |
| 1.2 | Rond de passkey af | Je bent ingelogd en ziet je dashboard |
| 1.3 | Herhaal 1.1–1.2 op Android en op iPhone met een nieuw adres | Werkt op beide; passkey wordt via het toestel aangemaakt |
| 1.4 | Breek de passkey-vraag af tijdens registratie | Er wordt geen account aangemaakt; opnieuw beginnen kan |
| 1.5 | Probeer met een nieuw adres in te loggen via Google, GitHub, Apple of e-mail (alleen als die knop zichtbaar is) | Er wordt geen nieuw account aangemaakt; je wordt naar registratie met passkey gestuurd of krijgt een weigering |

## 2. Inlogcyclus

| ID | Stap | Verwacht |
| --- | --- | --- |
| 2.1 | Log uit en log opnieuw in met de passkey | Inloggen zonder wachtwoord lukt |
| 2.2 | Log in op een tweede toestel; bekijk actieve sessies in je account | Beide toestellen staan in de lijst |
| 2.3 | Meld het tweede toestel af vanaf het eerste | Het tweede toestel is bij de volgende actie uitgelogd |
| 2.4 | Ververs na uitloggen een pagina die achter inloggen zit | Je komt op de inlogpagina, er verschijnen geen accountgegevens |

## 3. NFC-tik op Android

| ID | Stap | Verwacht |
| --- | --- | --- |
| 3.1 | Ingelogd op Android: start een gevoelige actie die bevestiging met de kaart vraagt | Het scherm vraagt je ROUT Card te tikken |
| 3.2 | Tik kaart A tegen de telefoon | De actie wordt bevestigd en het scherm gaat vanzelf verder |
| 3.3 | Tik kaart A zonder openstaand verzoek | Alleen een kaartcontrole, er wordt niets bevestigd |
| 3.4 | Start een verzoek, tik pas na meer dan 5 minuten | Het verzoek is verlopen, er wordt niets bevestigd |

## 4. `/t`-route op iPhone

| ID | Stap | Verwacht |
| --- | --- | --- |
| 4.1 | Start op de computer een gevoelige actie met kaartbevestiging | De computer wacht op je kaart |
| 4.2 | Houd kaart A bovenaan de iPhone en tik op de melding | Safari opent het scherm "Bevestigen met je ROUT Card?" |
| 4.3 | Kijk naar de adresbalk zodra het scherm geladen is | De kaartcode staat niet meer in het adres |
| 4.4 | Tik op "Ja, ik bevestig" | Bevestigd; de computer gaat vanzelf verder |
| 4.5 | Herhaal 4.1–4.2 en tik op "Nee, dit was ik niet" | Scherm "Niets bevestigd"; de computer gaat niet verder; het verzoek vervalt binnen 5 minuten |
| 4.6 | Open de kaartlink van 4.4 opnieuw via de geschiedenis van Safari | Geweigerd: een tik is maar één keer bruikbaar |
| 4.7 | Tik de kaart van iemand anders (of kaart B van een ander account) bij jouw openstaand verzoek | Geweigerd |

Het bevestigingsscherm volgt de gekozen taal (Nederlands, Engels, Frans, Duits); zie stap 8.3.

## 5. Kaart blokkeren als verloren

| ID | Stap | Verwacht |
| --- | --- | --- |
| 5.1 | Start een verzoek met kaartbevestiging, laat het openstaan | Wacht op kaart |
| 5.2 | Blokkeer kaart B in je account als verloren | Bevestiging dat de kaart geblokkeerd is |
| 5.3 | Tik kaart B voor een nieuw verzoek | Geweigerd; kaart B telt niet meer als kaartbevestiging |
| 5.4 | Kijk naar het verzoek uit 5.1 | Vervallen |
| 5.5 | Tik kaart A voor een nieuw verzoek | Werkt nog |

## 6. Beheeromgeving

| ID | Stap | Verwacht |
| --- | --- | --- |
| 6.1 | Testaccount (geen beheerder): open `/admin` | Scherm "Geen toegang tot beheer" met een knop terug naar je dashboard; nooit even een beheerscherm |
| 6.2 | Zelfde, open `/admin/cards` direct | Hetzelfde weigerscherm |
| 6.3 | Ontwikkelaarstools, tabblad Netwerk, bij 6.1 | Geen verzoeken die beheergegevens teruggeven |
| 6.4 | Beheeraccount zonder tweestapsverificatie | Je moet die eerst instellen |
| 6.5 | Beheeraccount met tweestapsverificatie | Beheeromgeving opent normaal |

## 7. Boekingen

| ID | Stap | Verwacht |
| --- | --- | --- |
| 7.1 | Ingelogd: open `/studio/booking` | Je komt op `/studio?page=booking` en het boekingenpaneel staat open |
| 7.2 | Open `/studio?page=iets-anders` | Studio opent normaal; `page` verdwijnt uit het adres |
| 7.3 | Uitgelogd: open `/studio/booking` | Je wordt naar inloggen gestuurd en ziet geen Studio-gegevens. Noteer waar je na inloggen uitkomt |

## 8. Talen

| ID | Stap | Verwacht |
| --- | --- | --- |
| 8.1 | Zet de taal op Engels, Frans en Duits; herhaal 6.1 | Weigerscherm volledig in de gekozen taal |
| 8.2 | Herhaal 1.1 en 7.1 in elke taal | Geen Nederlandse resten, geen technische sleutels zichtbaar |
| 8.3 | Zet de taal op Engels, Frans en Duits en herhaal 4.1–4.5 | Bevestigingsscherm, knoppen ("Yes, I confirm" / "Oui, je confirme" / "Ja, ich bestätige") en "Niets bevestigd"-scherm in de gekozen taal. Het zegel "Authentic ROUT Card · Cryptographically Verified" blijft bewust Engels |

## 9. Na afloop

- Log uit op alle testtoestellen.
- Laat kaart B geblokkeerd of vervang hem.
- Stuur het logboek (zonder links of codes) door; mislukte stappen worden apart opgepakt.
