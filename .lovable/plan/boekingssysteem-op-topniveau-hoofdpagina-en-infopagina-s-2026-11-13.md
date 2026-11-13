# Boekingssysteem op topniveau + hoofdpagina en infopagina's

## Wat er nu al staat (nagekeken)
- Vrije tijden berekenen, team-boekingen (iedereen samen of één van het team), tijdelijke reservering van 5 minuten, dag/week/maand-limieten, werkdagen-venster, aansluitende tijden en groepssessies (db/0216 t/m 0220).
- Externe agenda's alleen via een gewone agenda-link (ICS) die periodiek wordt opgehaald. Er is nog geen koppeling met Google, Outlook of iCloud via inloggen, geen meldingen bij wijzigingen en geen grootboek van boekingsgebeurtenissen.
- Er bestaat al een AI-koppeling (/api/mcp), maar die kent nog geen boekingshulpmiddelen.

## Werkwijze
Elke fase wordt apart opgeleverd, getest en aan jou voorgelegd. Databasewijzigingen schrijf ik eerst als bestand en test ik in de testdatabase. Op Neon gaan ze pas na jouw GO, volgens de vaste volgorde: eerst uitbreiden, dan afsluiten.

## Fase A — Hoofdpagina, ontdek-, about- en infopagina's (eerst, want direct zichtbaar)
1. Alle pagina's doorlopen op 12 schermformaten (320, 360, 384, 414, 768, 834, 1024, 1280, 1440, 1920 breed, plus liggend), met schermafbeeldingen per pagina.
2. Alles herstellen wat afgesneden, weggelaten of overlopend is, zoals tabellen en de scrollende "9 pagina's"-sectie op mobiel. Tabellen worden op smalle schermen kaarten of netjes scrollbare blokken, nooit afgeknipt.
3. Teksten en knoppen nalopen op de recente veranderingen in deze chat: herstelaanvragen, kluis en passkeys.
4. Een eigen voorbeeldafbeelding per pagina voor gedeelde links, plus volledige titels en omschrijvingen in NL/EN/FR/DE.
5. Ontwerp verfijnen binnen de bestaande huisstijl: typografie, ritme, beweging en contrast, zonder de huidige stijl van de openbare pagina's te breken.

## Fase B — Database (alles eerst achter "uitbreiden")
- `booking_events`: een grootboek waar alleen bij geschreven wordt. Elke gebeurtenis is gekoppeld aan de vorige via een hash, en de server ondertekent haar. De status van een boeking wordt afgeleid door de gebeurtenissen opnieuw af te spelen. De huidige `bookings`-tabel blijft als snel leesoverzicht dat alleen door de database zelf wordt bijgewerkt. Een controle vergelijkt overzicht en grootboek.
- `calendar_connections` (Google, Microsoft, CalDAV): de toegangssleutels van externe agenda's staan alleen als versleutelde envelop in de kluis. De app ziet enkel een ondoorzichtige verwijzing, nooit de sleutel zelf.
- `calendar_sources`: een overzicht per agenda: "telt mee voor conflicten" en "hierin schrijven". Daarnaast de stand van de synchronisatie (syncToken, deltaLink, ctag/etag) en de meldingskanalen met hun vervaldatum.
- `routing_forms` en `routing_rules`, `booking_locations` (video, telefoon, adres) en `cancellation_policies`.
- Voor elke tabel: toegang per rij, rechten per functie en bewaking van de zoekpaden.

## Fase C — Koppelingen en synchronisatie
- Google: inloggen, `events.watch` en incrementele synchronisatie met syncToken. Kanalen worden vóór hun vervaldatum vernieuwd.
- Microsoft: inloggen, abonnementen op wijzigingen en deltaLink, met automatische vernieuwing.
- CalDAV (iCloud, Fastmail, Nextcloud, Proton Bridge): sync-collection, met ctag/etag als terugval.
- Toegangssleutels worden onder een vergrendeling ververst, zodat twee gelijktijdige verversingen elkaar niet hinderen.
- Het zware werk gebeurt in de Omni-werker; de webkant ontvangt alleen de meldingen en controleert ze.
- Verplaatst of verwijdert de host een afspraak in zijn eigen agenda? Dan komt er een gebeurtenis in het grootboek en krijgt de gast een mail met een bijgewerkt .ics-bestand (REQUEST of CANCEL, met een oplopend volgnummer).
- Herhalende afspraken met uitzonderingen worden uitgerekend op de klok van de afspraak zelf, met tests rond de zomer- en wintertijd.

## Fase D — Tijden en verdeling over het team
- Gewogen beurtrol: verdeling volgens gewicht, eerlijk verdeeld over de geboekte uren van de laatste 30 dagen. Heeft de eerste keuze plots een conflict, dan neemt de volgende het over. Dit wordt in de database beslist.
- Gezamenlijke beschikbaarheid over hosts in verschillende tijdzones (bestaat al, en wordt uitgebreid getest).
- Routeringsvragen vooraf, die de bezoeker naar het juiste afspraaktype of de juiste specialist sturen.
- De publieke kant krijgt alleen anonieme tijdvakken of een bitmasker, nooit een omschrijving van een afspraak.

## Fase E — Vergaderruimtes, betalingen en annuleren
- Google Meet, Microsoft Teams en Jitsi met een willekeurige kamernaam. Daarnaast vaste locatie, "ik bel jou" of "jij belt mij", en een eigen adres met kaartlink.
- Betaalde afspraken via Stripe, bunq, SEPA/EPC-QR of Wero. De tijdelijke reservering blijft lopen tijdens het betalen en vervalt met een gebeurtenis in het grootboek.
- Een annuleringsbeleid met deadlines, dat in de database wordt afgedwongen.

## Fase F — Pagina's en mails
- Boekingspagina: aangrenzende maanden worden vooraf geladen, tijdzone automatisch herkend, keuze tussen 12 en 24 uur, een zichtbare aftelklok tijdens de reservering, en de eigen ROUT-agenda over die van de host leggen.
- Beheerpagina voor de gast via een ondertekende link: verzetten, annuleren, gasten toevoegen, .ics opnieuw downloaden.
- Editor voor de host: weekrooster, uitzonderingen (vakantie, afwijkende dagen) en een live voorbeeld.
- Alle teksten, mails en .ics-omschrijvingen in NL/EN/FR/DE.

## Fase G — Privacy, ROUT ID, Wallet en AI
- Gevoelige antwoorden op intakevragen worden in de browser versleuteld voor de host.
- Wie met ROUT inlogt, krijgt zijn naam en e-mailrelay vooraf ingevuld en kan met één klik boeken. De afspraak komt als pas in de ROUT Wallet, Apple Wallet of Google Wallet.
- AI-hulpmiddelen via /api/mcp: vrije tijden opvragen en een boeking voorbereiden (een tijdelijke reservering), met strenge controle van de invoer. Een AI bevestigt nooit zelf een boeking.

## Nodig van jou (blokkeert alleen de fase in kwestie)
- Google Cloud OAuth-app (client-id/secret, domeinverificatie voor de meldingen) — fase C/E.
- Microsoft Entra-app (client-id/secret) — fase C/E.
- Een plek waar de Omni-werker blijvend draait, met toegang tot Neon — fase C.
- GO per databasemigratie op Neon.

## Technische details
- Migraties vanaf 0265, elk met een eigen PGlite-test (`*-postgres.test.ts`). Iedere SECURITY DEFINER-functie krijgt `pg_catalog, pg_temp`, en EXECUTE-rechten worden expliciet gezet. Afsluitende migraties komen in db-pending/ tot de health-check het juiste schemaniveau meldt.
- Envelop voor de sleutels: RVE1 (ML-KEM + AES-GCM), gekoppeld aan eigenaar en doel ("calendar_refresh:<connection>").
- Het grootboek wordt geschreven onder dezelfde vergrendelingen per host en dag als `rout_booking_create`. De hash-keten volgt het patroon van de kluis-audit. Een trigger weigert UPDATE en DELETE.
- Regeltests (`*-rules.test.ts`): zomer- en wintertijd, buffers, gewogen verdeling, verval van reserveringen, uitzonderingsdatums, volgnummers.
- Oplevering per fase: tsgo, lint, vitest (volledig), de rechten-audit en schermafbeeldingen voor de pagina's.
