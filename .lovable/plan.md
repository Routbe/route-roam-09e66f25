# Boekingssysteem op topniveau + hoofdpagina en infopagina's — vervolg

Alles blijft op je eigen infrastructuur (Neon, Vercel, eigen Omni-werker). Niets gaat naar Neon zonder jouw GO per migratie.

## Stand van zaken (nagekeken)
- Het boekingssysteem bestaat al: vrije tijden, teams, reserveringen van 5 minuten, limieten, groepssessies (db/0216–0220). Code in `src/lib/booking-engine/` (o.a. `slot-rules.ts`, `hold-rules.ts`, `routing.ts`, `ledger.ts`, `bitmap.ts`, `ics.ts`).
- `db/0265_booking_ledger.sql` (grootboek, 458 regels) staat al in `db/`, is **niet** uitgevoerd op Neon, en breekt nu 2 controles:
  - de lege-database-test faalt omdat `pg_catalog.greatest(...)`/`pg_catalog.least(...)` geen functies zijn in PostgreSQL (het zijn taalconstructies; ze mogen niet met een schema ervoor);
  - de app meldt nog versie 0264 terwijl 0265 in `db/` staat.
- Externe agenda's: alleen ICS-links. Nog geen Google/Microsoft/CalDAV-login, geen meldingen, geen grootboek live.

## Stap 0 — Eerst de basis gezond (klein, direct)
- 0265 herstellen (`greatest`/`least` zonder schema) en tot jouw GO verplaatsen naar `db-pending/`, conform je eigen regel. Versie blijft 0264, beide controles weer groen.
- Volledige testronde: nu 8 rood → doel 0 rood (de overige 6 eerst diagnosticeren, niet gokken).

## Fase A — Hoofdpagina, ontdek, about, info (gelijktijdig met B)
1. Meetronde met schermafbeeldingen op 320, 360, 384, 414, 768, 834, 1024, 1280, 1440, 1920 + liggend, voor hoofdpagina, `/discover/*`, `/about/*`, `/info/*`, boekingspagina's.
2. Automatische controle per formaat: horizontale overloop, afgesneden elementen, verschuiving tijdens laden (CLS), tikdoelen kleiner dan 44px, contrast onder AAA.
3. Herstellen: de "9 pagina's"-scrollsectie op mobiel, tabellen → kaarten of netjes scrollbare blokken, niets weggelaten of afgeknipt. Animaties alleen via transform/opacity, met respect voor "minder beweging".
4. Teksten nalopen op recente wijzigingen (herstel 2-van-3, passkeys, kluis).
5. Per pagina eigen titel, omschrijving en deelafbeelding (1200x630) in NL/EN/FR/DE.
6. Ontwerp verfijnen binnen de bestaande huisstijl.
Oplevering: voor/na-schermafbeeldingen per formaat + rapport van de automatische controle.

## Fase B — Database (alles als "uitbreiden", eerst in testdatabase)
- **0265 grootboek** `booking_events`: alleen toevoegen, hash-keten per host, serverhandtekening, persoonsgegevens alleen als salted commitment (crypto-shredding bij verwijderen). Trigger weigert UPDATE/DELETE. Status wordt afgeleid door herafspelen; `bookings` blijft overzicht dat alleen de database bijwerkt, met een controlefunctie overzicht ↔ grootboek.
- **0266 agendakoppelingen**: `calendar_connections` (Google/Microsoft/CalDAV) — sleutels alleen als RVE1-envelop in `vault_enclave`, gebonden aan eigenaar en doel `calendar_refresh:<id>`; de app ziet enkel een `vtk_`-verwijzing.
- **0267 agendabronnen en sync-stand**: per agenda "telt mee voor conflicten" / "hierin schrijven", syncToken / deltaLink / ctag-etag, meldingskanalen met vervaldatum, verversvergrendeling.
- **0268 routering, locaties, annuleringsbeleid**: routeringsformulieren + regels, locaties (Meet/Teams/Jitsi/adres/telefoon), deadlines afgedwongen in SQL.
- **0269 gewogen beurtrol**: gewicht + eerlijke verdeling over 30 dagen + terugval, beslist in de database.
- Per migratie: RLS voor `rout_app` en `rout_omni_worker`, `search_path = pg_catalog, pg_temp`, expliciete EXECUTE-rechten, PGlite-test (`*-postgres.test.ts`), snapshot + types bijgewerkt. Afsluitende stappen in `db-pending/` tot de health-check het juiste niveau meldt.
Oplevering: migraties + tests getoond aan jou, daarna GO per migratie.

## Harde eisen voor Fase B t/m G (jouw toevoeging)
1. **Zero-knowledge versleuteling in de browser**: titels, beschrijvingen, notities en intake-antwoorden worden in de browser versleuteld (crypto-enclave-werker, sleutel via WebAuthn PRF / toestelgebonden hoofdsleutel). Server en Neon krijgen alleen versleutelde blobs en zien nooit platte tekst.
2. **Conflicten via blinde indexen**: bezetting alleen als tijdslot-bitmaskers (`bitmap.ts`) en blinde hashes. De server weet *dat* een slot bezet is, niet door wie of waarvoor.
3. **Wiskundige invarianten in het grootboek (0265)**: database-triggers en RPC's dwingen af dat er geen dubbele boekingen en geen splitsing in de toestand kunnen ontstaan: één keten per host, `(host, prev_hash)` uniek, vergrendeling per (host, UTC-dag), en elke toestandsovergang gecontroleerd tegen de herafgespeelde toestand.
4. **Cryptografische gastverificatie (Fase G)**: inchecken en verifiëren gebeurt met W3C Verifiable Credentials en een selectief-onthullend bewijs dat de gast een geldig tijdslot bezit, zonder dat zijn identiteit wordt onthuld.

Gevolg voor de host: wie de versleutelde inhoud van een afspraak wil lezen, moet zijn passkey of toestel ontgrendelen. Mails naar de gast bevatten alleen wat de gast zelf heeft opgegeven.

## Fase C — Koppelingen en synchronisatie (code klaar en lokaal getest, live na sleutels)
- Google: OAuth, `events.watch`, syncToken-delta, kanaalvernieuwing.
- Microsoft: OAuth, subscriptions, deltaLink, vernieuwing.
- CalDAV: sync-collection, ctag/etag als terugval.
- Webkant ontvangt en controleert meldingen; Omni-werker doet ophalen, verversen en vernieuwen. Publieke kant krijgt alleen bitmaskers / anonieme tijdvakken.
- Wijziging door host in eigen agenda → grootboekgebeurtenis → mail met .ics (REQUEST/CANCEL, oplopende SEQUENCE).
- Tests met opgenomen API-antwoorden (geen echte accounts nodig).

## Fase D–G (zoals eerder goedgekeurd, na B/C)
- D: routeringsvragen, gezamenlijke beschikbaarheid over tijdzones, uitgebreide regeltests.
- E: Meet/Teams/Jitsi, betaalde afspraken (Stripe, bunq, SEPA/EPC, Wero) met lopende reservering, annuleringsbeleid.
- F: boekingspagina (vooraf laden, tijdzone, 12/24u, aftelklok, eigen agenda als overlay), gastportaal via ondertekende link, editor voor de host, alles in NL/EN/FR/DE.
- G: versleutelde intake, ROUT ID één-klik-boeken, afspraakpas in Wallet, MCP-hulpmiddelen (vrije tijden lezen, reservering voorbereiden; bevestigen alleen na passkey/step-up van een mens).

## Nodig van jou
- GO per migratie op Neon.
- Google Cloud OAuth-app en Microsoft Entra-app (fase C/E live).
- Host voor de Omni-werker met toegang tot Neon (fase C live). De bestaande Dockerfile mist `worker/bun.lock` en kopieert `render-hosts.ts` niet; dat herstel ik mee.

## Technische details
- Oplevering per fase: tsgo, lint, volledige vitest, `scripts/audit-rls.ts` (in testdatabase), schermafbeeldingen.
- Regeltests (`*-rules.test.ts`): zomer/wintertijd, EXDATE, buffers, gewogen verdeling, reserveringsverval, SEQUENCE.
- Grootboek onder dezelfde (host, UTC-dag)-vergrendelingen als `rout_booking_create`; hash-keten volgens het patroon van de kluis-audit; serverhandtekening via bestaande serverkluis-sleutel (`ROUT_VAULT_KEK`-gewikkeld).
- Geen enkele wijziging aan Neon of aan productie zonder jouw expliciete GO.
