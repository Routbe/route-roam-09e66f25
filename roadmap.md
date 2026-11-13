# Roadmap

## ROUT Card tap (NTAG 424 DNA) — Batch 1
- [x] db/0245_sdm_tap.sql (EXPAND): fleet MetaRead key, batches, cards by uid_hash, tap attempts, tap grants, RPCs for rout_app only
- [x] sdm-verifier.ts: AN10922 diversification, PICCData decrypt, uid index, constant-time compares + NXP vectors
- [x] sdm-tap.server.ts + vault port methods; PGlite tests as rout_app
- [x] /t public tap page (PICCData only, no card id), "Authentic ROUT Card" badge, replaceState clears query
- [x] schema level 0245, snapshot + db types
## ROUT Card tap — later batches
- [x] Card tap step-up: "ROUT Card" method in the step-up dialog (Web NFC on Android, /t fallback for iPhone and other devices), accepted for card_reveal, card_lifecycle and general sensitive actions
- [x] db/0253 card revoke + 0250 audit fix (EXPAND, live on Neon)
- [x] Blocking or replacing the ROUT card revokes the member's physical cards (db/0253)
- [x] Test on real hardware: Android Chrome NFC scan, iPhone tap via /t, desktop + signed-in phone (owner-tested)
- [x] /t asks "Ja, ik bevestig" before a tap completes an open card step-up (an unrelated tap can no longer approve a request from another session)
- [x] Re-test the /t confirm button on iPhone (changed after the owner's hardware test; owner-confirmed 2026-11-13)
- [x] Admin batch screen (/admin/cards): create, station config export, manifest import; member activation (db/0246, live on Neon)

## Developer console
- [x] Billing page: plan without billing account, live limits from the enforced rules, fair use + link to API terms (nl/en/fr/de)

## Auth
- [x] Passkey-only registration enforced server-side (user.create hook + bridge refuses members without a passkey)

## Workspace Studio
- [x] New profile photo does not save in Workspace Studio: Studio uploads as workspace-logo, /api/public/avatar reads via rout_public_avatar (db/0251 live on Neon, public read verified)
- [x] Workspace logos: prune keeps every photo still in use (db/0252 rout_prune_avatar_uploads, live on Neon)
- [x] Workspace conversion: workspaces.avatar_url set from the live design's photo (conversionWorkspaceLogo)
- [ ] Converted workspace logo stored in the Neon fallback still belongs to the retired login (cascade on a hard user delete); copy it into the workspace owner's uploads if hard deletes are ever enabled
- [x] "ROUT OS v2.5 Alle systemen operationeel" overlaps bottom preview buttons on phone; check similar overlaps

- [x] 0247 hardening (live on Neon, verified): constant-time activation-hash compare, SERIALIZABLE + retry for consume/activate, deny-all RLS on vault_enclave (review before apply)
- [x] Station file v2: correct NDEF offsets, encrypted UID+counter, ChangeFileSettings payload
- [x] Key delivery to the personalisation station: HPKE P-256 sealed bundle (0248 live)
- [x] Station registry (0248) + HPKE-wrapped batch key export on /admin/cards, logged via mark_sdm_batch_exported
- [x] db/0249 (drop station-less export marker) moved into db/ after production reported 0248
- [x] db/0250 card tap as step-up factor (EXPAND, live on Neon)

## Beveiligingsmelding agenda's
- [x] Agenda toevoegen/verversen: max 20 per lid per uur (gedeelde teller, faalt dicht), melding in nl/en/fr/de + test

## Admin portal and Studio routing
- [x] Admin portal refuses non-admins in the UI itself (adminAccessDecision + AdminForbidden screen, nl/en/fr/de); server checks unchanged
- [x] /studio/booking lands on the bookings page: /studio accepts page=booking (src/lib/studio-page-param.ts) and Studio opens bookings from that routed value
- [ ] Signed-in click-through of the admin refusal screen and the bookings page: owner verifies on the Vercel deploy (no DATABASE_URL requested for the preview)

## Migratie-synchronisatie (2026-11-13)
- [x] Stap 1a: alleen-lezen analyse van 95/0169/0209/91 (verslag aan eigenaar)
- [x] Stap 1b: archief in db-archive/, erkende vingerafdrukken in scripts/migration-history-allowlist.ts, controle scripts/migration-history-check.ts (Neon: 251 rijen, 0 afwijkingen)
- [x] 0254: rout_pairwise_register op search_path = pg_catalog (live op Neon, gecontroleerd)
- [x] Afdwinging SECURITY DEFINER search_path: krimpende overgangslijst, lint + bewaking in beide runners vanaf 0255, test op snapshot, live controle (scripts/security-definer-check.ts)
- [x] Batch 1 — kaarten, kluis, inloggen: 21 functies (db/0255, live op Neon, 0 afwijkingen)
- [x] Batch 2 — werkruimtes, ouders, agent-sandbox: 36 functies (db/0256, live op Neon, 0 afwijkingen; 79 over)
- [x] Batch 3 — boekingen: 31 functies (db/0257, live op Neon, 48 over)
- [x] pg_temp-beleid: pg_catalog, pg_temp voor elke SECURITY DEFINER-functie (besluit eigenaar)
- [x] Batch 4 — de laatste 48 functies + pg_temp op alle 348 (db/0258, live op Neon, 0 open)
- [x] Rechtencorrectie interne hulpfuncties (db/0259, live op Neon, per functie nagekeken)
- [x] Herbouw uit db/ gelijk aan Neon voor alle functierechten (db/0260, op Neon aantoonbaar zonder effect)
- [x] db/0261 — drie ongebruikte SECURITY DEFINER-functies weg bij rout_app + samenvoegen met de handle van het tweede account herstellen (live op Neon 2026-11-13, per functie nagekeken)
- [x] 17 tabellen/reeksen: onderzoek per tabel klaar (bijlage J); voorstel db-pending/0262 getest
- [x] 0262 — overbodige tabelrechten van rout_app ingetrokken (live op Neon 2026-11-13, nagekeken), bestand in db/, schemaniveau 0262, volledige suite groen
- [x] auth_recovery_requests: besluit eigenaar — aparte SECURITY DEFINER-ingangen, geen policies
- [x] db/0263 (EXPAND) — ingangsfuncties voor herstelaanvragen geschreven en getest (bijlage K)
- [x] db/0263 live op Neon (2026-11-13, checksum gelijk, per functie nagekeken)
- [x] quarantine.server.ts gebruikt alleen nog de rout_recovery_*-functies (test tegen db/ + 0264, bijlage L)
- [x] Deze code op Vercel gezet door de eigenaar (health-probe meldde 0263, 2026-11-13 18:05 UTC)
- [x] 0264 (CONTRACT) in db/ en live op Neon (2026-11-13): rout_app heeft geen tabelrechten meer op auth_recovery_requests, schemaniveau 0264
- [ ] Productie opnieuw deployen zodat de health-probe 0264 meldt — eigenaar (geen haast: 0264 verandert alleen databaserechten)
- [x] Briefing in appendix van docs/HANDOVER.md (bijlage B letterlijk, bijlage C controle)
- [x] QA-testdraaiboek: docs/ROUT-QA-draaiboek.md (kopie in Files)
- [x] /t-schermen en knoppen in nl/en/fr/de (cardTap.* in interface-bundels); zegel "Authentic ROUT Card" blijft bewust Engels
- [ ] QA-draaiboek uitvoeren op het Vercel-deploy — eigenaar, met fysieke kaarten en toestellen

## Boekingssysteem topniveau (plan 2026-11-13)
- [ ] Fase A: hoofdpagina/ontdek/about/info op alle formaten (bezig: hoofdstukken op mobiel opgelost)
  - [ ] 12 formaten + liggend, geen overflow/afsnijding/CLS, contrast richting AAA, tikdoelen 44px, animaties alleen transform/opacity
  - [ ] Per pagina titels/omschrijvingen NL/EN/FR/DE + eigen deelafbeelding
- [ ] Fase B: database (grootboek, agendakoppelingen, routering, locaties, annuleringsbeleid) — Neon pas na GO
  - [ ] B1: booking_events — onveranderlijk grootboek, hash-keten + server-ondertekening, overzicht ↔ grootboek-controle (db/0265, alleen test)
  - [ ] B2: agendakoppelingen Google/Microsoft/CalDAV — sleutels alleen als RVE1-envelop in vault_enclave (alleen test)
  - [ ] B3: publieke kant alleen anonieme tijdvakken/bitmasker (bevestigen + test)
  - [ ] B4: MCP-hulpmiddelen: vrije tijden lezen, reservering voorbereiden; bevestigen alleen na passkey/step-up van een mens
- [ ] Fase C: Google/Microsoft/CalDAV sync — wacht op OAuth-apps van eigenaar + host voor Omni-werker
- [ ] Fase D: gewogen beurtrol, routeringsvragen
- [ ] Fase E: vergaderruimtes, betalingen, annuleringsbeleid
- [ ] Fase F: boekings-, beheer- en hostpagina's, mails NL/EN/FR/DE
- [ ] Fase G: intake-versleuteling, ROUT ID, Wallet, MCP-hulpmiddelen

## Vervolg 2026-11-13 (goedgekeurd plan)
- [x] Stap 0: 0265 greatest/least hersteld, naar db-pending tot GO
- [x] Stap 0: volledige testsuite groen (2805/2805)
- [x] Fase A: 12 formaten + liggend — geen overloop; 9-delige reeks en omgevingsknop op gsm opgelost
- [x] Fase A: taal al juist vanaf de server (geen Engels→Nederlands-wissel meer), lege flits bij laden weg; verspringen (CLS) overal < 0,07
- [x] Fase A: alle knoppen en links op de gemeten openbare pagina's ≥ 44×44 px (AAA), grijze tekst ≥ 7:1 contrast
- [ ] Fase A: OG-afbeelding/omschrijving per pagina en per taal nalopen; overige openbare pagina's (qr-, guide-, compare-, support-) door dezelfde meting
- [ ] Fase B: zero-knowledge (client-side E2EE, blinde indexen, grootboek-invarianten) vanaf de eerste migratie
- [ ] Fase G: W3C Verifiable Credentials / selectief-onthullend bewijs voor gastverificatie
- [x] Fase B: herstel 2-van-4 (passkey, ROUT-kaart, server, papier) — cryptokern + werker + tests; kaartgeheim alleen in URL-fragment
- [x] Fase B: db-pending/0266 kaartdeel herstel — getest in testdatabase (wacht op GO)
- [ ] Fase B: herstel 2-van-4 aansluiten op scherm, opslag en herstel-login (na GO 0266)
- [ ] Fase B: kaarten (her)personaliseren met #rk1-fragment (fabrieksstation) — fysieke kaarten nodig
- [x] Fase B: versleutelde boekingsinhoud (bkh/bkg, ML-KEM-1024 + X25519, vaste emmers) — kern + tests
- [ ] Fase B: 0265 grootboek aanpassen: vingerafdruk over versleutelde tekst i.p.v. platte velden
- [ ] Fase B: migratie boekingsenveloppen + host-boekingssleutel (zaad onder werkruimtesleutel) + werker-ops
- [ ] Fase B: gastcontact (e-mail) als kluisverwijzing + blinde index voor limieten per gast
- [ ] Fase B+: vaste byte-lengtes (padding) en constante responstijden voor boekings- en bitmasker-API's
- [ ] Fase B+: Omni-werker als blinde doorgeefluik, nooit toegang tot persoonlijke sleutels
