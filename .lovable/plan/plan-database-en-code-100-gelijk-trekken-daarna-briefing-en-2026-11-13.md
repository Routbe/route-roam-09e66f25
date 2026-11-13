# Plan: database en code 100% gelijk trekken, daarna briefing en testdraaiboek

Volgorde zoals gevraagd: eerst de open migratiepunten, dan de briefing vastleggen, en pas daarna het testdraaiboek.

## 1. Migraties gelijk trekken (prioriteit)

Bekende afwijkingen tussen Neon (`public.schema_migrations`) en `db/`:
- Wel toegepast in Neon, geen bestand in de code: `95_question_stories.sql`, `0169_workspace_icon.sql`.
- Toegepast met een checksum die afwijkt van het huidige bestand: `0209_recovery_vault_pairwise.sql`, `91_shadowban.sql`.

Hoe deze afwijkingen zijn ontstaan, is nog niet bevestigd. Stap 1 is dat uitzoeken.

Stap 1a, alleen lezen (geen wijzigingen in Neon):
- Uitzoeken wat `95_question_stories` en `0169_workspace_icon` in het schema hebben achtergelaten (tabellen, kolommen, functies, policies), en of dat nu nog bestaat of al door een latere migratie is vervangen.
- In de git-geschiedenis en `db-archive/` zoeken naar de oorspronkelijke inhoud: hernoemd, gesplitst of verwijderd. Op dezelfde nummers staan nu `95_youtube_vault.sql` en `0169_workspace_social_links.sql`. Nagaan of die apart in Neon zijn toegepast.
- Voor 0209 en 91 vergelijken wat het huidige bestand zou aanmaken met wat er echt in Neon staat. Daarmee weten we of het verschil alleen in de tekst zit (commentaar of opmaak) of ook in het effect.
- Een kort verslag per bestand: oorzaak, effect en voorgestelde oplossing. Daarna wacht ik op jouw akkoord voordat ik verder ga.

Stap 1b, oplossen volgens de projectregels:
- Ontbrekende bestanden: de oorspronkelijke inhoud terugzetten als die nog terug te vinden is. Anders een bestand dat beschrijft wat er in Neon werd toegepast, en alleen als dat ook echt zo is. Gaat het om historische migraties die al vervangen zijn, dan komen ze in `db-archive/`. In beide gevallen klopt de geschiedenis dan weer met de code.
- Checksum-afwijkingen: alleen tekstverschil betekent het toegepaste origineel terugzetten (de checksum moet dan exact kloppen). Verschilt het effect wel, dan schrijf ik een nieuwe, gereviewde migratie (EXPAND/CONTRACT, RLS blijft aan, SECURITY DEFINER alleen met `SET search_path = pg_catalog`) die het schema in lijn brengt. Een checksum in Neon overschrijf ik nooit zomaar.
- `CODE_SCHEMA_LEVEL` loopt mee als er een nieuwe migratie bijkomt, en de bijbehorende test wordt bijgewerkt.
- Een test of controlescript dat de drift bewaakt: elke rij in `schema_migrations` moet een bestand in `db/` of `db-archive/` hebben met een gelijke checksum. Ik draai het tegen Neon en het moet nul afwijkingen geven.

## 2. Briefing vastleggen

- Je nieuwe briefing komt in het appendix van `docs/HANDOVER.md`. De genummerde secties blijven letterlijk staan.
- Met correcties waar de briefing van de code afwijkt. Eén voorbeeld: "geen OAuth voor registratie" klopt, maar OAuth staat in de planning als toekomstige inlogoptie. De claim over 2-van-3-herstel controleer ik eerst in de code.
- De roadmap krijgt een update: testsessie, externe diensten (geparkeerd) en monitoring.

## 3. Testdraaiboek voor je fysieke QA-sessie

Een document in Files (`ROUT-QA-draaiboek.md`), te volgen op je Vercel-deploy:
- Android: tik met de NTAG 424 DNA-kaart, step-up voor een gevoelige actie, en een herhaalde tik (moet geweigerd worden).
- iPhone: de `/t`-route met "Ja, ik bevestig" en "Nee, dit was ik niet". Daarna controleren dat de URL is opgeschoond.
- Kaart blokkeren of vervangen, waarna een tik geweigerd moet worden.
- Registratie met passkey, uitloggen en weer inloggen. Een poging zonder passkey moet geweigerd worden.
- Beheeromgeving als gewone gebruiker ("Geen toegang") en als beheerder. Ook `/studio/booking`.
- Per stap: het verwachte resultaat en een vakje voor geslaagd of mislukt.

## Technische details
- Neon lees ik via de chatverbinding (niet gekoppeld aan het project). Schrijven naar Neon gebeurt alleen na jouw akkoord op het verslag uit stap 1a.
- Er komt nergens een token of geheim in een bestand of logboek terecht.
