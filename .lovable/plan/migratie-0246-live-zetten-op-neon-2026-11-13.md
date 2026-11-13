# Migratie 0246 live zetten op Neon

## Stappen
1. Controleren dat 0245 de laatste toegepaste migratie is en 0246 nog niet bestaat op Neon.
2. `db/0246_card_activation.sql` als één transactie uitvoeren via de beheerdersverbinding (alles of niets), en 0246 registreren in `schema_migrations` zoals de migratie-runner dat doet (inclusief checksum).
3. Rechten controleren:
   - `rout_app` heeft EXECUTE op `activate_member_card`, `list_sdm_batches`, `mark_sdm_batch_exported`.
   - `public` heeft daar geen rechten op.
   - `rout_app` heeft nog steeds nul tabelrechten in `vault_enclave`.
   - De drie functies zijn SECURITY DEFINER met `search_path = pg_catalog`.
   - Nieuwe kolom `initial_counter` en de verruimde constraints bestaan.
4. Rookproef als `rout_app` (via de app): `/api/public/health` meldt schema `0246`; `/admin/cards` laadt de batchlijst zonder fout.
5. Verslag aan jou met de resultaten, waarna je de NFC-activatie kunt testen.

## Bij fout
Bij een fout rolt de transactie volledig terug; er verandert dan niets op de live database en ik rapporteer de melding.
