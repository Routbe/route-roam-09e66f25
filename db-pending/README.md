# Held-back migrations

CONTRACT steps that remove legacy access. They stay out of `db/` (every file
there is replayed by the runners) until the deployed app uses the matching
EXPAND functions. Move a file into `db/` only when production runs that code
(the public health probe reports `schema` at or above the EXPAND number).


Applied and moved into `db/`: 0230, 0231, 0233, 0235, 0237 (production reported 0236).
- 0239 and 0241 applied (Nov 2026); no legacy rout_server access remains.
- 0262 applied on Neon (2026-11-13) and moved into `db/`.
- 0263 and 0264 applied on Neon (2026-11-13, production reported 0263); 0264 moved into `db/`. Nothing is held back.

- 0265_booking_ledger.sql: held back (EXPAND, not yet applied on Neon); greatest/least unqualified. Moves to db/ with CODE_SCHEMA_LEVEL 0265 after the owner's GO.
- 0266_recovery_card_factor.sql: held back (EXPAND, not applied on Neon): ROUT Card as fourth recovery shard (2-of-4). Test: src/test/recovery-card-factor-0266.test.ts. Moves to db/ only after the owner's GO.
