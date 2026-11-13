# Continue from the handover: three tasks, checked against the real code

The handover is mostly accurate, but some details don't match the code. The plan follows the code, not the handover.

## What differs from the handover
- **Database function names:** `verify_card_tap`, `create_sdm_batch` and `import_batch_manifest` don't exist. The real 0245 functions are `register_sdm_fleet_key`, `register_sdm_batch`, `register_sdm_batch_cards`, `begin_sdm_tap`, `confirm_sdm_tap` and `consume_sdm_tap`.
- **Card status:** cards have no `status = 'unassigned'` column. A card counts as unclaimed when it has no `owner_user_id` and no `activated_at`. There is already an `activation_hash` column and a `last_counter` column.
- **Bottom status bar:** no fixed "ROUT OS v2.5" bar exists. The status text sits in the footer. The floating bottom element is the "OMGEVING / Publiek / Admin" switch. The overlap still needs to be reproduced first.
- **Card admin screen:** no admin screen for card batches exists yet. The batch functions are only wired up on the server side.

## Task 1 — Fix the bottom overlap on phones
1. Open Studio at 390 px wide and take screenshots to find which floating elements overlap (environment switch, back-to-top button, tour, Studio action bar).
2. Fix only what is shown to overlap: hide the environment switch on Studio routes on phones, or raise it with bottom padding plus the iPhone safe area.
3. Check again on phone and desktop.

## Task 2 — Add the card rule to `src/lib/wallet/AGENTS.md`
One rule: card taps arrive on `/t`, the link is cleared from the address bar before checking, the link contains no card or user ID, and checking happens inside the vault using per-card keys. The handover's wording is used, with the real function names.

## Task 3 — Card batches and card activation
**Part A — Admin: batches** (new page `/admin/cards`, admins only)
- Create a batch (name, number of cards) using the existing `register_sdm_fleet_key` and `register_sdm_batch`.
- Export the setup file for the card writing station: SDM file settings and where the codes go on the card. No keys in plain text in the browser.
- Import the station's list of written cards. The server turns each chip ID into a hash and stores them with `register_sdm_batch_cards`.

**Part B — Members: activate a card with the first tap**
- A new, additive database update `0246_card_activation.sql` adds `vault_enclave.activate_member_card`. It checks the tap the same way `begin_sdm_tap`/`confirm_sdm_tap` do, accepts only unclaimed cards, saves the first counter, links the card to the signed-in member, sets `activated_at` and writes the vault audit log. It fails closed: on an error it writes an audit row and refuses.
- A wizard "Activeer je ROUT Card" in settings, with the instruction "Houd je nieuwe ROUT Card tegen de achterkant van je telefoon". While it is open, the next tap on `/t` activates the card instead of only verifying it.

## Order and checks
- Tasks run in order 1, 2, 3. I will show you the 0246 database update for review first and will not run it automatically; you or I apply it to Neon afterwards.
- Add tests for: only an unclaimed card can be activated, a reused tap is refused, lockout after 5 failed taps in 10 minutes, and the tap code is removed from the address bar.
- Run the existing tests.

## Technical details
- Bump `CODE_SCHEMA_LEVEL` to 0246 only once the update exists in `db/`, and update `db/schema.snapshot.json`.
- Grants: `rout_app` gets only execute on the new function, the same pattern as 0245.
- Station file: JSON with the NTAG 424 DNA SDM settings (offsets for PICCData and CMAC, key numbers for SDMMetaRead and SDMMAC). Key material stays sealed in the vault.
