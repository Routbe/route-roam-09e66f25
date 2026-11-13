# Plan: finish group 3 and harden group 4 (the last 48 database functions)

## What I checked against the handover
- Code and Neon are both at schema level 0257. 48 protected functions still lack the strict setting. 300 already have it.
- `.tmp-b3/` still exists. HANDOVER.md has no Appendix F yet. Roadmap still lists batch 3 as open.
- On Neon, the app role and PUBLIC cannot create temporary tables, and the app role cannot create objects in `public`. The handover is right about this.
- The handover's list for group 4 differs from the real list in `scripts/security-definer-legacy.ts`:
  - `rout_sunset_user_now`, `rout_purge_due` and "OIDC helpers" are not on it.
  - Not mentioned in the handover: the Q&A (10), subscriber (5) and wallet functions.
  - The file is leading.
- `src/test` has 121 files, not 466 or more. The handover probably counts all test files in the whole project.

## Step 1 — Close out group 3 (no database changes)
- Delete `.tmp-b3/`.
- Add Appendix F to HANDOVER.md: migration 0257, 31 functions, live result 79 to 48. Leave the existing sections untouched.
- Tick off batch 3 in roadmap.md.
- Run the security and migration tests, then the full test suite (`bun run test`). Report the results.

## Step 2 — Decide the pg_temp policy (report first, then decide)
- Facts: with `search_path = pg_catalog`, Postgres searches `pg_temp` first. Nobody on Neon can create temporary objects at the moment.
- My recommendation: switch to `pg_catalog, pg_temp`. That holds even if TEMP rights are ever granted by mistake. Apply it via one extra correction migration for every function already on `pg_catalog` (0254 to 0257), plus the new batch.
- Alternative: keep things as they are and add a test and check that TEMP stays revoked from `rout_app` and PUBLIC.
- You choose before step 3 starts.

## Step 3 — Group 4 (migration 0258)
1. Scan the 48 function bodies (live on Neon and in the snapshot) for unqualified tables, functions and types, such as `gen_random_bytes`, `now()` and own types.
2. Compare the live definitions with the code. Stop at any difference.
3. Write `db/0258_definer_search_path_rest.sql` using only `ALTER FUNCTION ... SET search_path`. Bodies, owners and rights stay the same. Where a body has unqualified names, I name the fix separately; that needs a full `CREATE OR REPLACE`.
4. Update `scripts/security-definer-legacy.ts`: add a `HARDENED_BY_MIGRATION` entry for 0258, so the legacy list becomes `[]`.
5. Extend the tests: run every function once on its normal path after a full replay.
6. Set `CODE_SCHEMA_LEVEL` to 0258 and refresh the snapshot.
7. **Live on Neon:** only after your explicit approval of the exact SQL. Run it in one transaction, with a count check before (48) and after (0), plus the log entry.
8. Run `security-definer-check` (0 open) and `migration-history-check` (0 differences).
9. Add Appendix G to HANDOVER.md and update roadmap.md.

## Technical notes
- Run order follows the existing runners. Nothing goes into `db-pending/` (this is not a CONTRACT step).
- The Neon connection stays unlinked from the app (only for my reviewed work).
- No changes to RLS, roles or app code outside the files named above.
