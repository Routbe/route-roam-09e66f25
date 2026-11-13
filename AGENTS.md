<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.

## What Lovable manages

Rules outside this block are the project's own. Change the pieces below in
Lovable, not by hand. With the [Lovable MCP](https://mcp.lovable.dev)
connected, `send_message` asks Lovable to do it; otherwise ask the user to
use the editor.

- **Database.** Do not add or edit `supabase/migrations/` or `drizzle/`.
  Ask Lovable to change the schema.
- **Generated files.** Do not edit a file whose header says it is automatically
  generated.
- **AI gateway.** Keep model calls on Lovable's gateway, and keep
  `LOVABLE_API_KEY` out of browser code.
- **Connectors.** Lovable provides native connectors. `list_connectors` shows
  which are enabled; `add_connector` only returns the dashboard link. When a
  connector is enabled, calls go through the connector gateway and need
  `LOVABLE_API_KEY`. When Lovable does not provide one, users can bring their
  own key and store it in Secrets.
- **Secrets.** Lovable manages them. Do not put secret values in the repo.
<!-- LOVABLE:END -->

## Imported ROUT application
- Preserve the source TanStack routes, providers, assets, and MDX catalog so the original app remains compatible.
- Preserve managed project metadata when importing source; register generated backend integrations and their auth attachment only when this project has its own backend connected. Why: the app signs in through its own auth, and a missing backend connection breaks every page that calls the server.
- Keep imported compiler options and MDX compilation while retaining the managed deployment target so source code compiles in this environment.
- Never copy source credentials or apply external database scripts automatically; original accounts and services require explicit compatible configuration.
- Read docs/HANDOVER.md before touching security, vault, card, auth or migration code; its numbered sections stay verbatim and corrections go only in its appendix. Why: it is the owner's handover dossier with the binding invariants and open items.

## Browser cryptography
- Browser encryption, protocol verification and private-key operations use the existing typed crypto-enclave worker with ordered requests, transferred buffers and no UI fallback; shared crypto helpers may still run in server-only handlers. Why: preserves ciphertext compatibility without exposing derived keys to React.
- Zero-fill owned secret/plaintext byte views in finally, hold pending master keys non-extractably and retain vault configuration only as ciphertext; recovery strings/WebAuthn input and engine-internal copies are not erasable or XSS-isolated. Why: cleanup must be testable without claiming a hardware enclave.
- Worker dispatch announces execution start for per-operation deadlines; auth changes terminate volatile state and invalidate captured crypto/HTTP scopes, while owner-keyed UI sessions reject stale completions and preserve persisted device keys. Why: logout, queue delays and late replies must not revive keys or another owner's plaintext.

## Interface materials
- Keep workspace material preferences separate from colour mode; activate root data-theme only for authenticated tools and QR/Studio routes, including their portals, and exclude profile/QR/export artwork. Why: the public gateway retains the imported appearance and Creator restores legacy materials without altering user designs.

## Server-rendered language and hydration
- The root route negotiates the locale on the server (rout_lang cookie, then Accept-Language; src/lib/locale-negotiation.ts) and passes it to I18nProvider and <html lang>; on the server, direct i18n.t() calls translate in the request's locale (src/lib/i18n-request.server.ts, installed in src/server.ts). Why: a first frame in the wrong language swapped all text after hydration and forced server-rendered Suspense boundaries back to loading.
- Root-level boundaries never wrap a lazy public shell, and MDX doc pages are preloaded in the router's hydrate hook (src/components/mdx/doc-modules.ts). Why: a still-loading lazy module during hydration blanks the server HTML on any provider update.
- Public controls are at least 44x44 px (WCAG 2.5.5 AAA); compact chips draw their visible pill inside the larger button and short text links use the tap-wide utility. Why: touch targets grow without changing the look.

## Zero-knowledge booking payloads
- Booking titles, descriptions, notes and intake answers exist server-side only as RVE1 envelopes from src/lib/crypto-enclave/booking-seal.ts: kind bkh (host device key, seed sealed under the workspace key) and bkg (guest key from the manage-link fragment), padded to fixed buckets and bound to host, payload id and copy role; the ledger stores a commitment over the ciphertext. Why: neither the server nor Neon may ever hold plaintext or a key that opens it, and envelope sizes must not reveal text length.

## Discover pages
- Product landing pages live at /discover/<topic>; slugs, main buttons and detail links come from src/lib/discover/topics.ts and per-locale copy from copy.<locale>.ts, with accents in src/styles/discover.css. Why: one source keeps the home page, detail-page buttons and sitemap pointing at the same product pages instead of the sign-in wall.

## Admin portal and Studio page routing
- The admin portal layout decides access from adminAccessDecision before rendering any admin screen, treating a failed permission lookup as no access; server-side checks stay unchanged. Why: non-admins must never see an admin screen or fire admin requests.
- /studio accepts only the search value page=booking (src/lib/studio-page-param.ts) and Studio opens its bookings panel from that routed value, not from window.location. Why: /studio/booking must reliably land on the bookings page and unknown values must not leak into the address.

## Vault enclave
- Raw identifiers live only as sealed 'RVE1' envelopes in the vault_enclave schema (db/0221); rout_app has no table rights and reaches it only through register_step_up_proof, store_opaque_token and retrieve_opaque_token, with the caller taken from the transaction context. Why: a compromised app role can neither read ciphertext in bulk nor act for another member.
- Outside the vault, data travels only as opaque refs validated by src/lib/vault/token-boundary.ts; refs are minted by the database, never by callers. Why: one strict boundary keeps raw values out of the browser, logs and APIs.
- Vault retrieval needs p_step_up_verified plus a passkey proof registered on the database clock, used once within 300 s; denials return granted=false instead of raising so their audit row commits. Why: a bare boolean is forgeable, and failed attempts must stay on the hash-chained audit log.
- vault_enclave is in the schema snapshot but gets no generated row types. Why: drift stays detectable while app code has no typed path to the tables.
- Vault access goes through IVaultPort (src/lib/vault/vault-port.server.ts); swap adapters only in vaultPort(). The port moves sealed envelopes and never decrypts. Why: the Postgres adapter must be replaceable 1:1 by a remote enclave client.
- RVE1 envelopes (crypto-enclave/pqc-envelope.ts) fix the allowed key holder per token kind and bind each envelope to a context string naming owner and purpose. Why: a ciphertext moved to another member, field or holder must not open.
- A passkey step-up registers its proof id in the vault at grant time; vault reads use the passkey-only, single-use action vault_token_read. Why: freshness is measured on the database clock from the moment the passkey was verified.
- The Master KEK (ROUT_VAULT_KEK, read per call in server-vault.server.ts) only wraps the server vault's RVE1 seed with AES-256-GCM; wrapped seeds live in vault_enclave.server_keys (db/0222) and a wrap that does not authenticate under the KEK is never used. Why: neither the database nor the environment alone can open vtk_/sdm_.
- vcc_ envelopes are sealed and opened only by the crypto worker's rve1.* ops with a device key whose seed is sealed under the device key; the UI gets plaintext only through enclave.rve1.withCredential, which wipes it after the callback. Why: private keys never reach the main thread and plaintext is short-lived.
- Archived migrations live in db-archive/, never in db/. Why: every file in db/ is replayed by the runner and the snapshot check.

## Legacy runtime access
- The free `rout_server` policies from db/0154 are removed table by table, only after every runtime read/write is moved into the owner's context or a narrow SECURITY DEFINER function; account purge deletes rely on `public.rout_purge_due(user_id)`. Why: dropping them all at once stops sign-in, payments and admin, and the purge runs without a member context.

## Neon database access
- The app runtime connects only through the DATABASE_URL secret (rout_app login); the owner-level Neon connection stays unlinked from the project and is used solely by the agent for reviewed schema work. Why: a linked NEON_API_KEY makes the gateway transport win over DATABASE_URL, so preview would diverge from the Vercel runtime.

## Migration history
- Every row in public.schema_migrations must match a file in db/ or an entry in scripts/migration-history-allowlist.ts carrying Neon's exact checksum; check with scripts/migration-history-check.ts and never rewrite Neon's rows. Why: history drift stays visible without falsifying what actually ran.

## SECURITY DEFINER search_path
- Every SECURITY DEFINER function runs with search_path = pg_catalog, pg_temp (from db/0258; 0255-0257 may still set the bare form during replay); the legacy list in scripts/security-definer-legacy.ts is empty and stays empty, both runners lint every migration from 0255 on by the rule in force at its number and run the guard in scripts/security-definer-policy.ts inside its transaction; `bun scripts/security-definer-check.ts` checks Neon. Why: nothing a caller can place on the path, including its temporary schema, may resolve inside owner-privileged code.

## Function execute rights
- A SECURITY DEFINER helper that only other definers or triggers call gets `revoke all ... from public, rout_app` in the migration that creates it; rout_app keeps EXECUTE only on functions app code or SECURITY INVOKER code calls. Why: Neon's default privileges grant rout_app EXECUTE on every new function, so revoking only PUBLIC leaves internal helpers callable by the app role.
- A replay of db/ must end with the same function EXECUTE rights as Neon (db/0260 recorded them; definer-execute-grants.test.ts guards it); every migration states function grants explicitly instead of relying on default privileges. Why: Neon's default privileges and a fresh replay diverge, and a rebuilt database was both looser for PUBLIC and broken for rout_app.

## Staged database lockdowns
- CONTRACT migrations that remove legacy access wait in db-pending/ until production runs the code using the matching EXPAND functions, then move into db/. Why: every file in db/ is replayed by the runners, so a premature contract would break the live deployment.
- The public health probe reports CODE_SCHEMA_LEVEL (src/lib/schema-version.ts, kept equal to the highest db/ migration by a test); a held-back contract is applied only once production reports at least the level of its EXPAND migration. Why: it is the only outside proof of which code a deployment runs.
- Before a contract closes a table, the EXPAND step turns every SECURITY INVOKER function or trigger that touches it into SECURITY DEFINER. Why: triggers run with the caller's rights, so a closed table would silently break app writes on other tables.

## Account creation
- A Better Auth user row is created only inside runPasskeyAccountCreation (passkey-enrollment.server.ts); the user.create.before hook refuses every other path and the bridge creates no public.users row for an identity without a passkey. Why: registration must be passkey-only regardless of which provider or plugin is enabled.

## Account recovery requests
- public.auth_recovery_requests is reached only through the rout_recovery_* SECURITY DEFINER functions (db/0263): filing answers the same for every input, deciding requires a full admin with two-factor on taken from rout.current_user_id, and binding tokens reach the database only as SHA-256. Why: no account enumeration, no trust in caller-supplied admin ids, and no raw token at rest.

## Uploaded photos
- Neon-fallback photo uploads are pruned only through public.rout_prune_avatar_uploads (db/0252), which keeps every photo a profile, draft, workspace or app logo still references; without it nothing is pruned. Why: a member's uploads serve several workspaces, so a per-member count deleted logos still in use.
