// @vitest-environment node
/**
 * db/0250 + db/0253 over the real SQL (PGlite, as rout_app): a tap of the
 * member's own ROUT Card completes their open step-up intent, which is claimed
 * exactly once; another member's card, a replay or a revoked card never does.
 * Plus the pure rules for the "card" step-up method and the tap URL parser.
 */
import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { cbc, cmac } from "@noble/ciphers/aes.js";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cardDivInput, diversifyAes128 } from "@/lib/crypto-enclave/sdm-verifier";
import { deriveVaultKek } from "@/lib/vault/server-kek";
import { activateMemberCard, completeCardStepUpTap, createSdmBatch, createSdmFleetKey, importSdmManifest, revokeMemberCards } from "@/lib/vault/sdm-tap.server";
import { LocalPostgresVaultAdapter, type VaultSqlExecutor } from "@/lib/vault/vault-port.server";
import { allowedStepUpMethods, methodAcceptedFor, parseStepUpPayload, proofCoversAction, stepUpPayload } from "@/lib/auth/step-up-rules";
import { cardTapRoute, parseCardTapUrl, tapFromNdefRecords } from "@/lib/wallet/card-tap-url";

const ADMIN = "00000000-0000-4000-8000-0000000000ad";
const ALICE = "00000000-0000-4000-8000-0000000000a1";
const BOB = "00000000-0000-4000-8000-0000000000b1";
const KEK = "K".repeat(32) + "7x".repeat(32);
let db: PGlite;

const asApp: VaultSqlExecutor = async (userId, query, params) => {
  await db.query("select set_config('rout.current_user_id', $1, false)", [userId]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Record<string, unknown>>(query, [...params])).rows;
  } finally {
    await db.exec("reset role");
  }
};
const port = new LocalPostgresVaultAdapter(asApp);
const deps = { port, kek: deriveVaultKek(KEK) };
const hex = (b: ArrayLike<number>) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
const bytes = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));
const META = new Uint8Array(16).fill(0x41);
const UID_INDEX = new Uint8Array(32).fill(0x42);
const MASTER = new Uint8Array(16).fill(0x43);
const queue = (...parts: Uint8Array[]) => (n: number) => {
  const next = parts.shift();
  if (!next || next.length !== n) throw new Error("unexpected random request");
  return next.slice();
};
const ALICE_CARD = "04C1B2C3D4E5F6";
const BOB_CARD = "04C1B2C3D4E5F7";
let batchId = "";
let counter = 1;

function tap(uidHex: string, n = counter++) {
  const uid = bytes(uidHex);
  const plain = new Uint8Array(16);
  plain[0] = 0xc7;
  plain.set(uid, 1);
  plain.set([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff], 8);
  const p = cbc(META, new Uint8Array(16), { disablePadding: true }).encrypt(plain);
  const fileKey = diversifyAes128(MASTER, cardDivInput(uid, bytes(batchId.replace(/-/g, ""))));
  const sv2 = Uint8Array.from([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80, ...uid, ...plain.slice(8, 11)]);
  const full = cmac(new Uint8Array(0), cmac(sv2, fileKey));
  return { p: hex(p), m: hex(Array.from({ length: 8 }, (_, i) => full[2 * i + 1] ?? 0)) };
}
const lastAudit = async (action: string) =>
  (await db.query<{ outcome: string; reason: string }>("select outcome, reason from vault_enclave.audit_logs where action = $1 order by seq desc limit 1", [action])).rows[0];

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto } });
  await db.exec(`create extension pgcrypto; create role rout_app; create table public.users (id uuid primary key);
    insert into public.users values ('${ADMIN}'), ('${ALICE}'), ('${BOB}');
    create function public.rout_is_admin_member(p_user uuid) returns boolean language sql stable as $$ select p_user = '${ADMIN}'::uuid $$;`);
  for (const f of ["0221_vault_enclave_isolation.sql", "0222_vault_server_keys.sql", "0224_sdm_recovery_gate.sql", "0245_sdm_tap.sql", "0246_card_activation.sql", "0247_vault_hardening.sql", "0248_sdm_stations.sql", "0250_card_step_up.sql", "0253_card_revoke.sql"]) {
    await db.exec(readFileSync(new URL(`../../db/${f}`, import.meta.url), "utf8"));
  }
  const fleetId = await createSdmFleetKey(ADMIN, { ...deps, random: queue(META, UID_INDEX) });
  batchId = await createSdmBatch(ADMIN, fleetId, "Step-up batch", { ...deps, random: queue(MASTER) });
  await importSdmManifest(ADMIN, fleetId, batchId, [{ uid: ALICE_CARD }, { uid: BOB_CARD }], deps);
  await activateMemberCard(ALICE, tap(ALICE_CARD), null, deps);
  await activateMemberCard(BOB, tap(BOB_CARD), null, deps);
}, 60_000);
afterAll(async () => db?.close());

describe("ROUT Card tap as step-up (db/0250)", () => {
  it("completes the member's own intent with their card, and the intent is claimed exactly once with its stored scope", async () => {
    expect(await port.memberCardFactor({ userId: ALICE })).toBe(true);
    const intent = await port.beginCardStepUp({ userId: ALICE }, "card_lifecycle");
    expect(intent).toMatch(/^csu_[0-9a-f]{64}$/);
    expect(await port.claimCardStepUp({ userId: ALICE }, intent!)).toBeNull(); // not tapped yet
    expect(await port.pendingCardStepUp({ userId: ALICE })).toBe(true);
    expect(await completeCardStepUpTap(ALICE, tap(ALICE_CARD), deps)).toBe(true);
    expect(await port.claimCardStepUp({ userId: BOB }, intent!)).toBeNull();
    expect(await port.claimCardStepUp({ userId: ALICE }, intent!)).toBe("card_lifecycle");
    expect(await port.claimCardStepUp({ userId: ALICE }, intent!)).toBeNull();
    expect((await lastAudit("card_step_up_claim"))?.reason).toBe("intent_spent");
  });

  it("refuses another member's card, a replayed tap and a tap without an open intent", async () => {
    expect(await completeCardStepUpTap(ALICE, tap(ALICE_CARD), deps)).toBe(false); // no open intent
    const intent = await port.beginCardStepUp({ userId: ALICE }, "card_reveal");
    expect(await completeCardStepUpTap(ALICE, tap(BOB_CARD), deps)).toBe(false);
    expect((await lastAudit("card_step_up_complete"))?.reason).toBe("tap_refused");
    const t = tap(ALICE_CARD);
    expect(await completeCardStepUpTap(ALICE, t, deps)).toBe(true);
    const second = await port.beginCardStepUp({ userId: ALICE }, "card_reveal");
    expect(await completeCardStepUpTap(ALICE, t, deps)).toBe(false); // same tap bytes again
    expect(await port.claimCardStepUp({ userId: ALICE }, intent!)).toBe("card_reveal");
    expect(await port.claimCardStepUp({ userId: ALICE }, second!)).toBeNull();
  });

  it("expires an intent after 300 s", async () => {
    const intent = await port.beginCardStepUp({ userId: BOB }, "*");
    await db.exec("update vault_enclave.card_step_up_intents set expires_at = clock_timestamp() - interval '1 second' where completed_at is null");
    expect(await completeCardStepUpTap(BOB, tap(BOB_CARD), deps)).toBe(false);
    expect(await port.claimCardStepUp({ userId: BOB }, intent!)).toBeNull();
  });
});

describe("revoking a lost card (db/0253)", () => {
  it("revokes only the caller's own cards, ends their open intent, and the card stops confirming", async () => {
    const intent = await port.beginCardStepUp({ userId: ALICE }, "card_lifecycle");
    expect(await revokeMemberCards(ALICE, deps)).toBe(1);
    expect(await port.memberCardFactor({ userId: ALICE })).toBe(false);
    expect(await port.memberCardFactor({ userId: BOB })).toBe(true);
    expect(await port.pendingCardStepUp({ userId: ALICE })).toBe(false);
    expect(await completeCardStepUpTap(ALICE, tap(ALICE_CARD), deps)).toBe(false);
    expect(await port.claimCardStepUp({ userId: ALICE }, intent!)).toBeNull();
    expect(await port.beginCardStepUp({ userId: ALICE }, "card_lifecycle")).toBeNull();
    expect(await revokeMemberCards(ALICE, deps)).toBe(0);
    expect(await lastAudit("sdm_card_revoke")).toEqual({ outcome: "granted", reason: "cards:0" });
  });

  it("does nothing without a signed-in caller and gives rout_app no direct table rights", async () => {
    expect(await port.revokeMemberCards({ userId: "" } as never).catch(() => 0)).toBe(0);
    await expect(asApp(BOB, "update vault_enclave.sdm_batch_cards set revoked_at = now()", [])).rejects.toThrow();
    expect(await port.memberCardFactor({ userId: BOB })).toBe(true);
  });
});

describe("card step-up rules", () => {
  const withCard = { passkey: true, totp: false, card: true };
  it("offers the card for card actions and general sensitive actions, never for a vault read or a card scan", () => {
    expect(allowedStepUpMethods(withCard, "card_reveal")).toEqual(["passkey", "card"]);
    expect(allowedStepUpMethods(withCard, "card_lifecycle")).toContain("card");
    expect(allowedStepUpMethods(withCard, "account_delete")).toEqual(["passkey", "card"]);
    expect(allowedStepUpMethods(withCard, "vault_token_read")).toEqual(["passkey"]);
    expect(allowedStepUpMethods(withCard, "card_scan")).not.toContain("card");
    expect(allowedStepUpMethods({ passkey: true, totp: false }, "card_reveal")).not.toContain("card");
    expect(methodAcceptedFor("vault_token_read", "card")).toBe(false);
    expect(methodAcceptedFor("card_scan", "card")).toBe(false);
  });

  it("binds a card proof to its action: a card proof for one action never covers another", () => {
    const now = 1_800_000_000;
    const proof = parseStepUpPayload(stepUpPayload(ALICE, "card", now, "card_reveal", "A".repeat(22)), ALICE, now)!;
    expect(proof.method).toBe("card");
    expect(proofCoversAction(proof, "card_reveal")).toBe(true);
    expect(proofCoversAction(proof, "card_lifecycle")).toBe(false);
    const general = parseStepUpPayload(stepUpPayload(ALICE, "card", now, "*", "B".repeat(22)), ALICE, now)!;
    expect(proofCoversAction(general, "account_delete")).toBe(true);
    expect(proofCoversAction(general, "card_lifecycle")).toBe(false);
  });

  it("reads the tap bytes from the card's URL record only", () => {
    const p = "A".repeat(32);
    const m = "b".repeat(16);
    expect(parseCardTapUrl(`https://rout.be/t?p=${p}&m=${m}`)).toEqual({ p, m });
    expect(parseCardTapUrl(`rout.be/t?p=${p}&m=${m}`)).toEqual({ p, m });
    expect(parseCardTapUrl(`https://rout.be/x?p=${p}&m=${m}`)).toBeNull();
    expect(parseCardTapUrl(`https://rout.be/t?p=${p.slice(1)}&m=${m}`)).toBeNull();
    const url = new TextEncoder().encode(`https://rout.be/t?p=${p}&m=${m}`);
    expect(tapFromNdefRecords([{ recordType: "text", data: new DataView(url.buffer) }])).toBeNull();
    expect(tapFromNdefRecords([{ recordType: "url", data: new DataView(url.buffer) }])).toEqual({ p, m });
  });

  it("a tap on /t confirms a step-up only after the member chose to, and never signed out", () => {
    expect(cardTapRoute("proof", true)).toBe("proof");
    expect(cardTapRoute("proof", false)).toBe("proof");
    expect(cardTapRoute("step_up", true)).toBe("step_up");
    expect(cardTapRoute("step_up", false)).toBe("refuse");
  });
});
