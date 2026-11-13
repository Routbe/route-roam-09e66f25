/**
 * Vault port (hexagonal architecture). Application code depends only on
 * IVaultPort; LocalPostgresVaultAdapter is today's implementation and talks
 * exclusively to the SECURITY DEFINER functions of db/0221. A remote enclave
 * adapter (mTLS gRPC to a Rust AMD SEV-SNP service) can implement the same
 * interface 1:1: every method is a single request with plain bytes and
 * strings, the caller is explicit, and no method exposes SQL, rows or sessions.
 *
 * The port moves sealed envelopes only. It never sees plaintext and never
 * decrypts: opening an envelope is the key holder's job (pqc-envelope.ts).
 * Every denial is the same VaultDeniedError; the reason stays in the enclave's
 * audit log.
 */
import { z } from "zod";
import { cleanContextId } from "@/lib/db-context";
import { ENVELOPE_MAX_BYTES } from "@/lib/crypto-enclave/pqc-envelope";
import { isTapGrant, OPAQUE_TOKEN_KINDS, opaqueTokenKind, parseOpaqueToken, type OpaqueToken, type OpaqueTokenKind, type TapGrant } from "./token-boundary";

/** An authenticated member (public user id from the server session, never from input). */
export type VaultCaller = { readonly userId: string };
/** A passkey step-up the server verified; proofId as registered in the enclave. */
export type PasskeyStepUp = { readonly verified: true; readonly proofId: string };
export type VaultEnvelope<K extends OpaqueTokenKind> = { readonly kind: K; readonly envelope: Uint8Array };
/** A server vault recipient key as stored: public parts plus the KEK-wrapped seed (db/0222). */
export type WrappedServerKey = { readonly kid: Uint8Array; readonly publicKey: Uint8Array; readonly wrappedSeed: Uint8Array; readonly kekId: Uint8Array };
/** Raw NTAG 424 DNA SUN tap bytes: encrypted PICCData (16) and truncated CMAC (8). */
export type SdmTapBytes = { readonly piccData: Uint8Array; readonly cmac: Uint8Array };
/** An open recovery attempt (db/0224): counted as a failure until confirmed. */
export type SdmRecoveryChallenge = {
  readonly attemptId: string;
  readonly ownerUserId: string;
  readonly sdmRef: OpaqueToken<"sdm">;
  readonly envelope: Uint8Array;
  readonly lastCounter: number | null;
};

/** A sealed fleet key (K_SDMMetaRead + UID-index key), db/0245. */
export type SdmFleetKey = { readonly fleetId: string; readonly ownerUserId: string; readonly envelope: Uint8Array };
/** An open tap attempt (db/0245): counted as a failure until confirmed. */
export type SdmTapChallenge = {
  readonly attemptId: string;
  readonly batchId: string;
  readonly batchOwner: string;
  readonly envelope: Uint8Array;
  readonly lastCounter: number | null;
};
/** recovery_factor (db-pending/0267): own, unrevoked card for the 2-of-4 recovery vault; spends the grant, completes nothing. */
export type SdmTapPurpose = "public_proof" | "step_up" | "recovery_factor";
export type SdmCardState = "active" | "unactivated";
/** What a card step-up proof will cover: one card action, or general sensitive actions. */
export type CardStepUpScope = "*" | "card_reveal" | "card_lifecycle";
export const CARD_STEP_UP_SCOPES: readonly CardStepUpScope[] = ["*", "card_reveal", "card_lifecycle"];
/** Single-use intent ref minted by the database; the browser only ever holds it in an HttpOnly cookie. */
export type CardStepUpIntent = string & { readonly __cardStepUpIntent: true };
export const isCardStepUpIntent = (v: unknown): v is CardStepUpIntent => typeof v === "string" && /^csu_[0-9a-f]{64}$/.test(v);
export type SdmBatchSummary = {
  readonly batchId: string;
  readonly fleetId: string;
  readonly label: string;
  readonly createdAt: string;
  readonly exportedAt: string | null;
  readonly retiredAt: string | null;
  readonly cards: number;
  readonly activeCards: number;
};

export type SdmStation = {
  readonly stationId: string;
  readonly label: string;
  readonly fingerprint: Uint8Array;
  readonly createdAt: string;
  readonly retiredAt: string | null;
};

/** What the vault hands out for one logged export: the station key and still-sealed envelopes. */
export type SdmBatchExport = {
  readonly stationPublicKey: Uint8Array;
  readonly batchOwner: string;
  readonly batchEnvelope: Uint8Array;
  readonly fleetOwner: string;
  readonly fleetEnvelope: Uint8Array;
};

export interface IVaultPort {
  /** Records a just-verified passkey step-up on the enclave's own clock. */
  registerPasskeyStepUp(caller: VaultCaller, proofId: string): Promise<void>;
  storeToken<K extends OpaqueTokenKind>(caller: VaultCaller, kind: K, envelope: Uint8Array): Promise<OpaqueToken<K>>;
  retrieveToken<K extends OpaqueTokenKind>(caller: VaultCaller, ref: OpaqueToken<K>, stepUp: PasskeyStepUp): Promise<VaultEnvelope<K>>;
  /** The server key that seals new envelopes, or null before the first one exists. */
  activeServerKey(caller: VaultCaller): Promise<WrappedServerKey | null>;
  /** Any server key by id (retired keys included, for older envelopes). */
  serverKey(caller: VaultCaller, kid: Uint8Array): Promise<WrappedServerKey | null>;
  /** Registers the first active key; false when one already exists. */
  registerServerKey(caller: VaultCaller, key: WrappedServerKey): Promise<boolean>;
  /** Links one of the caller's own sdm_ envelopes to a new card; returns the card id. */
  registerSdmCard(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string>;
  /** Pre-authentication: opens a recovery attempt for a card tap (lockout-checked). */
  beginSdmRecovery(cardId: string, tap: SdmTapBytes): Promise<SdmRecoveryChallenge>;
  /** Closes the attempt; true only for a verified tap with a strictly higher counter. */
  confirmSdmRecovery(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<boolean>;
  /** Admin: links one of the caller's own sdm_ envelopes as a fleet key. */
  registerSdmFleetKey(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string>;
  /** Admin: links one of the caller's own sdm_ envelopes as a batch master. */
  registerSdmBatch(caller: VaultCaller, fleetId: string, sdmRef: OpaqueToken<"sdm">, label: string): Promise<string>;
  /** Admin, batch owner: imports a manifest of uid hashes (and optional activation hashes). */
  registerSdmBatchCards(caller: VaultCaller, batchId: string, uidHashes: readonly Uint8Array[], activationHashes: readonly (Uint8Array | null)[] | null): Promise<number>;
  /** Pre-authentication: the active sealed fleet keys. */
  sdmFleetKeys(): Promise<SdmFleetKey[]>;
  /** Pre-authentication: opens a tap attempt for the card behind uidHash (lockout-checked). */
  beginSdmTap(fleetId: string, uidHash: Uint8Array, tap: SdmTapBytes): Promise<SdmTapChallenge>;
  /** Closes the attempt; a single-use tap_ grant only for a verified, strictly newer tap. */
  confirmSdmTap(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<TapGrant | null>;
  /** Spends a tap_ grant once for one purpose; step_up needs the card owner as caller. */
  consumeSdmTap(caller: VaultCaller | null, grant: TapGrant, purpose: SdmTapPurpose): Promise<SdmCardState | null>;
  /** Spends a tap_ grant to link an unclaimed card to the caller (db/0246); false on every denial. */
  activateMemberCard(caller: VaultCaller, grant: TapGrant, activationHash: Uint8Array | null): Promise<boolean>;
  /** Whether the caller owns an activated, unrevoked ROUT Card (db/0250). */
  memberCardFactor(caller: VaultCaller): Promise<boolean>;
  /** Opens the caller's single-use card step-up intent (300 s); null when they own no active card. */
  beginCardStepUp(caller: VaultCaller, scope: CardStepUpScope): Promise<CardStepUpIntent | null>;
  /** Whether the caller has an open card step-up intent. */
  pendingCardStepUp(caller: VaultCaller): Promise<boolean>;
  /** Spends a tap_ grant for step_up (owner only) and completes the caller's open intent, atomically. */
  completeCardStepUp(caller: VaultCaller, grant: TapGrant): Promise<boolean>;
  /** Claims a completed intent once; returns its scope, or null (not yet completed or denied). */
  claimCardStepUp(caller: VaultCaller, intent: CardStepUpIntent): Promise<CardStepUpScope | null>;
  /** Revokes every physical ROUT Card the caller owns (lost / replaced, db/0253); returns how many. */
  revokeMemberCards(caller: VaultCaller): Promise<number>;
  /** Admin: batches with card counts, no key material. */
  listSdmBatches(caller: VaultCaller): Promise<SdmBatchSummary[]>;
  /** Admin: pins a personalisation station by its raw P-256 public key (db/0248). */
  registerSdmStation(caller: VaultCaller, label: string, publicKey: Uint8Array): Promise<string>;
  /** Admin: registered stations with fingerprints. */
  listSdmStations(caller: VaultCaller): Promise<SdmStation[]>;
  /** Admin: retires a station for good. */
  retireSdmStation(caller: VaultCaller, stationId: string): Promise<boolean>;
  /**
   * Admin: mark_sdm_batch_exported(batch, station). Logs the export on the hash chain and,
   * in the same transaction, returns the station key and the sealed envelopes; null on denial.
   */
  exportSdmBatch(caller: VaultCaller, batchId: string, stationId: string): Promise<SdmBatchExport | null>;
}

export class VaultDeniedError extends Error {
  constructor() {
    super("vault_denied");
    this.name = "VaultDeniedError";
  }
}

/** Runs one statement as `userId` (transaction-scoped context) and returns its rows. */
/** `serializable` asks for SERIALIZABLE isolation with retry on 40001/40P01. */
export type VaultSqlExecutor = (
  userId: string,
  query: string,
  params: readonly unknown[],
  opts?: { serializable?: boolean },
) => Promise<readonly Record<string, unknown>[]>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX_RE = /^[0-9a-f]*$/;

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !HEX_RE.test(hex)) throw new VaultDeniedError();
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const RegisterRow = z.object({ ok: z.boolean() });
const StoreRow = z.object({ ref: z.string().nullable() });
const RetrieveRow = z.object({
  granted: z.boolean(),
  token_type: z.enum(OPAQUE_TOKEN_KINDS).nullable(),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2).nullable(),
});

const SdmCardRow = z.object({ card_id: z.string().regex(UUID_RE).nullable() });
const SdmRetrieveRow = z.object({
  granted: z.boolean(),
  attempt_id: z.string().regex(UUID_RE).nullable(),
  owner_user_id: z.string().regex(UUID_RE).nullable(),
  sdm_ref: z.string().nullable(),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2).nullable(),
  last_counter: z.number().int().min(0).max(0xfffffe).nullable(),
});
const FleetRow = z.object({
  fleet_id: z.string().regex(UUID_RE),
  owner_user_id: z.string().regex(UUID_RE),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2),
});
const TapBeginRow = z.object({
  granted: z.boolean(),
  attempt_id: z.string().regex(UUID_RE).nullable(),
  batch_id: z.string().regex(UUID_RE).nullable(),
  batch_owner: z.string().regex(UUID_RE).nullable(),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2).nullable(),
  last_counter: z.number().int().min(0).max(0xfffffe).nullable(),
});
function parseRef(ref: OpaqueToken<"sdm">): string {
  try {
    return parseOpaqueToken(ref, "sdm");
  } catch {
    throw new VaultDeniedError();
  }
}
function uuidOf(rows: readonly Record<string, unknown>[]): string {
  const id = rows[0]?.["id"];
  if (typeof id !== "string" || !UUID_RE.test(id)) throw new VaultDeniedError();
  return id;
}
/** Anonymous (pre-authentication) calls run with an empty caller context. */
const NO_CALLER = "";

function tapHex(tap: SdmTapBytes): [string, string] {
  if (tap.piccData.length !== 16 || tap.cmac.length !== 8) throw new VaultDeniedError();
  return [toHex(tap.piccData), toHex(tap.cmac)];
}

const ServerKeyRow = z.object({
  kid_hex: z.string().length(32),
  public_key_hex: z.string().length(3200),
  wrapped_seed_hex: z.string().length(160),
  kek_id_hex: z.string().length(32),
});
const SERVER_KEY_COLUMNS =
  "encode(kid, 'hex') as kid_hex, encode(public_key, 'hex') as public_key_hex, encode(wrapped_seed, 'hex') as wrapped_seed_hex, encode(kek_id, 'hex') as kek_id_hex";

function serverKeyOf(rows: readonly Record<string, unknown>[]): WrappedServerKey | null {
  if (rows.length === 0) return null;
  const row = ServerKeyRow.safeParse(rows[0]);
  if (!row.success) throw new VaultDeniedError();
  return {
    kid: fromHex(row.data.kid_hex),
    publicKey: fromHex(row.data.public_key_hex),
    wrappedSeed: fromHex(row.data.wrapped_seed_hex),
    kekId: fromHex(row.data.kek_id_hex),
  };
}

function callerId(caller: VaultCaller): string {
  const id = cleanContextId(caller.userId);
  if (!id) throw new VaultDeniedError();
  return id;
}

async function defaultExecutor(userId: string, query: string, params: readonly unknown[], opts?: { serializable?: boolean }) {
  const { runQuery, runSerializable, withDbContext } = await import("@/lib/neon");
  const run = opts?.serializable ? runSerializable : runQuery;
  return (await withDbContext({ userId, workspaceId: null }, () => run(query, [...params]))).rows;
}

export class LocalPostgresVaultAdapter implements IVaultPort {
  constructor(private readonly exec: VaultSqlExecutor = defaultExecutor) {}

  async registerPasskeyStepUp(caller: VaultCaller, proofId: string): Promise<void> {
    if (!UUID_RE.test(proofId)) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_step_up_proof($1::uuid, 'passkey') as ok", [proofId]);
    const row = RegisterRow.safeParse(rows[0]);
    if (!row.success || !row.data.ok) throw new VaultDeniedError();
  }

  async storeToken<K extends OpaqueTokenKind>(caller: VaultCaller, kind: K, envelope: Uint8Array): Promise<OpaqueToken<K>> {
    if (!OPAQUE_TOKEN_KINDS.includes(kind) || envelope.length > ENVELOPE_MAX_BYTES) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.store_opaque_token($1, decode($2, 'hex')) as ref", [kind, toHex(envelope)]);
    const row = StoreRow.safeParse(rows[0]);
    if (!row.success || row.data.ref === null) throw new VaultDeniedError();
    try {
      return parseOpaqueToken(row.data.ref, kind);
    } catch {
      throw new VaultDeniedError();
    }
  }

  async retrieveToken<K extends OpaqueTokenKind>(caller: VaultCaller, ref: OpaqueToken<K>, stepUp: PasskeyStepUp): Promise<VaultEnvelope<K>> {
    const kind = opaqueTokenKind(ref);
    if (stepUp.verified !== true || !UUID_RE.test(stepUp.proofId)) throw new VaultDeniedError();
    const rows = await this.exec(
      callerId(caller),
      "select granted, token_type, encode(encrypted_payload, 'hex') as payload_hex from vault_enclave.retrieve_opaque_token($1, $2, $3::uuid)",
      [ref, true, stepUp.proofId],
    );
    const row = RetrieveRow.safeParse(rows[0]);
    if (!row.success || !row.data.granted || row.data.token_type !== kind || row.data.payload_hex === null) throw new VaultDeniedError();
    return { kind, envelope: fromHex(row.data.payload_hex) };
  }

  async activeServerKey(caller: VaultCaller): Promise<WrappedServerKey | null> {
    return serverKeyOf(await this.exec(callerId(caller), `select ${SERVER_KEY_COLUMNS} from vault_enclave.server_key_active()`, []));
  }

  async serverKey(caller: VaultCaller, kid: Uint8Array): Promise<WrappedServerKey | null> {
    if (kid.length !== 16) throw new VaultDeniedError();
    return serverKeyOf(
      await this.exec(callerId(caller), `select ${SERVER_KEY_COLUMNS} from vault_enclave.server_key_get(decode($1, 'hex'))`, [toHex(kid)]),
    );
  }

  async registerServerKey(caller: VaultCaller, key: WrappedServerKey): Promise<boolean> {
    const rows = await this.exec(
      callerId(caller),
      "select vault_enclave.register_server_key(decode($1, 'hex'), decode($2, 'hex'), decode($3, 'hex'), decode($4, 'hex')) as ok",
      [toHex(key.kid), toHex(key.publicKey), toHex(key.wrappedSeed), toHex(key.kekId)],
    );
    const row = RegisterRow.safeParse(rows[0]);
    if (!row.success) throw new VaultDeniedError();
    return row.data.ok;
  }

  async registerSdmCard(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string> {
    if (opaqueTokenKind(sdmRef) !== "sdm") throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_card($1)::text as card_id", [sdmRef]);
    const row = SdmCardRow.safeParse(rows[0]);
    if (!row.success || row.data.card_id === null) throw new VaultDeniedError();
    return row.data.card_id;
  }

  async beginSdmRecovery(cardId: string, tap: SdmTapBytes): Promise<SdmRecoveryChallenge> {
    if (!UUID_RE.test(cardId)) throw new VaultDeniedError();
    // Malformed taps still reach the enclave so they count against the lockout.
    const picc = tap.piccData.length <= 64 ? toHex(tap.piccData) : "";
    const mac = tap.cmac.length <= 64 ? toHex(tap.cmac) : "";
    const rows = await this.exec(
      NO_CALLER,
      "select granted, attempt_id::text as attempt_id, owner_user_id::text as owner_user_id, sdm_ref, encode(encrypted_payload, 'hex') as payload_hex, last_counter from vault_enclave.retrieve_sdm_for_recovery($1::uuid, decode($2, 'hex'), decode($3, 'hex'))",
      [cardId, picc, mac],
    );
    const row = SdmRetrieveRow.safeParse(rows[0]);
    if (!row.success || !row.data.granted || !row.data.attempt_id || !row.data.owner_user_id || !row.data.sdm_ref || !row.data.payload_hex) {
      throw new VaultDeniedError();
    }
    let sdmRef: OpaqueToken<"sdm">;
    try {
      sdmRef = parseOpaqueToken(row.data.sdm_ref, "sdm");
    } catch {
      throw new VaultDeniedError();
    }
    return { attemptId: row.data.attempt_id, ownerUserId: row.data.owner_user_id, sdmRef, envelope: fromHex(row.data.payload_hex), lastCounter: row.data.last_counter };
  }

  async confirmSdmRecovery(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<boolean> {
    if (!UUID_RE.test(attemptId)) throw new VaultDeniedError();
    const [picc, mac] = tapHex(tap);
    const counter = readCounter !== null && Number.isInteger(readCounter) && readCounter >= 0 && readCounter <= 0xfffffe ? readCounter : null;
    const rows = await this.exec(
      NO_CALLER,
      "select vault_enclave.confirm_sdm_recovery($1::uuid, decode($2, 'hex'), decode($3, 'hex'), $4, $5::int) as ok",
      [attemptId, picc, mac, verified === true, counter],
    );
    const row = RegisterRow.safeParse(rows[0]);
    return row.success && row.data.ok;
  }

  async registerSdmFleetKey(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string> {
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_fleet_key($1)::text as id", [parseRef(sdmRef)]);
    return uuidOf(rows);
  }

  async registerSdmBatch(caller: VaultCaller, fleetId: string, sdmRef: OpaqueToken<"sdm">, label: string): Promise<string> {
    if (!UUID_RE.test(fleetId) || typeof label !== "string" || label.length > 80) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_batch($1::uuid, $2, $3)::text as id", [fleetId, parseRef(sdmRef), label]);
    return uuidOf(rows);
  }

  async registerSdmBatchCards(caller: VaultCaller, batchId: string, uidHashes: readonly Uint8Array[], activationHashes: readonly (Uint8Array | null)[] | null): Promise<number> {
    if (!UUID_RE.test(batchId) || uidHashes.length < 1 || uidHashes.length > 5000) throw new VaultDeniedError();
    if (uidHashes.some((h) => h.length !== 32)) throw new VaultDeniedError();
    if (activationHashes && (activationHashes.length !== uidHashes.length || activationHashes.some((h) => h !== null && h.length !== 32))) throw new VaultDeniedError();
    // Hex text arrays keep the statement portable across drivers.
    const rows = await this.exec(
      callerId(caller),
      "select vault_enclave.register_sdm_batch_cards($1::uuid, (select array_agg(decode(x, 'hex') order by i) from unnest($2::text[]) with ordinality u(x, i)), (select array_agg(case when x = '' then null else decode(x, 'hex') end order by i) from unnest($3::text[]) with ordinality a(x, i))) as n",
      [batchId, uidHashes.map(toHex), activationHashes ? activationHashes.map((h) => (h ? toHex(h) : "")) : null],
    );
    const row = z.object({ n: z.number().int().min(0).nullable() }).safeParse(rows[0]);
    if (!row.success || row.data.n === null) throw new VaultDeniedError();
    return row.data.n;
  }

  async sdmFleetKeys(): Promise<SdmFleetKey[]> {
    const rows = await this.exec(NO_CALLER, "select fleet_id::text as fleet_id, owner_user_id::text as owner_user_id, encode(encrypted_payload, 'hex') as payload_hex from vault_enclave.sdm_tap_fleet_keys()", []);
    const parsed = z.array(FleetRow).max(4).safeParse(rows);
    if (!parsed.success) throw new VaultDeniedError();
    return parsed.data.map((r) => ({ fleetId: r.fleet_id, ownerUserId: r.owner_user_id, envelope: fromHex(r.payload_hex) }));
  }

  async beginSdmTap(fleetId: string, uidHash: Uint8Array, tap: SdmTapBytes): Promise<SdmTapChallenge> {
    if (!UUID_RE.test(fleetId) || uidHash.length !== 32) throw new VaultDeniedError();
    const [picc, mac] = tapHex(tap);
    const rows = await this.exec(
      NO_CALLER,
      "select granted, attempt_id::text as attempt_id, batch_id::text as batch_id, batch_owner::text as batch_owner, encode(encrypted_payload, 'hex') as payload_hex, last_counter from vault_enclave.begin_sdm_tap($1::uuid, decode($2, 'hex'), decode($3, 'hex'), decode($4, 'hex'))",
      [fleetId, toHex(uidHash), picc, mac],
    );
    const row = TapBeginRow.safeParse(rows[0]);
    if (!row.success || !row.data.granted || !row.data.attempt_id || !row.data.batch_id || !row.data.batch_owner || !row.data.payload_hex) {
      throw new VaultDeniedError();
    }
    return { attemptId: row.data.attempt_id, batchId: row.data.batch_id, batchOwner: row.data.batch_owner, envelope: fromHex(row.data.payload_hex), lastCounter: row.data.last_counter };
  }

  async confirmSdmTap(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<TapGrant | null> {
    if (!UUID_RE.test(attemptId)) throw new VaultDeniedError();
    const [picc, mac] = tapHex(tap);
    const counter = readCounter !== null && Number.isInteger(readCounter) && readCounter >= 0 && readCounter <= 0xfffffe ? readCounter : null;
    const rows = await this.exec(
      NO_CALLER,
      "select vault_enclave.confirm_sdm_tap($1::uuid, decode($2, 'hex'), decode($3, 'hex'), $4, $5::int) as grant_ref",
      [attemptId, picc, mac, verified === true, counter],
    );
    const ref = rows[0]?.["grant_ref"];
    return isTapGrant(ref) ? ref : null;
  }

  async consumeSdmTap(caller: VaultCaller | null, grant: TapGrant, purpose: SdmTapPurpose): Promise<SdmCardState | null> {
    if (!isTapGrant(grant) || (purpose !== "public_proof" && purpose !== "step_up" && purpose !== "recovery_factor")) throw new VaultDeniedError();
    const rows = await this.exec(caller ? callerId(caller) : NO_CALLER, "select granted, card_state from vault_enclave.consume_sdm_tap($1, $2)", [grant, purpose], { serializable: true });
    const row = z.object({ granted: z.boolean(), card_state: z.enum(["active", "unactivated"]).nullable() }).safeParse(rows[0]);
    return row.success && row.data.granted && row.data.card_state ? row.data.card_state : null;
  }

  async activateMemberCard(caller: VaultCaller, grant: TapGrant, activationHash: Uint8Array | null): Promise<boolean> {
    if (!isTapGrant(grant) || (activationHash !== null && activationHash.length !== 32)) throw new VaultDeniedError();
    const rows = await this.exec(
      callerId(caller),
      "select vault_enclave.activate_member_card($1, case when $2::text is null then null else decode($2, 'hex') end) as ok",
      [grant, activationHash ? toHex(activationHash) : null],
      { serializable: true },
    );
    return rows[0]?.["ok"] === true;
  }

  async memberCardFactor(caller: VaultCaller): Promise<boolean> {
    const rows = await this.exec(callerId(caller), "select vault_enclave.member_card_factor() as ok", []);
    return rows[0]?.["ok"] === true;
  }

  async beginCardStepUp(caller: VaultCaller, scope: CardStepUpScope): Promise<CardStepUpIntent | null> {
    if (!CARD_STEP_UP_SCOPES.includes(scope)) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.begin_card_step_up($1) as ref", [scope], { serializable: true });
    const ref = rows[0]?.["ref"];
    return isCardStepUpIntent(ref) ? ref : null;
  }

  async pendingCardStepUp(caller: VaultCaller): Promise<boolean> {
    const rows = await this.exec(callerId(caller), "select vault_enclave.pending_card_step_up() as ok", []);
    return rows[0]?.["ok"] === true;
  }

  async completeCardStepUp(caller: VaultCaller, grant: TapGrant): Promise<boolean> {
    if (!isTapGrant(grant)) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.complete_card_step_up($1) as ok", [grant], { serializable: true });
    return rows[0]?.["ok"] === true;
  }

  async claimCardStepUp(caller: VaultCaller, intent: CardStepUpIntent): Promise<CardStepUpScope | null> {
    if (!isCardStepUpIntent(intent)) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.claim_card_step_up($1) as scope", [intent], { serializable: true });
    const scope = rows[0]?.["scope"];
    return CARD_STEP_UP_SCOPES.includes(scope as CardStepUpScope) ? (scope as CardStepUpScope) : null;
  }

  async revokeMemberCards(caller: VaultCaller): Promise<number> {
    const rows = await this.exec(callerId(caller), "select vault_enclave.revoke_member_cards() as n", [], { serializable: true });
    const n = Number(rows[0]?.["n"]);
    return Number.isSafeInteger(n) && n >= 0 ? n : 0;
  }

  async listSdmBatches(caller: VaultCaller): Promise<SdmBatchSummary[]> {
    const rows = await this.exec(
      callerId(caller),
      "select batch_id::text as batch_id, fleet_id::text as fleet_id, label, created_at::text as created_at, exported_at::text as exported_at, retired_at::text as retired_at, cards, active_cards from vault_enclave.list_sdm_batches()",
      [],
    );
    const parsed = z
      .array(
        z.object({
          batch_id: z.string().regex(UUID_RE),
          fleet_id: z.string().regex(UUID_RE),
          label: z.string().max(80),
          created_at: z.string(),
          exported_at: z.string().nullable(),
          retired_at: z.string().nullable(),
          cards: z.number().int().min(0),
          active_cards: z.number().int().min(0),
        }),
      )
      .max(200)
      .safeParse(rows);
    if (!parsed.success) throw new VaultDeniedError();
    return parsed.data.map((r) => ({
      batchId: r.batch_id,
      fleetId: r.fleet_id,
      label: r.label,
      createdAt: r.created_at,
      exportedAt: r.exported_at,
      retiredAt: r.retired_at,
      cards: r.cards,
      activeCards: r.active_cards,
    }));
  }

  async registerSdmStation(caller: VaultCaller, label: string, publicKey: Uint8Array): Promise<string> {
    if (publicKey.length !== 65 || publicKey[0] !== 0x04 || label.trim().length < 1 || label.trim().length > 80) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_station($1, decode($2, 'hex'))::text as id", [label.trim(), toHex(publicKey)]);
    const id = rows[0]?.["id"];
    if (typeof id !== "string" || !UUID_RE.test(id)) throw new VaultDeniedError();
    return id;
  }

  async listSdmStations(caller: VaultCaller): Promise<SdmStation[]> {
    const rows = await this.exec(
      callerId(caller),
      "select station_id::text as station_id, label, encode(fingerprint, 'hex') as fingerprint_hex, created_at::text as created_at, retired_at::text as retired_at from vault_enclave.list_sdm_stations()",
      [],
    );
    const parsed = z
      .array(
        z.object({
          station_id: z.string().regex(UUID_RE),
          label: z.string().max(80),
          fingerprint_hex: z.string().regex(/^[0-9a-f]{64}$/),
          created_at: z.string(),
          retired_at: z.string().nullable(),
        }),
      )
      .max(50)
      .safeParse(rows);
    if (!parsed.success) throw new VaultDeniedError();
    return parsed.data.map((r) => ({ stationId: r.station_id, label: r.label, fingerprint: fromHex(r.fingerprint_hex), createdAt: r.created_at, retiredAt: r.retired_at }));
  }

  async retireSdmStation(caller: VaultCaller, stationId: string): Promise<boolean> {
    if (!UUID_RE.test(stationId)) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.retire_sdm_station($1::uuid) as ok", [stationId]);
    return rows[0]?.["ok"] === true;
  }

  async exportSdmBatch(caller: VaultCaller, batchId: string, stationId: string): Promise<SdmBatchExport | null> {
    if (!UUID_RE.test(batchId) || !UUID_RE.test(stationId)) throw new VaultDeniedError();
    const rows = await this.exec(
      callerId(caller),
      "select granted, encode(station_public_key, 'hex') as station_hex, batch_owner::text as batch_owner, encode(batch_payload, 'hex') as batch_hex, fleet_owner::text as fleet_owner, encode(fleet_payload, 'hex') as fleet_hex from vault_enclave.mark_sdm_batch_exported($1::uuid, $2::uuid)",
      [batchId, stationId],
    );
    const row = z
      .object({
        granted: z.boolean(),
        station_hex: z.string().regex(/^04[0-9a-f]{128}$/).nullable(),
        batch_owner: z.string().regex(UUID_RE).nullable(),
        batch_hex: z.string().regex(/^[0-9a-f]+$/).nullable(),
        fleet_owner: z.string().regex(UUID_RE).nullable(),
        fleet_hex: z.string().regex(/^[0-9a-f]+$/).nullable(),
      })
      .safeParse(rows[0]);
    if (!row.success || !row.data.granted) return null;
    const d = row.data;
    if (!d.station_hex || !d.batch_owner || !d.batch_hex || !d.fleet_owner || !d.fleet_hex) return null;
    return { stationPublicKey: fromHex(d.station_hex), batchOwner: d.batch_owner, batchEnvelope: fromHex(d.batch_hex), fleetOwner: d.fleet_owner, fleetEnvelope: fromHex(d.fleet_hex) };
  }
}

let port: IVaultPort | undefined;
/** The process-wide vault port. Swap the adapter here, nowhere else. */
export function vaultPort(): IVaultPort {
  port ??= new LocalPostgresVaultAdapter();
  return port;
}

/**
 * Reads a sealed envelope for the signed-in member. Requires the member's
 * fresh passkey step-up for "vault_token_read" (spent once, here and in the enclave).
 */
export async function readVaultEnvelope<K extends OpaqueTokenKind>(userId: string, ref: OpaqueToken<K>): Promise<VaultEnvelope<K>> {
  const { ensureStepUpProof, StepUpRequiredError } = await import("@/lib/auth/step-up.server");
  const { stepUpProofId } = await import("./step-up-proof-id");
  const proof = await ensureStepUpProof(userId, "vault_token_read");
  if (proof.method !== "passkey") throw new StepUpRequiredError();
  return vaultPort().retrieveToken({ userId }, ref, { verified: true, proofId: stepUpProofId(proof.jti) });
}
