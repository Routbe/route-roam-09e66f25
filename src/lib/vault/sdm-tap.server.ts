/**
 * ROUT Card taps (db/0245): NXP NTAG 424 DNA SUN/SDM, unlinkable.
 *
 * Tap URL: https://rout.be/t?p=<PICCData, 32 hex>&m=<CMAC, 16 hex>. No card id
 * or batch id: PICCData differs on every tap.
 *
 *   1. The active fleet keys (K_SDMMetaRead + UID-index key) are opened with
 *      the server vault key; PICCData is decrypted to UID + counter, unverified.
 *   2. vault_enclave.begin_sdm_tap finds the card by HMAC(UID-index key, UID),
 *      checks the lockout and opens a PENDING attempt (a failure until closed);
 *      it returns the card's sealed batch master.
 *   3. K_SDMFileRead = AN10922(batch master, UID || batch id), then the
 *      AN12196 SV2 session key and truncated CMAC are checked (sdm-verifier).
 *   4. vault_enclave.confirm_sdm_tap binds the verdict to the same tap bytes,
 *      within 60 s, with a strictly higher counter, and mints a single-use
 *      tap_ grant (120 s) that one purpose can spend.
 *
 * Every key byte is wiped in `finally`. Every failure is the same
 * VaultDeniedError; reasons stay on the enclave's audit chain. Never log
 * PICCData, CMAC or UID.
 */
import { z } from "zod";
import { cardDivInput, decryptPiccData, diversifyAes128, uidIndex, verifySdmTap } from "@/lib/crypto-enclave/sdm-verifier";
import type { VaultKek } from "./server-kek";
import { openWithServerKey, sealServerToken } from "./server-vault.server";
import type { TapGrant } from "./token-boundary";
import { VaultDeniedError, vaultPort, type IVaultPort, type SdmBatchSummary, type SdmCardState, type SdmTapBytes, type SdmTapChallenge } from "./vault-port.server";

export const SDM_FLEET_PURPOSE = "card_fleet";
export const SDM_BATCH_PURPOSE = "card_batch";
const FLEET_MAGIC = [0x53, 0x44, 0x46, 0x31] as const; // "SDF1"
const BATCH_MAGIC = [0x53, 0x44, 0x42, 0x31] as const; // "SDB1"
const FLEET_BYTES = 4 + 16 + 32;
const BATCH_BYTES = 4 + 16;

/** `random` is injectable for tests that must act as the card (they need its keys). */
type Deps = { port?: IVaultPort; kek?: VaultKek; random?: (n: number) => Uint8Array };
const randomOf = (deps: Deps) => deps.random ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
const kekOf = (deps: Deps) => (deps.kek ? { kek: deps.kek } : {});

export const CardTapSchema = z
  .object({ p: z.string().regex(/^[0-9A-Fa-f]{32}$/), m: z.string().regex(/^[0-9A-Fa-f]{16}$/) })
  .strict();
export type CardTap = z.infer<typeof CardTapSchema>;

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
const uuidBytes = (id: string) => hexBytes(id.replace(/-/g, ""));

function withMagic(magic: readonly number[], parts: Uint8Array[], size: number): Uint8Array {
  const out = new Uint8Array(size);
  out.set(magic, 0);
  let at = magic.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  if (at !== size) throw new TypeError("sdm_secret_size");
  return out;
}

/** Views into `plain` (wipe `plain` to wipe them). */
function fleetSecrets(plain: Uint8Array) {
  if (plain.length !== FLEET_BYTES || FLEET_MAGIC.some((m, i) => plain[i] !== m)) throw new VaultDeniedError();
  return { metaReadKey: plain.subarray(4, 20), uidIndexKey: plain.subarray(20, 52) };
}
function batchMaster(plain: Uint8Array): Uint8Array {
  if (plain.length !== BATCH_BYTES || BATCH_MAGIC.some((m, i) => plain[i] !== m)) throw new VaultDeniedError();
  return plain.subarray(4, 20);
}

/** The stored form of a printed activation code (same as the manifest import). */
export async function activationCodeHash(code: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`rout-card-activation:v1:${code.trim().toUpperCase()}`)));
}

// ---------------------------------------------------------------- admin side

/** Generates a fleet key inside the server, seals it and registers it (admin). */
export async function createSdmFleetKey(adminId: string, deps: Deps = {}): Promise<string> {
  const port = deps.port ?? vaultPort();
  const plain = withMagic(FLEET_MAGIC, [randomOf(deps)(16), randomOf(deps)(32)], FLEET_BYTES);
  try {
    const ref = await sealServerToken(adminId, "sdm", SDM_FLEET_PURPOSE, plain, { port, ...kekOf(deps) });
    return await port.registerSdmFleetKey({ userId: adminId }, ref);
  } finally {
    plain.fill(0);
  }
}

/** Generates a batch master inside the server, seals it and registers the batch (admin). */
export async function createSdmBatch(adminId: string, fleetId: string, label: string, deps: Deps = {}): Promise<string> {
  const port = deps.port ?? vaultPort();
  const plain = withMagic(BATCH_MAGIC, [randomOf(deps)(16)], BATCH_BYTES);
  try {
    const ref = await sealServerToken(adminId, "sdm", SDM_BATCH_PURPOSE, plain, { port, ...kekOf(deps) });
    return await port.registerSdmBatch({ userId: adminId }, fleetId, ref, label);
  } finally {
    plain.fill(0);
  }
}

async function openFleet<T>(fleet: { ownerUserId: string; envelope: Uint8Array }, deps: Deps, use: (s: ReturnType<typeof fleetSecrets>) => T | Promise<T>): Promise<T> {
  const plain = await openWithServerKey(fleet.ownerUserId, "sdm", SDM_FLEET_PURPOSE, fleet.envelope, { ...(deps.port ? { port: deps.port } : {}), ...kekOf(deps) });
  try {
    return await use(fleetSecrets(plain));
  } finally {
    plain.fill(0);
  }
}

/** Manifest import: raw UIDs (and activation codes) from the station become keyed hashes here. */
export async function importSdmManifest(
  adminId: string,
  fleetId: string,
  batchId: string,
  cards: readonly { uid: string; activationCode?: string }[],
  deps: Deps = {},
): Promise<number> {
  const port = deps.port ?? vaultPort();
  const fleet = (await port.sdmFleetKeys()).find((f) => f.fleetId === fleetId);
  if (!fleet || cards.length < 1 || cards.length > 5000) throw new VaultDeniedError();
  if (cards.some((c) => !/^[0-9A-Fa-f]{14}$/.test(c.uid))) throw new VaultDeniedError();
  const activation = await Promise.all(cards.map((c) => (c.activationCode ? activationCodeHash(c.activationCode) : null)));
  const hashes = await openFleet(fleet, deps, (s) =>
    cards.map((c) => {
      const uid = hexBytes(c.uid);
      try {
        return uidIndex(s.uidIndexKey, uid);
      } finally {
        uid.fill(0);
      }
    }),
  );
  return port.registerSdmBatchCards({ userId: adminId }, batchId, hashes, activation.some((a) => a) ? activation : null);
}

// ---------------------------------------------------------------- tap side

/** Verifies one tap and returns a fresh single-use tap_ grant. */
export async function verifyCardTap(input: unknown, deps: Deps = {}): Promise<TapGrant> {
  const parsed = CardTapSchema.safeParse(input);
  if (!parsed.success) throw new VaultDeniedError();
  const port = deps.port ?? vaultPort();
  const tap: SdmTapBytes = { piccData: hexBytes(parsed.data.p), cmac: hexBytes(parsed.data.m) };
  const fleets = await port.sdmFleetKeys();

  let challenge: SdmTapChallenge | null = null;
  let metaReadKey: Uint8Array | null = null;
  let uid: Uint8Array | null = null;
  for (const fleet of fleets) {
    try {
      const found = await openFleet(fleet, deps, async (s) => {
        const picc = decryptPiccData(s.metaReadKey, parsed.data.p);
        if (!picc) return null;
        const hash = uidIndex(s.uidIndexKey, picc.uid);
        try {
          const c = await port.beginSdmTap(fleet.fleetId, hash, tap);
          return { c, meta: s.metaReadKey.slice(), uid: picc.uid };
        } catch (e) {
          picc.uid.fill(0);
          throw e;
        } finally {
          hash.fill(0);
        }
      });
      if (found) {
        challenge = found.c;
        metaReadKey = found.meta;
        uid = found.uid;
        break;
      }
    } catch {
      // A wrong fleet (or a denied begin) is not an answer yet: try the next one.
    }
  }
  if (!challenge || !metaReadKey || !uid) throw new VaultDeniedError();

  let plain: Uint8Array | undefined;
  let fileReadKey: Uint8Array | undefined;
  let divInput: Uint8Array | undefined;
  let verified: { readCounter: number } | null = null;
  try {
    plain = await openWithServerKey(challenge.batchOwner, "sdm", SDM_BATCH_PURPOSE, challenge.envelope, { ...(deps.port ? { port: deps.port } : {}), ...kekOf(deps) });
    divInput = cardDivInput(uid, uuidBytes(challenge.batchId));
    fileReadKey = diversifyAes128(batchMaster(plain), divInput);
    verified = verifySdmTap({
      tap: { piccData: parsed.data.p, cmac: parsed.data.m },
      keys: { metaReadKey, fileReadKey },
      lastCounter: challenge.lastCounter,
      expectedUid: toHex(uid),
    });
    const grant = await port.confirmSdmTap(challenge.attemptId, tap, true, verified.readCounter);
    if (!grant) throw new VaultDeniedError();
    return grant;
  } catch {
    if (verified === null) await port.confirmSdmTap(challenge.attemptId, tap, false, null).catch(() => null);
    throw new VaultDeniedError();
  } finally {
    plain?.fill(0);
    fileReadKey?.fill(0);
    divInput?.fill(0);
    metaReadKey.fill(0);
    uid.fill(0);
  }
}

/** A tap for the public "authentic card" check: verified, then spent at once. */
export async function publicCardProof(input: unknown, deps: Deps = {}): Promise<SdmCardState> {
  const port = deps.port ?? vaultPort();
  const grant = await verifyCardTap(input, { ...deps, port });
  const state = await port.consumeSdmTap(null, grant, "public_proof");
  if (!state) throw new VaultDeniedError();
  return state;
}

/**
 * A live tap of the signed-in member's own, unrevoked card, for the 2-of-4
 * recovery vault (db-pending/0267 purpose recovery_factor): verified exactly
 * like a public proof, then spent at once. Completes no step-up and reveals
 * nothing else. False for every denial, including a database without 0267.
 */
export async function confirmOwnCardTap(userId: string, input: unknown, deps: Deps = {}): Promise<boolean> {
  const port = deps.port ?? vaultPort();
  let grant: TapGrant;
  try {
    grant = await verifyCardTap(input, { ...deps, port });
  } catch {
    return false;
  }
  const state = await port.consumeSdmTap({ userId }, grant, "recovery_factor").catch(() => null);
  return state === "active";
}

// ---------------------------------------------------------------- activation (db/0246)

/**
 * First physical tap of a new card by its signed-in member: the tap is verified
 * exactly like a public proof, then its grant is spent for "activation", which
 * links the unclaimed card to `userId`. Every denial is the same VaultDeniedError.
 */
export async function activateMemberCard(userId: string, input: unknown, activationCode: string | null, deps: Deps = {}): Promise<void> {
  const port = deps.port ?? vaultPort();
  const grant = await verifyCardTap(input, { ...deps, port });
  const code = activationCode?.trim() ? activationCode : null;
  if (code !== null && !/^[0-9A-Za-z-]{4,32}$/.test(code.trim())) throw new VaultDeniedError();
  const hash = code ? await activationCodeHash(code) : null;
  try {
    if (!(await port.activateMemberCard({ userId }, grant, hash))) throw new VaultDeniedError();
  } finally {
    hash?.fill(0);
  }
}

/** Admin: batch overview (counts only). */
export function listSdmBatches(adminId: string, deps: Deps = {}): Promise<SdmBatchSummary[]> {
  return (deps.port ?? vaultPort()).listSdmBatches({ userId: adminId });
}

/** 3-byte little-endian, as NTAG 424 DNA file settings carry offsets. */
const le24 = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff];

/**
 * NDEF file 2 for the tap URL (NFC Forum Type 4): NLEN (2) + short URI record
 * D1 01 <len> 55 + prefix 0x04 ("https://") + URL body. Offsets are positions
 * inside this file, which is what the SDM mirror offsets refer to.
 */
export function sdmNdefFile(origin = "https://rout.be") {
  const url = `${origin.replace(/\/$/, "")}/t?p=${"0".repeat(32)}&m=${"0".repeat(16)}`;
  if (!url.startsWith("https://")) throw new TypeError("sdm_origin_not_https");
  const body = new TextEncoder().encode(url.slice("https://".length));
  const payloadLength = 1 + body.length; // prefix code + body
  if (payloadLength > 255) throw new TypeError("sdm_url_too_long");
  const record = [0xd1, 0x01, payloadLength, 0x55, 0x04, ...body];
  const file = Uint8Array.from([(record.length >> 8) & 0xff, record.length & 0xff, ...record]);
  const bodyAt = 2 + 4 + 1;
  const text = url.slice("https://".length);
  return { url, file, piccOffset: bodyAt + text.indexOf("p=") + 2, macOffset: bodyAt + text.indexOf("m=") + 2 };
}

/**
 * NTAG 424 DNA personalisation settings for the writing station (AN12196 SUN):
 * the NDEF file, the ChangeFileSettings payload for file 2 and the key slots.
 * It carries no key bytes: a leaked file grants nothing.
 *
 * File settings (NT4H2421 / AN12196): FileOption 0x40 (SDM on, plain comm),
 * AccessRights 00 E0 (read free, write/RW/change key 0), SDMOptions 0xC1 (UID
 * and read counter inside the encrypted PICCData, ASCII), SDMAccessRights
 * FF 12 (no plain counter read, MetaRead key 1, FileRead key 2), then
 * PICCDataOffset, SDMMACInputOffset and SDMMACOffset (MAC input = MAC offset,
 * so the CMAC covers no file data; matches sdm-verifier).
 */
export function stationConfig(batchId: string, origin = "https://rout.be") {
  const ndef = sdmNdefFile(origin);
  const fileSettings = Uint8Array.from([0x40, 0x00, 0xe0, 0xc1, 0xff, 0x12, ...le24(ndef.piccOffset), ...le24(ndef.macOffset), ...le24(ndef.macOffset)]);
  return {
    format: "rout-sdm-station/v2",
    batchId,
    chip: "NTAG 424 DNA",
    ndef: { fileNo: 2, uriPrefix: "https://", urlTemplate: ndef.url, fileHex: toHex(ndef.file), fileLength: ndef.file.length },
    changeFileSettings: { fileNo: 2, commMode: "full (key 0)", payloadHex: toHex(fileSettings) },
    sdm: {
      enabled: true,
      asciiEncoding: true,
      // Mirrored inside the encrypted PICCData (tag 0xC7), never in plain text.
      uidInPiccData: true,
      readCounterInPiccData: true,
      plainCounterRead: false,
      encryptedPiccData: { offset: ndef.piccOffset, length: 32, keyNo: 1, key: "K_SDMMetaRead (fleet)" },
      sdmMac: { offset: ndef.macOffset, macInputOffset: ndef.macOffset, length: 16, keyNo: 2, key: "K_SDMFileRead = AN10922(batch master, UID || batch id)" },
      readCounterLimit: null,
    },
    access: { read: "free", write: "key 0", readWrite: "key 0", change: "key 0", keyNo0: "card master (station)" },
    manifest: { format: "one line per chip: UID (14 hex)[,activation code]", maxCards: 5000 },
  } as const;
}

export const SDM_KEYS_FORMAT = "rout-sdm-keys/v1";
const KEYS_MAGIC = [0x52, 0x53, 0x4b, 0x31] as const; // "RSK1"
const KEYS_AAD = new TextEncoder().encode(SDM_KEYS_FORMAT);

/** HPKE info: binds the sealed keys to this batch and this one station key. */
export function sdmExportInfo(batchId: string, fingerprint: Uint8Array): Uint8Array {
  const label = new TextEncoder().encode("rout-sdm-station/v2");
  const out = new Uint8Array(label.length + 1 + 16 + 32);
  out.set(label, 0);
  out.set(uuidBytes(batchId), label.length + 1);
  out.set(fingerprint, label.length + 17);
  return out;
}
export const sdmExportAad = () => KEYS_AAD.slice();

/** Admin: registers a station from PEM / base64 SPKI / raw hex; returns id and fingerprint. */
export async function registerSdmStation(adminId: string, label: string, publicKeyText: string, deps: Deps = {}) {
  const { parseStationPublicKey, stationFingerprint } = await import("./hpke-p256");
  let pk: Uint8Array;
  try {
    pk = parseStationPublicKey(publicKeyText);
  } catch {
    throw new VaultDeniedError();
  }
  const stationId = await (deps.port ?? vaultPort()).registerSdmStation({ userId: adminId }, label, pk);
  return { stationId, fingerprint: toHex(stationFingerprint(pk)) };
}

export async function listSdmStations(adminId: string, deps: Deps = {}) {
  const rows = await (deps.port ?? vaultPort()).listSdmStations({ userId: adminId });
  return rows.map((r) => ({ stationId: r.stationId, label: r.label, fingerprint: toHex(r.fingerprint), createdAt: r.createdAt, retiredAt: r.retiredAt }));
}

export function retireSdmStation(adminId: string, stationId: string, deps: Deps = {}) {
  return (deps.port ?? vaultPort()).retireSdmStation({ userId: adminId }, stationId);
}

/**
 * Admin: the station bundle. mark_sdm_batch_exported logs the export (with the
 * station fingerprint) and returns the sealed envelopes in one transaction; the
 * keys are opened here, HPKE-sealed to the station (P-256, AES-256-GCM) and wiped.
 * The returned JSON holds only the HPKE ciphertext, never a key byte.
 */
export async function exportStationBundle(adminId: string, batchId: string, stationId: string, origin?: string, deps: Deps = {}) {
  const port = deps.port ?? vaultPort();
  const { hpkeSeal, stationFingerprint, HPKE_AEAD_AES256GCM, HPKE_KDF_SHA256, HPKE_KEM_P256 } = await import("./hpke-p256");
  const ex = await port.exportSdmBatch({ userId: adminId }, batchId, stationId);
  if (!ex) throw new VaultDeniedError();
  const fingerprint = stationFingerprint(ex.stationPublicKey);
  const portDeps = { ...(deps.port ? { port: deps.port } : {}), ...kekOf(deps) };
  let fleetPlain: Uint8Array | null = null;
  let batchPlain: Uint8Array | null = null;
  const payload = new Uint8Array(4 + 16 + 16 + 16);
  try {
    fleetPlain = await openWithServerKey(ex.fleetOwner, "sdm", SDM_FLEET_PURPOSE, ex.fleetEnvelope, portDeps);
    batchPlain = await openWithServerKey(ex.batchOwner, "sdm", SDM_BATCH_PURPOSE, ex.batchEnvelope, portDeps);
    payload.set(KEYS_MAGIC, 0);
    payload.set(uuidBytes(batchId), 4);
    payload.set(fleetSecrets(fleetPlain).metaReadKey, 20);
    payload.set(batchMaster(batchPlain), 36);
    const info = sdmExportInfo(batchId, fingerprint);
    const sealed = hpkeSeal(ex.stationPublicKey, info, KEYS_AAD, payload);
    return {
      ...stationConfig(batchId, origin),
      keys: {
        format: SDM_KEYS_FORMAT,
        hpke: { rfc: "RFC 9180", mode: "base", kemId: HPKE_KEM_P256, kdfId: HPKE_KDF_SHA256, aeadId: HPKE_AEAD_AES256GCM, suite: "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM" },
        station: { stationId, fingerprint: toHex(fingerprint) },
        infoHex: toHex(info),
        aadHex: toHex(KEYS_AAD),
        encHex: toHex(sealed.enc),
        ciphertextHex: toHex(sealed.ciphertext),
        plaintextLayout: '"RSK1" (4) || batch id (16) || K_SDMMetaRead, key 1 (16) || batch master (16)',
        diversification: "K_SDMFileRead (key 2) = AN10922 AES-128(batch master, M = UID (7) || batch id (16))",
      },
    };
  } finally {
    payload.fill(0);
    fleetPlain?.fill(0);
    batchPlain?.fill(0);
  }
}

// ---------------------------------------------------------------- step-up (db/0250)

/**
 * A tap of the member's own card completes their open card step-up intent: the
 * tap is verified like a public proof, then complete_card_step_up spends the
 * grant for 'step_up' (owner-checked) in the same transaction. False on every
 * denial (no open intent, another member's card, a revoked card, a replay).
 */
export async function completeCardStepUpTap(userId: string, input: unknown, deps: Deps = {}): Promise<boolean> {
  const port = deps.port ?? vaultPort();
  let grant: TapGrant;
  try {
    grant = await verifyCardTap(input, { ...deps, port });
  } catch {
    return false;
  }
  return port.completeCardStepUp({ userId }, grant).catch(() => false);
}

/** Lost or replaced: every physical card of the member stops working at once (db/0253). */
export function revokeMemberCards(userId: string, deps: Deps = {}): Promise<number> {
  return (deps.port ?? vaultPort()).revokeMemberCards({ userId });
}

/**
 * A blocked or replaced ROUT card also retires the member's physical cards, so a
 * lost chip can no longer confirm anything. Never throws: a refusal is logged
 * and recorded as a security event.
 */
export async function retireMemberCards(userId: string, deps: Deps = {}): Promise<void> {
  try {
    await revokeMemberCards(userId, deps);
  } catch {
    console.error("[card] physical card revoke failed");
    const { recordSecurityEvent } = await import("@/lib/audit-log.server");
    void recordSecurityEvent({ eventType: "card.physical_revoke_failed", userId, payload: {} });
  }
}
