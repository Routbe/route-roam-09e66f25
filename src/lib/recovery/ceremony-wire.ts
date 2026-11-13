/**
 * Transport form of a recovery ceremony: every envelope as standard base64, so
 * it crosses server functions and the database as plain text. Contains only
 * ciphertext; no factor, share or key. A ROUT Card shard (nfc_card) present
 * means version 2 (2-of-4); absent means version 1 (2-of-3).
 */
import type { CoreFactor, RecoveryCeremony } from "@/lib/crypto-enclave/recovery-mpc";

export type CeremonyWire = {
  ceremonyId: string;
  keyId: string;
  sealedMaster: string;
  shards: Record<CoreFactor, string> & { nfc_card?: string };
};

export const CEREMONY_ID_RE = /^[0-9a-f]{32}$/;
export const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
export const SHARD_B64_MAX = 6000;
export const MASTER_B64_MAX = 400;

/** Restores with the server's piece per member per hour (fail-closed). */
export const CEREMONY_RESTORES_PER_HOUR = 5;

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromB64(value: string): Uint8Array {
  if (!B64_RE.test(value)) throw new TypeError("invalid_base64");
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

export function ceremonyToWire(c: RecoveryCeremony, keyId: string): CeremonyWire {
  const core = { device_prf: toB64(c.shards.device_prf), paper_guardian: toB64(c.shards.paper_guardian), server_guardian: toB64(c.shards.server_guardian) };
  return {
    ceremonyId: c.ceremonyId,
    keyId,
    sealedMaster: toB64(c.sealedMaster),
    shards: c.version === 2 ? { ...core, nfc_card: toB64(c.shards.nfc_card) } : core,
  };
}

export function ceremonyFromWire(w: CeremonyWire, memberId: string): RecoveryCeremony {
  if (!CEREMONY_ID_RE.test(w.ceremonyId)) throw new TypeError("invalid_ceremony");
  const base = { ceremonyId: w.ceremonyId, memberId, threshold: 2 as const, sealedMaster: fromB64(w.sealedMaster) };
  const core = { device_prf: fromB64(w.shards.device_prf), paper_guardian: fromB64(w.shards.paper_guardian), server_guardian: fromB64(w.shards.server_guardian) };
  const card = w.shards.nfc_card;
  return card === undefined || card === null ? { ...base, version: 1, shards: core } : { ...base, version: 2, shards: { ...core, nfc_card: fromB64(card) } };
}

/** A stored ceremony as the version-aware reads (db/0266 *_v2) return it. */
export type CeremonyRow = {
  ceremony_id: string;
  key_id: string;
  sealed_master: string;
  device_shard: string;
  paper_shard: string;
  server_shard: string;
  card_shard: string | null;
  ceremony_version: number;
  device_credential: string;
};

/**
 * Wire form of a stored ceremony. A version 2 row must carry its card shard and
 * a version 1 row must not; anything else is refused rather than guessed, so a
 * 2-of-4 ceremony is never handed out (or opened) as 2-of-3.
 */
export function ceremonyRowToWire(r: CeremonyRow): CeremonyWire {
  const core = { device_prf: r.device_shard, paper_guardian: r.paper_shard, server_guardian: r.server_shard };
  const version = Number(r.ceremony_version);
  if (version === 1 && r.card_shard === null) return { ceremonyId: r.ceremony_id, keyId: r.key_id, sealedMaster: r.sealed_master, shards: core };
  if (version === 2 && typeof r.card_shard === "string" && r.card_shard.length > 0) {
    return { ceremonyId: r.ceremony_id, keyId: r.key_id, sealedMaster: r.sealed_master, shards: { ...core, nfc_card: r.card_shard } };
  }
  throw new TypeError("invalid_ceremony_row");
}

/** 2-of-3 (version 1) or 2-of-4 (version 2, with a ROUT Card shard). */
export const wireVersion = (w: CeremonyWire): 1 | 2 => (w.shards.nfc_card === undefined ? 1 : 2);

/** Number of words typed so far (for enabling a button; the words themselves are not kept). */
export function wordCount(text: string): number {
  const t = text.trim();
  return t ? t.split(/\s+/).length : 0;
}
