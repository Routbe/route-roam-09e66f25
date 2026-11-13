/**
 * Booking ledger (db/0265) — pure, browser-safe verification.
 *
 * The database writes every change to a booking into a per-host hash chain:
 * entry_hash = SHA-256(prev_hash || UTF-8(preimage)), the first prev_hash being
 * SHA-256("rout.booking-ledger.v1|genesis|<host>"). The preimage is a
 * length-prefixed encoding ("n" for null, "v<len>:<value>"), counted in Unicode
 * code points exactly like Postgres char_length. The server signs
 * "rout.booking-ledger.v1.attest" || entry_hash with Ed25519.
 *
 * Trust comes only from public keys configured outside the database: a
 * signature by any other key, or a key listed in the database, proves nothing.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

export const LEDGER_TAG = "rout.booking-ledger.v1";
export const ATTEST_TAG = "rout.booking-ledger.v1.attest";

export const LEDGER_KINDS = [
  "imported", "created", "status_changed", "rescheduled", "updated", "transferred_in", "transferred_out", "deleted",
] as const;
export type LedgerKind = (typeof LEDGER_KINDS)[number];

export type LedgerEvent = {
  hostUserId: string;
  hostSeq: number;
  occurredAt: string;
  bookingId: string;
  groupId: string | null;
  eventTypeId: string;
  workspaceId: string | null;
  kind: LedgerKind;
  status: string;
  startUtc: string;
  endUtc: string;
  blockStartUtc: string;
  blockEndUtc: string;
  icsSequence: number;
  detailCommit: string | null;
  actorUserId: string | null;
};

/** Row shape returned by rout_booking_ledger_entries / _unsigned. */
export type LedgerRow = { host_seq: number | string; preimage: string; prev_hash: string; entry_hash: string };
export type AttestationRow = { host_seq: number | string; key_id: string; signature: string };

const enc = new TextEncoder();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const HEX32 = /^[0-9a-f]{64}$/;

export class LedgerFormatError extends Error {}

/** Same encoding as public.rout_ledger_field. */
export function field(value: string | null): string {
  return value === null ? "n" : `v${Array.from(value).length}:${value}`;
}

export function encodePreimage(e: LedgerEvent): string {
  return LEDGER_TAG + [
    e.hostUserId, String(e.hostSeq), e.occurredAt, e.bookingId, e.groupId, e.eventTypeId, e.workspaceId,
    e.kind, e.status, e.startUtc, e.endUtc, e.blockStartUtc, e.blockEndUtc, String(e.icsSequence), e.detailCommit, e.actorUserId,
  ].map(field).join("");
}

/** Strict parser: any byte that does not fit the format is refused. */
export function parsePreimage(preimage: string): LedgerEvent {
  if (!preimage.startsWith(LEDGER_TAG)) throw new LedgerFormatError("tag");
  const cps = Array.from(preimage.slice(LEDGER_TAG.length));
  let i = 0;
  const out: (string | null)[] = [];
  while (i < cps.length) {
    const c = cps[i++];
    if (c === "n") { out.push(null); continue; }
    if (c !== "v") throw new LedgerFormatError("field");
    let len = "";
    while (i < cps.length && /[0-9]/.test(cps[i]!)) len += cps[i++];
    if (!len || (len.length > 1 && len.startsWith("0")) || cps[i++] !== ":") throw new LedgerFormatError("length");
    const n = Number(len);
    if (i + n > cps.length) throw new LedgerFormatError("truncated");
    out.push(cps.slice(i, i + n).join(""));
    i += n;
  }
  if (out.length !== 16) throw new LedgerFormatError("arity");
  const [host, seq, at, booking, group, type, ws, kind, status, s, e, bs, be, icsSeq, commit, actor] = out;
  const need = (v: string | null, re: RegExp, what: string) => {
    if (v === null || !re.test(v)) throw new LedgerFormatError(what);
    return v;
  };
  const opt = (v: string | null, re: RegExp, what: string) => (v === null ? null : need(v, re, what));
  if (!LEDGER_KINDS.includes(kind as LedgerKind)) throw new LedgerFormatError("kind");
  const event: LedgerEvent = {
    hostUserId: need(host, UUID, "host"),
    hostSeq: Number(need(seq, /^[1-9][0-9]{0,17}$/, "seq")),
    occurredAt: need(at, TS, "occurred_at"),
    bookingId: need(booking, UUID, "booking"),
    groupId: opt(group, UUID, "group"),
    eventTypeId: need(type, UUID, "event_type"),
    workspaceId: opt(ws, UUID, "workspace"),
    kind: kind as LedgerKind,
    status: need(status, /^[a-z_]{1,32}$/, "status"),
    startUtc: need(s, TS, "start"),
    endUtc: need(e, TS, "end"),
    blockStartUtc: need(bs, TS, "block_start"),
    blockEndUtc: need(be, TS, "block_end"),
    icsSequence: Number(need(icsSeq, /^(0|[1-9][0-9]{0,9})$/, "ics_sequence")),
    detailCommit: opt(commit, HEX32, "detail_commit"),
    actorUserId: opt(actor, UUID, "actor"),
  };
  // Round-trip: one event has exactly one encoding.
  if (encodePreimage(event) !== preimage) throw new LedgerFormatError("non_canonical");
  if ((event.kind === "deleted" || event.kind === "transferred_out") !== (event.detailCommit === null)) {
    throw new LedgerFormatError("detail_commit");
  }
  return event;
}

export function genesisHash(hostUserId: string): Uint8Array {
  return sha256(enc.encode(`${LEDGER_TAG}|genesis|${hostUserId}`));
}

export function entryHash(prevHash: Uint8Array, preimage: string): Uint8Array {
  const body = enc.encode(preimage);
  const buf = new Uint8Array(prevHash.length + body.length);
  buf.set(prevHash, 0);
  buf.set(body, prevHash.length);
  return sha256(buf);
}

export function attestationMessage(entryHashBytes: Uint8Array): Uint8Array {
  const tag = enc.encode(ATTEST_TAG);
  const out = new Uint8Array(tag.length + entryHashBytes.length);
  out.set(tag, 0);
  out.set(entryHashBytes, tag.length);
  return out;
}

/** key_id = first 16 bytes of SHA-256(public key), hex. */
export function ledgerKeyId(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey)).slice(0, 32);
}

export function signEntry(secretKey: Uint8Array, entryHashHex: string): string {
  return bytesToHex(ed25519.sign(attestationMessage(hexToBytes(entryHashHex)), secretKey));
}

export function verifyEntrySignature(publicKey: Uint8Array, entryHashHex: string, signatureHex: string): boolean {
  if (!HEX32.test(entryHashHex) || !/^[0-9a-f]{128}$/.test(signatureHex)) return false;
  try {
    return ed25519.verify(hexToBytes(signatureHex), attestationMessage(hexToBytes(entryHashHex)), publicKey);
  } catch {
    return false;
  }
}

export type ChainProblem =
  | "format" | "host" | "seq_gap" | "prev_hash" | "entry_hash" | "clock" | "hex";

export type LedgerVerdict = {
  ok: boolean;
  entries: number;
  /** First event whose link, hash, order or format is wrong. */
  broken: { seq: number; problem: ChainProblem } | null;
  /** Events without a valid signature from a trusted key. */
  unsigned: number[];
  /** Events carrying a signature by a trusted key id that does not verify. */
  forged: number[];
  headHash: string;
  events: LedgerEvent[];
};

/**
 * Verifies a complete chain from genesis. `trustedKeys` maps key_id → public
 * key; signatures under other key ids are ignored.
 */
export function verifyLedger(
  hostUserId: string,
  rows: readonly LedgerRow[],
  attestations: readonly AttestationRow[],
  trustedKeys: ReadonlyMap<string, Uint8Array>,
): LedgerVerdict {
  const sigs = new Map<number, AttestationRow[]>();
  for (const a of attestations) {
    const seq = Number(a.host_seq);
    sigs.set(seq, [...(sigs.get(seq) ?? []), a]);
  }
  let prev = genesisHash(hostUserId);
  let lastAt = "";
  const events: LedgerEvent[] = [];
  const unsigned: number[] = [];
  const forged: number[] = [];
  const fail = (seq: number, problem: ChainProblem): LedgerVerdict => ({
    ok: false, entries: events.length, broken: { seq, problem }, unsigned, forged, headHash: bytesToHex(prev), events,
  });
  const ordered = [...rows].sort((a, b) => Number(a.host_seq) - Number(b.host_seq));
  for (let i = 0; i < ordered.length; i++) {
    const row = ordered[i]!;
    const seq = Number(row.host_seq);
    if (seq !== i + 1) return fail(seq, "seq_gap");
    if (!HEX32.test(row.prev_hash) || !HEX32.test(row.entry_hash)) return fail(seq, "hex");
    let ev: LedgerEvent;
    try {
      ev = parsePreimage(row.preimage);
    } catch {
      return fail(seq, "format");
    }
    if (ev.hostUserId !== hostUserId) return fail(seq, "host");
    if (ev.hostSeq !== seq) return fail(seq, "seq_gap");
    if (row.prev_hash !== bytesToHex(prev)) return fail(seq, "prev_hash");
    const h = entryHash(prev, row.preimage);
    if (bytesToHex(h) !== row.entry_hash) return fail(seq, "entry_hash");
    if (ev.occurredAt < lastAt) return fail(seq, "clock");
    let signed = false;
    for (const a of sigs.get(seq) ?? []) {
      const key = trustedKeys.get(a.key_id);
      if (!key) continue;
      if (verifyEntrySignature(key, row.entry_hash, a.signature)) signed = true;
      else forged.push(seq);
    }
    if (!signed) unsigned.push(seq);
    events.push(ev);
    prev = h;
    lastAt = ev.occurredAt;
  }
  return { ok: forged.length === 0, entries: events.length, broken: null, unsigned, forged, headHash: bytesToHex(prev), events };
}

export type UnsignedRow = LedgerRow & { prev_signature: string | null };

export type SignPlan =
  | { ok: true; signatures: { seq: number; signature: string }[] }
  | { ok: false; seq: number; problem: ChainProblem | "unsigned_predecessor" };

/**
 * Decides what the signer may sign for one host. It only extends from genesis
 * or from a predecessor carrying a valid signature of its own key, and checks
 * every link and hash on the way. One wrong byte: nothing is signed.
 */
export function planSignatures(
  hostUserId: string,
  rows: readonly UnsignedRow[],
  secretKey: Uint8Array,
): SignPlan {
  const publicKey = ed25519.getPublicKey(secretKey);
  const ordered = [...rows].sort((a, b) => Number(a.host_seq) - Number(b.host_seq));
  const signatures: { seq: number; signature: string }[] = [];
  let prev: string | null = null;
  let lastAt = "";
  for (const row of ordered) {
    const seq = Number(row.host_seq);
    if (!HEX32.test(row.prev_hash) || !HEX32.test(row.entry_hash)) return { ok: false, seq, problem: "hex" };
    if (prev === null) {
      if (seq === 1) {
        if (row.prev_hash !== bytesToHex(genesisHash(hostUserId))) return { ok: false, seq, problem: "prev_hash" };
      } else if (!row.prev_signature || !verifyEntrySignature(publicKey, row.prev_hash, row.prev_signature)) {
        return { ok: false, seq, problem: "unsigned_predecessor" };
      }
    } else if (row.prev_hash !== prev) {
      return { ok: false, seq, problem: "prev_hash" };
    }
    if (prev !== null && seq !== signatures[signatures.length - 1]!.seq + 1) return { ok: false, seq, problem: "seq_gap" };
    let ev: LedgerEvent;
    try {
      ev = parsePreimage(row.preimage);
    } catch {
      return { ok: false, seq, problem: "format" };
    }
    if (ev.hostUserId !== hostUserId) return { ok: false, seq, problem: "host" };
    if (ev.hostSeq !== seq) return { ok: false, seq, problem: "seq_gap" };
    if (bytesToHex(entryHash(hexToBytes(row.prev_hash), row.preimage)) !== row.entry_hash) {
      return { ok: false, seq, problem: "entry_hash" };
    }
    if (ev.occurredAt < lastAt) return { ok: false, seq, problem: "clock" };
    signatures.push({ seq, signature: signEntry(secretKey, row.entry_hash) });
    prev = row.entry_hash;
    lastAt = ev.occurredAt;
  }
  return { ok: true, signatures };
}
