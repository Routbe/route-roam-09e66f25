/**
 * Zero-knowledge booking payloads (Phase B, owner requirements 2026-11-13).
 *
 * Title, description, guest note and intake answers are sealed in the browser
 * as RVE1 envelopes (pqc-envelope.ts: ML-KEM-1024 + X25519 hybrid KEM,
 * XChaCha20-Poly1305). There are two copies, each a separate envelope kind
 * whose key holder is fixed and never server-side:
 *
 *   bkh  host copy   sealed to the host's booking key (member_device). The
 *                    host's key seed is random and kept sealed under the
 *                    workspace key, which comes from the Master Key, so the
 *                    2-of-4 recovery also restores every booking.
 *   bkg  guest copy  sealed to a key derived from a 32-byte seed that lives
 *                    only in the guest's manage-link fragment (#bg1=…), which
 *                    browsers never send to a server.
 *
 * Both envelopes are bound by their context to the host, a client-chosen
 * payload id (the database ties it to exactly one booking) and the copy role,
 * so a blob moved to another booking, host or role never opens.
 *
 * Length hiding: the plaintext is a canonical encoding padded to one of three
 * fixed sizes (BOOKING_PAD_BUCKETS) before sealing, so an envelope's length
 * reveals only the bucket, never how long a title or an answer is.
 *
 * Every opening failure throws the same BookingSealError. Padded plaintext
 * buffers are wiped in `finally`.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { CardFactorError, parseCardFragment, toB64url } from "./card-factor";
import { generateRecipientKeys, openEnvelope, PUBLIC_KEY_BYTES, sealEnvelope, type RecipientKeys } from "./pqc-envelope";

export const BOOKING_PAYLOAD_VERSION = 1;
/** Padded plaintext sizes in bytes (4-byte length prefix included). */
export const BOOKING_PAD_BUCKETS = [1024, 4096, 16384] as const;
export const BOOKING_MAX_ENCODED = BOOKING_PAD_BUCKETS[BOOKING_PAD_BUCKETS.length - 1] - 4;
export const GUEST_FRAGMENT_PARAM = "bg1";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export class BookingSealError extends Error {
  constructor() {
    super("booking_payload_invalid");
    this.name = "BookingSealError";
  }
}

export type IntakeAnswer = { questionId: string; value: string };
export type BookingPayload = {
  title?: string;
  description?: string;
  note?: string;
  answers?: IntakeAnswer[];
};

const LIMITS = { title: 200, description: 4000, note: 4000, answers: 50, questionId: 64, value: 2000 } as const;

const wipe = (...a: (Uint8Array | undefined | null)[]) => {
  for (const x of a) x?.fill(0);
};

function checkText(v: unknown, max: number): string {
  if (typeof v !== "string" || Array.from(v).length > max || v.includes("\u0000")) throw new BookingSealError();
  return v.normalize("NFC");
}

/** Validates and normalises a payload; unknown keys are refused, not dropped. */
export function normalizePayload(p: BookingPayload): BookingPayload {
  if (typeof p !== "object" || p === null || Array.isArray(p)) throw new BookingSealError();
  for (const k of Object.keys(p)) if (!["title", "description", "note", "answers"].includes(k)) throw new BookingSealError();
  const out: BookingPayload = {};
  if (p.title !== undefined) out.title = checkText(p.title, LIMITS.title);
  if (p.description !== undefined) out.description = checkText(p.description, LIMITS.description);
  if (p.note !== undefined) out.note = checkText(p.note, LIMITS.note);
  if (p.answers !== undefined) {
    if (!Array.isArray(p.answers) || p.answers.length > LIMITS.answers) throw new BookingSealError();
    const seen = new Set<string>();
    out.answers = p.answers.map((a) => {
      if (typeof a !== "object" || a === null || Object.keys(a).sort().join(",") !== "questionId,value") throw new BookingSealError();
      const questionId = checkText(a.questionId, LIMITS.questionId);
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(questionId) || seen.has(questionId)) throw new BookingSealError();
      seen.add(questionId);
      return { questionId, value: checkText(a.value, LIMITS.value) };
    });
  }
  return out;
}

/** Canonical bytes: fixed key order, so one payload has exactly one encoding. */
export function encodePayload(p: BookingPayload): Uint8Array {
  const n = normalizePayload(p);
  const canonical = {
    v: BOOKING_PAYLOAD_VERSION,
    ...(n.title !== undefined ? { title: n.title } : {}),
    ...(n.description !== undefined ? { description: n.description } : {}),
    ...(n.note !== undefined ? { note: n.note } : {}),
    ...(n.answers !== undefined ? { answers: n.answers.map((a) => ({ questionId: a.questionId, value: a.value })) } : {}),
  };
  const bytes = enc.encode(JSON.stringify(canonical));
  if (bytes.length > BOOKING_MAX_ENCODED) {
    wipe(bytes);
    throw new BookingSealError();
  }
  return bytes;
}

export function decodePayload(bytes: Uint8Array): BookingPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(dec.decode(bytes));
  } catch {
    throw new BookingSealError();
  }
  if (typeof parsed !== "object" || parsed === null || (parsed as { v?: unknown }).v !== BOOKING_PAYLOAD_VERSION) throw new BookingSealError();
  const { v: _v, ...rest } = parsed as Record<string, unknown>;
  const payload = normalizePayload(rest as BookingPayload);
  // Round-trip: anything that is not the canonical encoding is refused.
  const again = encodePayload(payload);
  try {
    if (again.length !== bytes.length || again.some((b, i) => b !== bytes[i])) throw new BookingSealError();
  } finally {
    wipe(again);
  }
  return payload;
}

/** Smallest bucket that fits u32 length || bytes. */
export function bucketFor(length: number): number {
  const b = BOOKING_PAD_BUCKETS.find((size) => length + 4 <= size);
  if (b === undefined) throw new BookingSealError();
  return b;
}

export function pad(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bucketFor(bytes.length));
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

/** Strict unpad: exact bucket size, length in range, every pad byte zero. Returns a view. */
export function unpad(padded: Uint8Array): Uint8Array {
  if (!(BOOKING_PAD_BUCKETS as readonly number[]).includes(padded.length)) throw new BookingSealError();
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  if (len > padded.length - 4 || bucketFor(len) !== padded.length) throw new BookingSealError();
  let nonZero = 0;
  for (let i = 4 + len; i < padded.length; i++) nonZero |= padded[i] ?? 0;
  if (nonZero !== 0) throw new BookingSealError();
  return padded.subarray(4, 4 + len);
}

export type BookingCopy = "host" | "guest";
const KIND = { host: "bkh", guest: "bkg" } as const;
const HOLDER = { host: "member_device", guest: "booking_guest" } as const;

function context(hostUserId: string, payloadId: string, copy: BookingCopy): string {
  if (!UUID.test(hostUserId) || !UUID.test(payloadId)) throw new BookingSealError();
  return `rout.booking.payload.v${BOOKING_PAYLOAD_VERSION}|host=${hostUserId}|payload=${payloadId}|copy=${copy}`;
}

/** The host's booking key pair from its random 32-byte seed (kept sealed under the workspace key). */
export function hostBookingKeys(seed: Uint8Array): RecipientKeys {
  if (seed.length !== 32) throw new BookingSealError();
  return generateRecipientKeys("member_device", seed);
}

/** The guest's key pair from the 32-byte seed in their manage-link fragment. */
export function guestBookingKeys(seed: Uint8Array): RecipientKeys {
  if (seed.length !== 32 || seed.every((b) => b === 0)) throw new BookingSealError();
  return generateRecipientKeys("booking_guest", seed);
}

export function guestFragment(seed: Uint8Array): string {
  if (seed.length !== 32 || seed.every((b) => b === 0)) throw new BookingSealError();
  return `#${GUEST_FRAGMENT_PARAM}=${toB64url(seed)}`;
}

export function parseGuestFragment(fragment: string): Uint8Array {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const prefix = `${GUEST_FRAGMENT_PARAM}=`;
  if (!raw.startsWith(prefix)) throw new BookingSealError();
  // Same strict 32-byte base64url rule as the card fragment.
  try {
    return parseCardFragment(`rk1=${raw.slice(prefix.length)}`);
  } catch (e) {
    if (e instanceof CardFactorError) throw new BookingSealError();
    throw e;
  }
}
export type SealedBooking = { host: Uint8Array; guest: Uint8Array | null; commit: string };

/**
 * Seals one payload for the host and, when the guest has a link key, for the
 * guest. `commit` = SHA-256 over both envelopes: the value the ledger stores
 * instead of any field (crypto-shredding = deleting the envelopes).
 */
export function sealBookingPayload(input: {
  hostUserId: string;
  payloadId: string;
  payload: BookingPayload;
  hostPublicKey: Uint8Array;
  guestPublicKey?: Uint8Array;
}): SealedBooking {
  if (input.hostPublicKey.length !== PUBLIC_KEY_BYTES || (input.guestPublicKey && input.guestPublicKey.length !== PUBLIC_KEY_BYTES)) {
    throw new BookingSealError();
  }
  const body = encodePayload(input.payload);
  let padded: Uint8Array | null = null;
  try {
    padded = pad(body);
    const host = sealEnvelope({ kind: KIND.host, holder: HOLDER.host, recipientPublicKey: input.hostPublicKey, plaintext: padded, context: context(input.hostUserId, input.payloadId, "host") });
    const guest = input.guestPublicKey
      ? sealEnvelope({ kind: KIND.guest, holder: HOLDER.guest, recipientPublicKey: input.guestPublicKey, plaintext: padded, context: context(input.hostUserId, input.payloadId, "guest") })
      : null;
    return { host, guest, commit: bookingCommit(host, guest) };
  } finally {
    wipe(body, padded);
  }
}

/** Opens one copy with its holder's secret key. */
export function openBookingPayload(input: { envelope: Uint8Array; copy: BookingCopy; hostUserId: string; payloadId: string; secretKey: Uint8Array }): BookingPayload {
  let padded: Uint8Array | null = null;
  try {
    padded = openEnvelope({ envelope: input.envelope, expectedKind: KIND[input.copy], holder: HOLDER[input.copy], secretKey: input.secretKey, context: context(input.hostUserId, input.payloadId, input.copy) });
    return decodePayload(unpad(padded));
  } catch {
    throw new BookingSealError();
  } finally {
    wipe(padded);
  }
}

/** Ledger commitment over the ciphertext only (hex). */
export function bookingCommit(host: Uint8Array, guest: Uint8Array | null): string {
  const tag = enc.encode("rout.booking.detail.v2");
  const g = guest ?? new Uint8Array(0);
  const buf = new Uint8Array(tag.length + 4 + host.length + 4 + g.length);
  const view = new DataView(buf.buffer);
  let o = 0;
  buf.set(tag, o); o += tag.length;
  view.setUint32(o, host.length, false); o += 4;
  buf.set(host, o); o += host.length;
  view.setUint32(o, g.length, false); o += 4;
  buf.set(g, o);
  return Array.from(sha256(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}
