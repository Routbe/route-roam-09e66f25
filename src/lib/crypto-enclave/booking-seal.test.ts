// @vitest-environment node
/**
 * Owner requirements 2026-11-13: booking titles, descriptions, notes and intake
 * answers are sealed in the browser with ML-KEM-1024 + X25519; no server-side
 * holder can open them; envelope sizes reveal only a fixed bucket.
 */
import { describe, expect, it } from "vitest";
import {
  BOOKING_PAD_BUCKETS,
  BookingSealError,
  bookingCommit,
  encodePayload,
  guestBookingKeys,
  guestFragment,
  hostBookingKeys,
  openBookingPayload,
  pad,
  parseGuestFragment,
  sealBookingPayload,
  unpad,
} from "./booking-seal";
import { EnvelopePolicyError, ENVELOPE_MIN_BYTES, generateRecipientKeys, openEnvelope, sealEnvelope } from "./pqc-envelope";

const HOST = "00000000-0000-4000-8000-0000000000a1";
const OTHER_HOST = "00000000-0000-4000-8000-0000000000a2";
const PAYLOAD_ID = "11111111-2222-4333-8444-555555555555";
const host = hostBookingKeys(new Uint8Array(32).fill(1));
const guestSeed = new Uint8Array(32).map((_, i) => i + 1);
const guest = guestBookingKeys(guestSeed);
const payload = { title: "Intake — Café Ünïcode", description: "Bespreking", note: "Graag ochtend", answers: [{ questionId: "q1", value: "ja" }] };

describe("zero-knowledge booking payloads", () => {
  const sealed = sealBookingPayload({ hostUserId: HOST, payloadId: PAYLOAD_ID, payload, hostPublicKey: host.publicKey, guestPublicKey: guest.publicKey });

  it("host and guest each open their own copy", () => {
    expect(openBookingPayload({ envelope: sealed.host, copy: "host", hostUserId: HOST, payloadId: PAYLOAD_ID, secretKey: host.secretKey })).toEqual(payload);
    expect(openBookingPayload({ envelope: sealed.guest!, copy: "guest", hostUserId: HOST, payloadId: PAYLOAD_ID, secretKey: guest.secretKey })).toEqual(payload);
  });

  it("uses the hybrid post-quantum envelope (RVE1 suite 1, 1600-byte ML-KEM-1024 + X25519 ciphertext)", () => {
    expect([...sealed.host.subarray(0, 4)]).toEqual([0x52, 0x56, 0x45, 0x31]);
    expect(sealed.host[4]).toBe(1);
    expect(sealed.host[5]).toBe(5); // bkh
    expect(sealed.guest![5]).toBe(6); // bkg
    expect(sealed.host.length).toBeGreaterThan(1600);
  });

  it("no server-side holder can open or seal a booking blob", () => {
    const server = generateRecipientKeys("server_vault");
    expect(() => sealEnvelope({ kind: "bkh", holder: "server_vault", recipientPublicKey: server.publicKey, plaintext: new Uint8Array(4), context: "x" })).toThrow(EnvelopePolicyError);
    expect(() => openEnvelope({ envelope: sealed.host, expectedKind: "bkh", holder: "server_vault", secretKey: server.secretKey, context: "x" })).toThrow(EnvelopePolicyError);
    expect(() => sealEnvelope({ kind: "bkg", holder: "member_device", recipientPublicKey: host.publicKey, plaintext: new Uint8Array(4), context: "x" })).toThrow(EnvelopePolicyError);
  });

  it("a copy never opens for another host, booking, role or key", () => {
    const other = { hostUserId: OTHER_HOST, payloadId: PAYLOAD_ID };
    expect(() => openBookingPayload({ envelope: sealed.host, copy: "host", ...other, secretKey: host.secretKey })).toThrow(BookingSealError);
    expect(() => openBookingPayload({ envelope: sealed.host, copy: "host", hostUserId: HOST, payloadId: "11111111-2222-4333-8444-555555555556", secretKey: host.secretKey })).toThrow(BookingSealError);
    expect(() => openBookingPayload({ envelope: sealed.host, copy: "guest", hostUserId: HOST, payloadId: PAYLOAD_ID, secretKey: guest.secretKey })).toThrow(BookingSealError);
    expect(() => openBookingPayload({ envelope: sealed.guest!, copy: "guest", hostUserId: HOST, payloadId: PAYLOAD_ID, secretKey: guestBookingKeys(new Uint8Array(32).fill(9)).secretKey })).toThrow(BookingSealError);
    const tampered = sealed.host.slice();
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
    expect(() => openBookingPayload({ envelope: tampered, copy: "host", hostUserId: HOST, payloadId: PAYLOAD_ID, secretKey: host.secretKey })).toThrow(BookingSealError);
  });

  it("envelope length reveals only the bucket: 1 character and 900 characters seal to the same size", () => {
    const a = sealBookingPayload({ hostUserId: HOST, payloadId: PAYLOAD_ID, payload: { title: "x" }, hostPublicKey: host.publicKey });
    const b = sealBookingPayload({ hostUserId: HOST, payloadId: PAYLOAD_ID, payload: { note: "y".repeat(900) }, hostPublicKey: host.publicKey });
    expect(a.host.length).toBe(b.host.length);
    expect(a.host.length).toBe(ENVELOPE_MIN_BYTES + BOOKING_PAD_BUCKETS[0]);
    const c = sealBookingPayload({ hostUserId: HOST, payloadId: PAYLOAD_ID, payload: { note: "z".repeat(3000) }, hostPublicKey: host.publicKey });
    expect(c.host.length).toBe(ENVELOPE_MIN_BYTES + BOOKING_PAD_BUCKETS[1]);
  });

  it("padding is strict: wrong size, overlong length or a non-zero pad byte is refused", () => {
    const p = pad(new Uint8Array([1, 2, 3]));
    expect(p.length).toBe(1024);
    expect([...unpad(p)]).toEqual([1, 2, 3]);
    expect(() => unpad(p.subarray(0, 1000))).toThrow(BookingSealError);
    const dirty = p.slice();
    dirty[900] = 1;
    expect(() => unpad(dirty)).toThrow(BookingSealError);
    const long = p.slice();
    new DataView(long.buffer).setUint32(0, 2000, false);
    expect(() => unpad(long)).toThrow(BookingSealError);
    // A short body stored in a larger bucket than needed is not canonical.
    const big = new Uint8Array(4096);
    new DataView(big.buffer).setUint32(0, 3, false);
    expect(() => unpad(big)).toThrow(BookingSealError);
  });

  it("refuses unknown fields, oversize text, duplicate questions and NUL bytes instead of dropping them", () => {
    for (const bad of [
      { title: "x", extra: 1 },
      { title: "t".repeat(201) },
      { answers: [{ questionId: "q", value: "a" }, { questionId: "q", value: "b" }] },
      { answers: [{ questionId: "bad id", value: "a" }] },
      { note: "a\u0000b" },
      { note: "n".repeat(4001) },
    ]) {
      expect(() => encodePayload(bad as never)).toThrow(BookingSealError);
    }
  });

  it("the ledger commitment covers the ciphertext of both copies", () => {
    expect(sealed.commit).toMatch(/^[0-9a-f]{64}$/);
    expect(bookingCommit(sealed.host, sealed.guest)).toBe(sealed.commit);
    expect(bookingCommit(sealed.host, null)).not.toBe(sealed.commit);
  });

  it("the guest seed round-trips through the manage-link fragment only", () => {
    const f = guestFragment(guestSeed);
    expect(f.startsWith("#bg1=")).toBe(true);
    expect([...parseGuestFragment(f)]).toEqual([...guestSeed]);
    expect(() => parseGuestFragment("#rk1=" + f.slice(5))).toThrow(BookingSealError);
    expect(() => guestBookingKeys(new Uint8Array(32))).toThrow(BookingSealError);
  });
});
