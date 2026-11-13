/**
 * HPKE (RFC 9180), base mode, single-shot: DHKEM(P-256, HKDF-SHA256),
 * HKDF-SHA256 and AES-GCM. Used to wrap ROUT Card batch keys for exactly one
 * personalisation station. Verified against the RFC 9180 A.3.1 test vector.
 *
 * Only the sender (seal) runs in ROUT; `open` exists for tests and for a
 * reference station implementation.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const HPKE_KEM_P256 = 0x0010;
export const HPKE_KDF_SHA256 = 0x0001;
export const HPKE_AEAD_AES128GCM = 0x0001;
export const HPKE_AEAD_AES256GCM = 0x0002;
export type HpkeAead = typeof HPKE_AEAD_AES128GCM | typeof HPKE_AEAD_AES256GCM;

const enc = new TextEncoder();
const VERSION = enc.encode("HPKE-v1");
const i2osp = (n: number, len: number) => {
  const out = new Uint8Array(len);
  for (let i = len - 1, v = n; i >= 0; i--, v >>>= 8) out[i] = v & 0xff;
  return out;
};
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const KEM_SUITE = cat(enc.encode("KEM"), i2osp(HPKE_KEM_P256, 2));
const hpkeSuite = (aead: HpkeAead) => cat(enc.encode("HPKE"), i2osp(HPKE_KEM_P256, 2), i2osp(HPKE_KDF_SHA256, 2), i2osp(aead, 2));

const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) =>
  extract(sha256, cat(VERSION, suite, enc.encode(label), ikm), salt);
const labeledExpand = (suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, len: number) =>
  expand(sha256, prk, cat(i2osp(len, 2), VERSION, suite, enc.encode(label), info), len);

/** Strict uncompressed SEC1 P-256 public key (65 bytes, on the curve, not identity). */
export function assertP256PublicKey(pk: Uint8Array): void {
  if (pk.length !== 65 || pk[0] !== 0x04 || !p256.utils.isValidPublicKey(pk, false)) throw new TypeError("hpke_bad_public_key");
}

/** RFC 9180 7.1.3 DeriveKeyPair for P-256 (bitmask 0xff). */
export function deriveKeyPairP256(ikm: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const prk = labeledExtract(KEM_SUITE, new Uint8Array(0), "dkp_prk", ikm);
  for (let counter = 0; counter < 256; counter++) {
    const sk = labeledExpand(KEM_SUITE, prk, "candidate", i2osp(counter, 1), 32);
    if (p256.utils.isValidSecretKey(sk)) return { secretKey: sk, publicKey: p256.getPublicKey(sk, false) };
    sk.fill(0);
  }
  throw new Error("hpke_derive_key_pair_failed");
}

function dh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  const point = p256.getSharedSecret(sk, pk, true); // 0x02/0x03 || x
  const x = point.slice(1, 33);
  point.fill(0);
  return x;
}

function sharedSecret(dhValue: Uint8Array, encapsulated: Uint8Array, pkR: Uint8Array): Uint8Array {
  const prk = labeledExtract(KEM_SUITE, new Uint8Array(0), "eae_prk", dhValue);
  try {
    return labeledExpand(KEM_SUITE, prk, "shared_secret", cat(encapsulated, pkR), 32);
  } finally {
    prk.fill(0);
  }
}

function keySchedule(aead: HpkeAead, shared: Uint8Array, info: Uint8Array) {
  const suite = hpkeSuite(aead);
  const empty = new Uint8Array(0);
  const context = cat(Uint8Array.of(0x00), labeledExtract(suite, empty, "psk_id_hash", empty), labeledExtract(suite, empty, "info_hash", info));
  const secret = labeledExtract(suite, shared, "secret", empty);
  try {
    return {
      key: labeledExpand(suite, secret, "key", context, aead === HPKE_AEAD_AES256GCM ? 32 : 16),
      nonce: labeledExpand(suite, secret, "base_nonce", context, 12),
    };
  } finally {
    secret.fill(0);
  }
}

export type HpkeSealed = { enc: Uint8Array; ciphertext: Uint8Array };

/**
 * Single-shot seal (sequence 0) to `pkR`. `ikmE` is only for test vectors;
 * production always draws a fresh ephemeral key.
 */
export function hpkeSeal(
  pkR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  opts: { aead?: HpkeAead; ikmE?: Uint8Array } = {},
): HpkeSealed {
  assertP256PublicKey(pkR);
  const aead = opts.aead ?? HPKE_AEAD_AES256GCM;
  const eph = opts.ikmE ? deriveKeyPairP256(opts.ikmE) : (() => {
    const secretKey = p256.utils.randomSecretKey();
    return { secretKey, publicKey: p256.getPublicKey(secretKey, false) };
  })();
  const dhValue = dh(eph.secretKey, pkR);
  eph.secretKey.fill(0);
  const shared = sharedSecret(dhValue, eph.publicKey, pkR);
  dhValue.fill(0);
  const { key, nonce } = keySchedule(aead, shared, info);
  shared.fill(0);
  try {
    return { enc: eph.publicKey, ciphertext: gcm(key, nonce, aad).encrypt(plaintext) };
  } finally {
    key.fill(0);
    nonce.fill(0);
  }
}

/** Single-shot open (sequence 0) with the recipient secret key. */
export function hpkeOpen(skR: Uint8Array, encapsulated: Uint8Array, info: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, aead: HpkeAead = HPKE_AEAD_AES256GCM): Uint8Array {
  assertP256PublicKey(encapsulated);
  const pkR = p256.getPublicKey(skR, false);
  const dhValue = dh(skR, encapsulated);
  const shared = sharedSecret(dhValue, encapsulated, pkR);
  dhValue.fill(0);
  const { key, nonce } = keySchedule(aead, shared, info);
  shared.fill(0);
  try {
    return gcm(key, nonce, aad).decrypt(ciphertext);
  } finally {
    key.fill(0);
    nonce.fill(0);
  }
}

/** SPKI DER prefix of an id-ecPublicKey / prime256v1 key with an uncompressed point. */
const P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

/**
 * Accepts a station public key as PEM ("BEGIN PUBLIC KEY", SPKI), base64 SPKI,
 * or hex of the raw 65-byte point. Returns the validated raw point.
 */
export function parseStationPublicKey(input: string): Uint8Array {
  const text = input.trim();
  let bytes: Uint8Array;
  if (/^(04)?[0-9a-fA-F]{128}$/.test(text) && text.length === 130) {
    bytes = Uint8Array.from(text.match(/../g)!, (h) => Number.parseInt(h, 16));
  } else {
    const b64 = text.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length > 400) throw new TypeError("hpke_bad_public_key");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    if (der.length !== 91 || P256_SPKI_PREFIX.some((b, i) => der[i] !== b)) throw new TypeError("hpke_bad_public_key");
    bytes = der.slice(26);
  }
  assertP256PublicKey(bytes);
  return bytes;
}

/** SHA-256 over the raw point: what the admin compares with the station's display. */
export function stationFingerprint(pk: Uint8Array): Uint8Array {
  assertP256PublicKey(pk);
  return sha256(pk);
}
