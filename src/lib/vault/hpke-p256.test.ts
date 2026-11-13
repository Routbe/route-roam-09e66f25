// @vitest-environment node
import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";
import { HPKE_AEAD_AES128GCM, deriveKeyPairP256, hpkeOpen, hpkeSeal, parseStationPublicKey, stationFingerprint } from "@/lib/vault/hpke-p256";

const h = (s: string) => Uint8Array.from(s.replace(/\s+/g, "").match(/../g)!, (x) => Number.parseInt(x, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// RFC 9180 A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
const V = {
  info: h("4f6465206f6e2061204772656369616e2055726e"),
  ikmE: h("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"),
  pkEm: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
  ikmR: h("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550"),
  pkRm: "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
  skRm: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
  pt: h("4265617574792069732074727574682c20747275746820626561757479"),
  aad: h("436f756e742d30"),
  ct: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
};

describe("HPKE P-256 (RFC 9180)", () => {
  it("derives the RFC key pairs", () => {
    expect(hex(deriveKeyPairP256(V.ikmE).publicKey)).toBe(V.pkEm);
    const r = deriveKeyPairP256(V.ikmR);
    expect(hex(r.publicKey)).toBe(V.pkRm);
    expect(hex(r.secretKey)).toBe(V.skRm);
  });

  it("reproduces the RFC A.3.1 sequence-0 ciphertext and opens it", () => {
    const sealed = hpkeSeal(h(V.pkRm), V.info, V.aad, V.pt, { aead: HPKE_AEAD_AES128GCM, ikmE: V.ikmE });
    expect(hex(sealed.enc)).toBe(V.pkEm);
    expect(hex(sealed.ciphertext)).toBe(V.ct);
    expect(hpkeOpen(h(V.skRm), sealed.enc, V.info, V.aad, sealed.ciphertext, HPKE_AEAD_AES128GCM)).toEqual(V.pt);
  });

  it("round-trips with AES-256-GCM and fails on another info, aad or key", () => {
    const sk = p256.utils.randomSecretKey();
    const pk = p256.getPublicKey(sk, false);
    const s = hpkeSeal(pk, V.info, V.aad, V.pt);
    expect(hpkeOpen(sk, s.enc, V.info, V.aad, s.ciphertext)).toEqual(V.pt);
    expect(() => hpkeOpen(sk, s.enc, h("00"), V.aad, s.ciphertext)).toThrow();
    expect(() => hpkeOpen(sk, s.enc, V.info, h("00"), s.ciphertext)).toThrow();
    expect(() => hpkeOpen(p256.utils.randomSecretKey(), s.enc, V.info, V.aad, s.ciphertext)).toThrow();
    // A fresh ephemeral key every time.
    expect(hex(hpkeSeal(pk, V.info, V.aad, V.pt).enc)).not.toBe(hex(s.enc));
  });

  it("accepts a station key as PEM, base64 SPKI or raw hex, and rejects anything else", () => {
    const pk = h(V.pkRm);
    const der = new Uint8Array([...h("3059301306072a8648ce3d020106082a8648ce3d030107034200"), ...pk]);
    const b64 = btoa(String.fromCharCode(...der));
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64.slice(0, 64)}\n${b64.slice(64)}\n-----END PUBLIC KEY-----`;
    expect(parseStationPublicKey(pem)).toEqual(pk);
    expect(parseStationPublicKey(b64)).toEqual(pk);
    expect(parseStationPublicKey(V.pkRm)).toEqual(pk);
    const offCurve = V.pkRm.slice(0, -2) + (V.pkRm.endsWith("a0") ? "a1" : "a0");
    expect(() => parseStationPublicKey(offCurve)).toThrow();
    expect(() => parseStationPublicKey("hello")).toThrow();
    expect(stationFingerprint(pk)).toHaveLength(32);
  });
});
