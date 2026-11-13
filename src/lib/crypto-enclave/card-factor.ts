/**
 * ROUT Card recovery factor (nfc_card, ceremony version 2).
 *
 * Split knowledge: the card's NDEF tap URL carries, after its SUN part, a
 * fragment `#rk1=<43 base64url chars>` holding 32 random bytes written at
 * personalisation and never stored by ROUT. Browsers never send a fragment to
 * a server (neither Web NFC on Android nor Safari opening /t on iPhone), so the
 * factor key below can only be derived on a device that has just read the
 * card. The SUN part (PICCData + CMAC) stays the server's live-tap proof; the
 * server can verify taps but can never derive this factor, so ROUT's own
 * factor plus the card gate never add up to two shares.
 *
 * The fragment secret is held in a fresh buffer the caller must wipe; the
 * returned keys' `secretKey` is the caller's to wipe too.
 */
import { factorKeys } from "./recovery-mpc";
import type { RecipientKeys } from "./pqc-envelope";

export const CARD_FRAGMENT_PARAM = "rk1";
const SECRET_BYTES = 32;
const B64URL_43 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/; // 43 chars encoding exactly 32 bytes (last char has 2 zero pad bits)

export class CardFactorError extends Error {
  constructor() {
    super("card_factor_invalid");
    this.name = "CardFactorError";
  }
}

function fromB64url(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toB64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Strictly parses a tap URL fragment (with or without the leading "#").
 * Exactly one parameter, exactly `rk1`, exactly 32 bytes, and not all zero:
 * anything else is refused with the same error.
 */
export function parseCardFragment(fragment: string): Uint8Array {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const prefix = `${CARD_FRAGMENT_PARAM}=`;
  if (!raw.startsWith(prefix)) throw new CardFactorError();
  const value = raw.slice(prefix.length);
  if (!B64URL_43.test(value)) throw new CardFactorError();
  const secret = fromB64url(value);
  if (secret.length !== SECRET_BYTES || secret.every((b) => b === 0)) {
    secret.fill(0);
    throw new CardFactorError();
  }
  return secret;
}

/** The fragment a personalisation station writes after the SUN template. */
export function cardFragment(secret: Uint8Array): string {
  if (secret.length !== SECRET_BYTES || secret.every((b) => b === 0)) throw new CardFactorError();
  return `#${CARD_FRAGMENT_PARAM}=${toB64url(secret)}`;
}

/** Factor key pair of a card for one member (bound to the member id like every factor). */
export function cardFactorKeys(secret: Uint8Array, memberId: string): RecipientKeys {
  if (secret.length !== SECRET_BYTES) throw new CardFactorError();
  return factorKeys("nfc_card", secret, memberId);
}

/** Parses a fragment and derives the card factor keys; wipes the parsed secret. */
export function cardFactorKeysFromFragment(fragment: string, memberId: string): RecipientKeys {
  const secret = parseCardFragment(fragment);
  try {
    return cardFactorKeys(secret, memberId);
  } finally {
    secret.fill(0);
  }
}
