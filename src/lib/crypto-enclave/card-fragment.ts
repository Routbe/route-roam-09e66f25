/**
 * ROUT Card recovery fragment `#rk1=<43 base64url chars>`: parsing only, no
 * keys. Browser-safe and free of the enclave core, so /t and the Web NFC
 * reader can lift the 32-byte secret off a tap and hand it straight to the
 * crypto worker (card-factor.ts derives the factor keys there).
 *
 * The returned secret is a fresh buffer the caller must wipe.
 */
export const CARD_FRAGMENT_PARAM = "rk1";
export const CARD_SECRET_BYTES = 32;
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
  if (secret.length !== CARD_SECRET_BYTES || secret.every((b) => b === 0)) {
    secret.fill(0);
    throw new CardFactorError();
  }
  return secret;
}

/** The fragment a personalisation station writes after the SUN template. */
export function cardFragment(secret: Uint8Array): string {
  if (secret.length !== CARD_SECRET_BYTES || secret.every((b) => b === 0)) throw new CardFactorError();
  return `#${CARD_FRAGMENT_PARAM}=${toB64url(secret)}`;
}

/** The card secret from a full tap URL (or null when it carries no valid fragment). */
export function cardSecretFromUrl(url: string | null | undefined): Uint8Array | null {
  if (!url || url.length > 512) return null;
  const hash = url.indexOf("#");
  if (hash < 0) return null;
  try {
    return parseCardFragment(url.slice(hash));
  } catch {
    return null;
  }
}
