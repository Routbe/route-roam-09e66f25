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
import { CARD_SECRET_BYTES, CardFactorError, parseCardFragment } from "./card-fragment";

export { CARD_FRAGMENT_PARAM, CardFactorError, cardFragment, cardSecretFromUrl, parseCardFragment, toB64url } from "./card-fragment";

/** Factor key pair of a card for one member (bound to the member id like every factor). */
export function cardFactorKeys(secret: Uint8Array, memberId: string): RecipientKeys {
  if (secret.length !== CARD_SECRET_BYTES) throw new CardFactorError();
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
