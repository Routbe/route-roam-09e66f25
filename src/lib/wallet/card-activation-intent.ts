/**
 * Marks that the member started "Activeer je ROUT Card" in this tab, so the
 * next tap on /t activates instead of only verifying. Holds only an expiry: no
 * code, card id or tap bytes. Five minutes, then it is ignored.
 */
const KEY = "rout-card-activation-intent";
export const ACTIVATION_INTENT_MS = 5 * 60 * 1000;

export function startActivationIntent(now = Date.now()): void {
  try {
    window.sessionStorage.setItem(KEY, String(now + ACTIVATION_INTENT_MS));
  } catch {
    /* storage blocked: the tap then only verifies */
  }
}

/** Reads and clears the intent; true only when it has not expired. */
export function takeActivationIntent(now = Date.now()): boolean {
  try {
    const raw = window.sessionStorage.getItem(KEY);
    window.sessionStorage.removeItem(KEY);
    const until = Number(raw);
    return Number.isFinite(until) && until > now && until - now <= ACTIVATION_INTENT_MS;
  } catch {
    return false;
  }
}
