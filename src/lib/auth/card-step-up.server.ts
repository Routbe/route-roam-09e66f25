/**
 * Card tap as a step-up factor (db/0250). The dialog opens a single-use intent
 * (csu_ ref, HttpOnly cookie, 300 s); a verified tap of the member's own card
 * completes it, either read by the dialog itself (Web NFC on Android) or on
 * /t when the phone opens the tap URL (iPhone, other browsers, another device
 * signed in to the same account). Claiming the completed intent once turns it
 * into an ordinary signed step-up proof for the scope stored with the intent,
 * never a scope the browser asks for.
 */
import type { StepUpAction } from "./step-up-rules";

export const CARD_STEP_UP_COOKIE = "rout_card_stepup";
export const CARD_STEP_UP_TTL_SEC = 300;

export type CardStepUpStart = { status: "waiting"; expiresInSec: number } | { status: "no_card" } | { status: "limited" };
export type CardStepUpClaim = { status: "done" } | { status: "pending" } | { status: "none" };

/** Opens the intent when the member owns an active card and may use it for this action. */
export async function beginCardStepUp(userId: string, action: StepUpAction | undefined): Promise<CardStepUpStart> {
  const [{ enrolledFactors }, { allowedStepUpMethods }] = await Promise.all([import("./step-up.server"), import("./step-up-rules")]);
  if (!allowedStepUpMethods(await enrolledFactors(userId), action).includes("card")) return { status: "no_card" };
  const { vaultPort } = await import("@/lib/vault/vault-port.server");
  const scope = action === "card_reveal" || action === "card_lifecycle" ? action : "*";
  const intent = await vaultPort().beginCardStepUp({ userId }, scope).catch(() => null);
  if (!intent) return { status: "no_card" };
  const { writeResponseCookie } = await import("@/lib/request-context");
  writeResponseCookie(CARD_STEP_UP_COOKIE, intent, { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: CARD_STEP_UP_TTL_SEC });
  return { status: "waiting", expiresInSec: CARD_STEP_UP_TTL_SEC };
}

/** Claims this browser's completed intent once and issues the step-up proof for its stored scope. */
export async function claimCardStepUp(userId: string): Promise<CardStepUpClaim> {
  const { readRequestCookie, clearResponseCookie } = await import("@/lib/request-context");
  const { isCardStepUpIntent, vaultPort } = await import("@/lib/vault/vault-port.server");
  const raw = readRequestCookie(CARD_STEP_UP_COOKIE);
  if (!isCardStepUpIntent(raw)) return { status: "none" };
  const scope = await vaultPort().claimCardStepUp({ userId }, raw).catch(() => null);
  if (!scope) return { status: "pending" };
  clearResponseCookie(CARD_STEP_UP_COOKIE, { path: "/" });
  const { grantStepUp } = await import("./step-up.server");
  await grantStepUp(userId, "card", undefined, scope === "*" ? undefined : scope);
  return { status: "done" };
}
