/**
 * Public ROUT Card tap check (/t). No session needed: the card proves itself
 * with a live NTAG 424 DNA SUN tap (sdm-tap.server.ts). Rate limited fail-closed
 * per IP; every denial looks the same and nothing about the card's owner is returned.
 * A signed-in member with an open card step-up (db/0250) confirms that step-up
 * only by choosing purpose "step_up" on /t after seeing the question; only their
 * own card can do so. A plain tap never completes a step-up.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { optionalAuth } from "@/lib/auth/middleware";
import { cardTapRoute } from "@/lib/wallet/card-tap-url";

export type CardTapResult =
  | { status: "verified"; activated: boolean }
  | { status: "step_up_confirmed" }
  | { status: "step_up_denied" }
  | { status: "denied" }
  | { status: "limited" };

export const verifyCardTapFn = createServerFn({ method: "POST" })
  .middleware([optionalAuth])
  .inputValidator((d: unknown) =>
    z.object({ p: z.string().max(64), m: z.string().max(64), purpose: z.enum(["proof", "step_up"]).default("proof") }).strict().parse(d),
  )
  .handler(async ({ data, context }): Promise<CardTapResult> => {
    const { getRequest, setResponseHeader } = await import("@tanstack/react-start/server");
    setResponseHeader("cache-control", "no-store");
    const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-tap", clientIp(getRequest()), { limit: 20, windowSec: 60 }, { failClosed: true }).catch(() => ({ ok: false }));
    if (!limit.ok) return { status: "limited" };
    const route = cardTapRoute(data.purpose, !!context.userId);
    if (route === "refuse") return { status: "step_up_denied" };
    const tap = { p: data.p, m: data.m };
    if (route === "step_up" && context.userId) {
      const { completeCardStepUpTap } = await import("@/lib/vault/sdm-tap.server");
      return { status: (await completeCardStepUpTap(context.userId, tap)) ? "step_up_confirmed" : "step_up_denied" };
    }
    try {
      const { publicCardProof } = await import("@/lib/vault/sdm-tap.server");
      const state = await publicCardProof(tap);
      return { status: "verified", activated: state === "active" };
    } catch {
      return { status: "denied" };
    }
  });

/** /t asks this before using a tap: does the signed-in member have an open card step-up? Reads no tap. */
export const pendingCardStepUpFn = createServerFn({ method: "POST" })
  .middleware([optionalAuth])
  .handler(async ({ context }): Promise<{ pending: boolean }> => {
    const { setResponseHeader } = await import("@tanstack/react-start/server");
    setResponseHeader("cache-control", "no-store");
    if (!context.userId) return { pending: false };
    const { vaultPort } = await import("@/lib/vault/vault-port.server");
    return { pending: await vaultPort().pendingCardStepUp({ userId: context.userId }).catch(() => false) };
  });
