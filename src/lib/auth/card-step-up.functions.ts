/**
 * Server functions for the ROUT Card tap step-up (see card-step-up.server.ts).
 * All need a signed-in member; the proof is only ever issued server-side.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";
import type { CardStepUpClaim, CardStepUpStart } from "./card-step-up.server";

const actionInput = z.enum(["card_reveal", "card_lifecycle"]).optional();

async function noStore() {
  const { setResponseHeader } = await import("@tanstack/react-start/server");
  setResponseHeader("cache-control", "no-store");
}

/** Opens a card step-up for this browser (300 s). */
export const beginCardStepUpFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ action: actionInput }).strict().parse(d ?? {}))
  .handler(async ({ data, context }): Promise<CardStepUpStart> => {
    await noStore();
    const { hitRateLimit } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-step-up-begin", context.userId, { limit: 20, windowSec: 600 }, { failClosed: true }).catch(() => ({ ok: false }));
    if (!limit.ok) return { status: "limited" };
    const { beginCardStepUp } = await import("./card-step-up.server");
    return beginCardStepUp(context.userId, data.action);
  });

/** Polled by the dialog: done once the card was tapped (here, on /t or on another device). */
export const claimCardStepUpFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }): Promise<CardStepUpClaim> => {
    await noStore();
    const { claimCardStepUp } = await import("./card-step-up.server");
    return claimCardStepUp(context.userId);
  });

/** Web NFC (Android): the dialog read the tap itself and hands over the tap bytes. */
export const cardStepUpTapFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ p: z.string().max(64), m: z.string().max(64) }).strict().parse(d))
  .handler(async ({ data, context }): Promise<{ status: "done" | "denied" | "limited" }> => {
    await noStore();
    const { hitRateLimit } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-step-up-tap", context.userId, { limit: 10, windowSec: 600 }, { failClosed: true }).catch(() => ({ ok: false }));
    if (!limit.ok) return { status: "limited" };
    const { completeCardStepUpTap } = await import("@/lib/vault/sdm-tap.server");
    if (!(await completeCardStepUpTap(context.userId, data))) return { status: "denied" };
    const { claimCardStepUp } = await import("./card-step-up.server");
    return (await claimCardStepUp(context.userId)).status === "done" ? { status: "done" } : { status: "denied" };
  });
