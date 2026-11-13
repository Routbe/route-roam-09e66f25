/**
 * ROUT Card batches (admin) and member card activation (db/0246).
 * Admin calls need the admin role + 2FA (assertAdminRole) and are checked again
 * inside the vault functions. Key material never leaves the server.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

export const listCardBatchesFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { listSdmBatches } = await import("@/lib/vault/sdm-tap.server");
    return listSdmBatches(context.userId);
  });

export const createCardBatchFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ label: z.string().trim().min(1).max(80) }).strict().parse(d))
  .handler(async ({ data, context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { createSdmBatch, createSdmFleetKey } = await import("@/lib/vault/sdm-tap.server");
    const { vaultPort } = await import("@/lib/vault/vault-port.server");
    // One active fleet key serves every batch; it is created once, inside the server.
    const fleets = await vaultPort().sdmFleetKeys();
    const fleetId = fleets[0]?.fleetId ?? (await createSdmFleetKey(context.userId));
    const batchId = await createSdmBatch(context.userId, fleetId, data.label);
    return { batchId };
  });

export const exportCardBatchFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ batchId: z.string().uuid(), stationId: z.string().uuid() }).strict().parse(d))
  .handler(async ({ data, context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { getRequest, setResponseHeader } = await import("@tanstack/react-start/server");
    setResponseHeader("cache-control", "no-store");
    const { exportStationBundle } = await import("@/lib/vault/sdm-tap.server");
    // The tap URL is the canonical public origin; the request origin only as a fallback.
    const configured = process.env["PUBLIC_ORIGIN"];
    let origin = new URL(getRequest().url).origin;
    try {
      if (configured) origin = new URL(configured).origin;
    } catch {
      /* malformed PUBLIC_ORIGIN: keep the request origin */
    }
    // HPKE sealing happens here on the server; only ciphertext crosses the wire.
    return exportStationBundle(context.userId, data.batchId, data.stationId, origin);
  });

export const listCardStationsFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { listSdmStations } = await import("@/lib/vault/sdm-tap.server");
    return listSdmStations(context.userId);
  });

export const registerCardStationFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ label: z.string().trim().min(1).max(80), publicKey: z.string().min(64).max(600) }).strict().parse(d))
  .handler(async ({ data, context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { registerSdmStation } = await import("@/lib/vault/sdm-tap.server");
    try {
      return { ok: true as const, ...(await registerSdmStation(context.userId, data.label, data.publicKey)) };
    } catch {
      return { ok: false as const };
    }
  });

export const retireCardStationFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ stationId: z.string().uuid() }).strict().parse(d))
  .handler(async ({ data, context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { retireSdmStation } = await import("@/lib/vault/sdm-tap.server");
    return { ok: await retireSdmStation(context.userId, data.stationId) };
  });

const ManifestSchema = z
  .object({
    batchId: z.string().uuid(),
    cards: z
      .array(z.object({ uid: z.string().regex(/^[0-9A-Fa-f]{14}$/), activationCode: z.string().max(32).optional() }).strict())
      .min(1)
      .max(5000),
  })
  .strict();

export const importCardManifestFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => ManifestSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { assertAdminRole } = await import("@/lib/admin.server");
    await assertAdminRole(context.userId);
    const { listSdmBatches, importSdmManifest } = await import("@/lib/vault/sdm-tap.server");
    const batch = (await listSdmBatches(context.userId)).find((b) => b.batchId === data.batchId);
    if (!batch || batch.retiredAt) return { ok: false as const, imported: 0 };
    try {
      const imported = await importSdmManifest(context.userId, batch.fleetId, batch.batchId, data.cards);
      return { ok: true as const, imported };
    } catch {
      return { ok: false as const, imported: 0 };
    }
  });

export type CardActivationResult = { status: "activated" } | { status: "denied" } | { status: "limited" };

/** First tap of a new card while signed in: links the unclaimed card to the member. */
export const activateCardFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({ p: z.string().max(64), m: z.string().max(64), code: z.string().max(32).nullable().optional() }).strict().parse(d),
  )
  .handler(async ({ data, context }): Promise<CardActivationResult> => {
    const { setResponseHeader } = await import("@tanstack/react-start/server");
    setResponseHeader("cache-control", "no-store");
    const { hitRateLimit } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-activate", context.userId, { limit: 10, windowSec: 600 }, { failClosed: true }).catch(() => ({ ok: false }));
    if (!limit.ok) return { status: "limited" };
    try {
      const { activateMemberCard } = await import("@/lib/vault/sdm-tap.server");
      await activateMemberCard(context.userId, { p: data.p, m: data.m }, data.code ?? null);
      return { status: "activated" };
    } catch {
      return { status: "denied" };
    }
  });
