// @vitest-environment node
import "fake-indexeddb/auto";
import { it } from "vitest";
import { serverFactorPublicKey } from "@/lib/recovery/server-factor.server";
import { runEnclaveOp } from "./enclave-core";
import { factorKeys, paperFactorKeys, recoverMasterKey, type RecoveryCeremony } from "./recovery-mpc";
const SECRET = "A".repeat(32) + "b".repeat(32);
it("dbg", async () => {
  const userId = "00000000-0000-4000-8000-0000000000e1";
  const card = new Uint8Array(32).fill(3);
  const b: any = (await runEnclaveOp("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET), cardSecret: card } as any) as any).result;
  const words = b.paperWords.split(" ");
  await runEnclaveOp("ceremony.checkWords", { handle: b.handle, answers: b.checkPositions.map((position: number) => ({ position, word: words[position - 1] })) });
  const s: any = (await runEnclaveOp("ceremony.sealDevice", { handle: b.handle, prf: new Uint8Array(32).fill(6) }) as any).result;
  const c = s.ceremony as RecoveryCeremony;
  console.log("DBG version", c.version, Object.keys(c.shards), c.sealedMaster.length, Object.values(c.shards).map((x: any) => x.length));
  try {
    const m = await recoverMasterKey({ ceremony: c, memberId: userId, factorSecretKeys: { device_prf: factorKeys("device_prf", new Uint8Array(32).fill(6), userId).secretKey, paper_guardian: paperFactorKeys(b.paperWords, userId).secretKey } });
    console.log("DBG ok", m.length);
  } catch (e) { console.log("DBG fail", e); }
  const c2 = await runEnclaveOp("ceremony.commit", { handle: b.handle, userId });
  console.log("DBG commit", JSON.stringify(c2).slice(0,100));
  const { forgetDeviceKey } = await import("@/lib/e2ee/device-key");
  await forgetDeviceKey(userId);
  const r = await runEnclaveOp("ceremony.restore", { userId, ceremony: c, keyId: (c2 as any).result.keyId, prf: new Uint8Array(32).fill(6), paperWords: b.paperWords });
  console.log("DBG restore", JSON.stringify(r));
});
