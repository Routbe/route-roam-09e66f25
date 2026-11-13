// @vitest-environment node
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { forgetDeviceKey, loadDeviceKey } from "@/lib/e2ee/device-key";
import { newMasterKey } from "@/lib/e2ee/recovery";
import { openServerShard, serverFactorPublicKey } from "@/lib/recovery/server-factor.server";
import { runEnclaveOp } from "./enclave-core";
import type { EnclaveOp, EnclaveOps } from "./protocol";
import type { RecoveryCeremony } from "./recovery-mpc";

const SECRET = "A".repeat(32) + "b".repeat(32);
const prfOf = (n: number) => new Uint8Array(32).fill(n);

async function call<K extends EnclaveOp>(op: K, args: EnclaveOps[K]["req"]): Promise<EnclaveOps[K]["res"]> {
  const r = await runEnclaveOp(op, args);
  if (!r.ok) throw new Error(r.code);
  return r.result as EnclaveOps[K]["res"];
}
const code = async (op: EnclaveOp, args: unknown) => {
  const r = await runEnclaveOp(op, args);
  return r.ok ? "ok" : r.code;
};

/** Runs a full setup and returns what the server would store plus the paper words. */
async function setup(userId: string, mnemonic?: string) {
  const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET), ...(mnemonic ? { mnemonic } : {}) });
  const words = begun.paperWords.split(" ");
  const answers = begun.checkPositions.map((position) => ({ position, word: words[position - 1] ?? "" }));
  expect((await call("ceremony.checkWords", { handle: begun.handle, answers })).ok).toBe(true);
  const sealed = await call("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(5) });
  const committed = await call("ceremony.commit", { handle: begun.handle, userId });
  return { begun, ceremony: sealed.ceremony as RecoveryCeremony, keyId: committed.keyId, paper: begun.paperWords };
}

describe("2-of-3 ceremony in the crypto enclave", () => {
  it("a device without a key gets a fresh Master Key, installed only at commit", async () => {
    const userId = "00000000-0000-4000-8000-0000000000c1";
    const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET) });
    expect(begun.fresh).toBe(true);
    expect(begun.paperWords.split(" ")).toHaveLength(24);
    expect(new Set(begun.checkPositions).size).toBe(3);
    expect(begun.checkPositions.every((p) => p >= 1 && p <= 24)).toBe(true);
    expect(await loadDeviceKey(userId)).toBeNull();
    await call("ceremony.discard", { handle: begun.handle });
    expect(await loadDeviceKey(userId)).toBeNull();
  });

  it("the passkey cannot seal before three words were retyped correctly", async () => {
    const userId = "00000000-0000-4000-8000-0000000000c2";
    const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET) });
    expect(await code("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(1) })).toBe("invalid_input");
    const wrong = begun.checkPositions.map((position) => ({ position, word: "abandon" }));
    expect((await call("ceremony.checkWords", { handle: begun.handle, answers: wrong })).ok).toBe(false);
    for (let i = 0; i < 4; i++) await call("ceremony.checkWords", { handle: begun.handle, answers: wrong });
    // Fifth failure: the ceremony is gone.
    expect(await code("ceremony.checkWords", { handle: begun.handle, answers: wrong })).toBe("unknown_handle");
  });

  it("sealing happens once, and a failed device-key store can be retried at commit", async () => {
    const userId = "00000000-0000-4000-8000-0000000000c9";
    const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET) });
    const words = begun.paperWords.split(" ");
    const answers = begun.checkPositions.map((position) => ({ position, word: words[position - 1] ?? "" }));
    await call("ceremony.checkWords", { handle: begun.handle, answers });
    await call("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(9) });
    expect(await code("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(9) })).toBe("invalid_input");
    const open = indexedDB.open.bind(indexedDB);
    indexedDB.open = () => { throw new Error("storage_blocked"); };
    try {
      expect(await code("ceremony.commit", { handle: begun.handle, userId })).not.toBe("ok");
    } finally {
      indexedDB.open = open;
    }
    expect((await call("ceremony.commit", { handle: begun.handle, userId })).keyId).toBe(begun.keyId);
    expect((await loadDeviceKey(userId))?.keyId).toBe(begun.keyId);
    expect(await code("ceremony.commit", { handle: begun.handle, userId })).toBe("unknown_handle");
  });

  it("any two of passkey, paper and ROUT's piece restore the same key on a new device; one does not", async () => {
    const userId = "00000000-0000-4000-8000-0000000000c3";
    const { ceremony, keyId, paper } = await setup(userId);
    expect((await loadDeviceKey(userId))?.keyId).toBe(keyId);

    // Requests are wiped after each op (as after postMessage), so every call gets its own copy.
    const fresh = async () => forgetDeviceKey(userId);
    const server = () => openServerShard(structuredClone(ceremony), userId, SECRET);

    await fresh();
    expect((await call("ceremony.restore", { userId, ceremony: structuredClone(ceremony), keyId, paperWords: paper, serverShare: server() })).keyId).toBe(keyId);
    await fresh();
    expect((await call("ceremony.restore", { userId, ceremony: structuredClone(ceremony), keyId, prf: prfOf(5), serverShare: server() })).keyId).toBe(keyId);
    await fresh();
    expect((await call("ceremony.restore", { userId, ceremony: structuredClone(ceremony), keyId, prf: prfOf(5), paperWords: paper })).keyId).toBe(keyId);
    expect((await loadDeviceKey(userId))?.keyId).toBe(keyId);

    await fresh();
    expect(await code("ceremony.restore", { userId, ceremony: structuredClone(ceremony), keyId, serverShare: server() })).toBe("decrypt_failed");
    expect(await code("ceremony.restore", { userId, ceremony: structuredClone(ceremony), keyId, paperWords: paper })).toBe("decrypt_failed");
    expect(await code("ceremony.restore", { userId, ceremony: structuredClone(ceremony), keyId, prf: prfOf(6), serverShare: server() })).toBe("decrypt_failed");
    expect(await loadDeviceKey(userId)).toBeNull();
  });

  it("protects the existing Master Key: its words are required and must match", async () => {
    const userId = "00000000-0000-4000-8000-0000000000c4";
    const master = newMasterKey();
    await call("masterKey.unlock", { userId, mnemonic: master.mnemonic });
    const key = (await loadDeviceKey(userId))?.keyId;
    expect(await code("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET) })).toBe("master_key_required");
    expect(await code("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET), mnemonic: newMasterKey().mnemonic })).toBe("key_mismatch");
    const { keyId, begun } = await setup(userId, master.mnemonic);
    expect(begun.fresh).toBe(false);
    expect(keyId).toBe(key);
  });

  it("a ceremony of one member does not restore for another", async () => {
    const alice = "00000000-0000-4000-8000-0000000000c5";
    const bob = "00000000-0000-4000-8000-0000000000c6";
    const { ceremony, keyId, paper } = await setup(alice);
    expect(await code("ceremony.restore", { userId: bob, ceremony: structuredClone(ceremony), keyId, paperWords: paper, prf: prfOf(5) })).toBe("invalid_input");
    expect(await code("ceremony.restore", { userId: bob, ceremony: { ...structuredClone(ceremony), memberId: bob }, keyId, paperWords: paper, prf: prfOf(5) })).toBe("decrypt_failed");
  });
});

describe("2-of-4 ceremony with the ROUT Card in the crypto enclave", () => {
  const cardOf = (n: number) => new Uint8Array(32).map((_, i) => (i * 13 + n) & 0xff);

  it("a tapped card makes it version 2; card + one other factor restore on a new device, the card alone does not", async () => {
    const userId = "00000000-0000-4000-8000-0000000000d1";
    const card = cardOf(3);
    const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET), cardSecret: card });
    expect(begun.version).toBe(2);
    expect(card.every((b) => b === 0)).toBe(true); // wiped inside the worker
    const words = begun.paperWords.split(" ");
    const answers = begun.checkPositions.map((position) => ({ position, word: words[position - 1] ?? "" }));
    await call("ceremony.checkWords", { handle: begun.handle, answers });
    const sealed = await call("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(6) });
    const stored = sealed.ceremony as RecoveryCeremony;
    expect(stored.version).toBe(2);
    // The worker wipes every byte array it receives (as after a transfer): each call gets a fresh copy.
    const copy = (c: RecoveryCeremony) => structuredClone(c);
    const ceremony = copy(stored);
    const { keyId } = await call("ceremony.commit", { handle: begun.handle, userId });

    await forgetDeviceKey(userId);
    expect(await code("ceremony.restore", { userId, ceremony: copy(stored), keyId, cardSecret: cardOf(3) })).toBe("decrypt_failed");
    await forgetDeviceKey(userId);
    expect((await call("ceremony.restore", { userId, ceremony: copy(stored), keyId, cardSecret: cardOf(3), paperWords: begun.paperWords })).keyId).toBe(keyId);
    await forgetDeviceKey(userId);
    const serverShare = openServerShard(copy(stored), userId, SECRET);
    expect((await call("ceremony.restore", { userId, ceremony: copy(stored), keyId, cardSecret: cardOf(3), serverShare })).keyId).toBe(keyId);
    await forgetDeviceKey(userId);
    expect((await call("ceremony.restore", { userId, ceremony: copy(stored), keyId, cardSecret: cardOf(3), prf: prfOf(6) })).keyId).toBe(keyId);
    // Another card does not count as the card factor.
    await forgetDeviceKey(userId);
    expect(await code("ceremony.restore", { userId, ceremony: copy(stored), keyId, cardSecret: cardOf(4), paperWords: begun.paperWords })).toBe("decrypt_failed");
  });

  it("refuses a card secret that is not 32 bytes, and a card on a 2-of-3 ceremony", async () => {
    const userId = "00000000-0000-4000-8000-0000000000d2";
    expect(await code("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET), cardSecret: new Uint8Array(31) })).toBe("invalid_input");
    const { ceremony, keyId, paper } = await setup(userId);
    expect(ceremony.version).toBe(1);
    await forgetDeviceKey(userId);
    expect(await code("ceremony.restore", { userId, ceremony, keyId, cardSecret: cardOf(1), paperWords: paper })).toBe("decrypt_failed");
  });

  it("a stored version 2 ceremony without its card shard is refused as input", async () => {
    const userId = "00000000-0000-4000-8000-0000000000d3";
    const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET), cardSecret: cardOf(9) });
    const words = begun.paperWords.split(" ");
    await call("ceremony.checkWords", { handle: begun.handle, answers: begun.checkPositions.map((position) => ({ position, word: words[position - 1] ?? "" })) });
    const sealed = await call("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(2) });
    const { keyId } = await call("ceremony.commit", { handle: begun.handle, userId });
    const c = sealed.ceremony as RecoveryCeremony & { shards: Record<string, Uint8Array> };
    const { nfc_card: _gone, ...core } = c.shards;
    await forgetDeviceKey(userId);
    expect(await code("ceremony.restore", { userId, ceremony: { ...c, shards: core }, keyId, prf: prfOf(2), paperWords: begun.paperWords })).toBe("invalid_input");
  });
});
