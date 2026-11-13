// @vitest-environment node
/**
 * Owner decision 2026-11-13: recovery = any 2 of 4 shards (passkey PRF, ROUT
 * Card, ROUT's server shard, 24 paper words). Version 1 (2-of-3) ceremonies
 * keep opening exactly as before.
 */
import { describe, expect, it } from "vitest";
import { cardFactorKeysFromFragment, cardFragment } from "./card-factor";
import {
  RECOVERY_THRESHOLD,
  RecoveryError,
  VERSION_FACTORS,
  beginRecoveryCeremony,
  completeRecoveryCeremony,
  createPaperFactor,
  createRecoveryCeremony,
  factorKeys,
  openFactorShard,
  recoverMasterKey,
  type RecoveryCeremony,
  type RecoveryFactor,
} from "./recovery-mpc";

const ALICE = "00000000-0000-4000-8000-00000000000a";
const master = new Uint8Array(32).map((_, i) => 200 - i);
const device = factorKeys("device_prf", new Uint8Array(32).fill(3), ALICE);
const server = factorKeys("server_guardian", new Uint8Array(32).fill(5), ALICE);
const paper = createPaperFactor(ALICE);
const cardSecret = new Uint8Array(32).map((_, i) => (i * 37 + 11) & 0xff);
const fragment = cardFragment(cardSecret);
const card = cardFactorKeysFromFragment(fragment, ALICE);

const pub = { device_prf: device.publicKey, paper_guardian: paper.keys.publicKey, server_guardian: server.publicKey, nfc_card: card.publicKey };
const sec: Record<RecoveryFactor, Uint8Array> = { device_prf: device.secretKey, paper_guardian: paper.keys.secretKey, server_guardian: server.secretKey, nfc_card: card.secretKey };
const pick = (...f: RecoveryFactor[]) => Object.fromEntries(f.map((x) => [x, sec[x]])) as Partial<Record<RecoveryFactor, Uint8Array>>;
const ALL: RecoveryFactor[] = ["device_prf", "nfc_card", "server_guardian", "paper_guardian"];

describe("2-of-4 recovery (ceremony version 2)", async () => {
  const ceremony = await createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: pub });

  it("is version 2 with threshold 2 and exactly four shards", () => {
    expect(ceremony.version).toBe(2);
    expect(ceremony.threshold).toBe(2);
    expect(RECOVERY_THRESHOLD).toBe(2);
    expect(Object.keys(ceremony.shards).sort()).toEqual([...VERSION_FACTORS[2]].sort());
    expect(VERSION_FACTORS[2]).toHaveLength(4);
  });

  it("each of the six pairs rebuilds the Master Key", async () => {
    let pairs = 0;
    for (let i = 0; i < ALL.length; i++) {
      for (let j = i + 1; j < ALL.length; j++) {
        const got = await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick(ALL[i]!, ALL[j]!) });
        expect([...got]).toEqual([...master]);
        pairs++;
      }
    }
    expect(pairs).toBe(6);
  });

  it("three or four factors also rebuild it", async () => {
    expect([...(await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick("device_prf", "nfc_card", "paper_guardian") }))]).toEqual([...master]);
    expect([...(await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick(...ALL) }))]).toEqual([...master]);
  });

  it("any single factor is refused, the card included", async () => {
    for (const f of ALL) await expect(recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick(f) })).rejects.toThrow(RecoveryError);
  });

  it("ROUT's opened server shard plus the card rebuilds; the server shard alone does not", async () => {
    const share = openFactorShard(ceremony, ALICE, "server_guardian", server.secretKey);
    expect([...(await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick("nfc_card"), openedShares: { server_guardian: share } }))]).toEqual([...master]);
    expect(share.every((b) => b === 0)).toBe(true);
    const alone = openFactorShard(ceremony, ALICE, "server_guardian", server.secretKey);
    await expect(recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: {}, openedShares: { server_guardian: alone } })).rejects.toThrow(RecoveryError);
    expect(alone.every((b) => b === 0)).toBe(true);
  });

  it("the card shard opens only with the key from that card's fragment", async () => {
    const other = cardFactorKeysFromFragment(cardFragment(new Uint8Array(32).fill(0x42)), ALICE);
    await expect(recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: { nfc_card: other.secretKey, device_prf: device.secretKey } })).rejects.toThrow(RecoveryError);
    // The same card for another member derives a different key.
    const bob = cardFactorKeysFromFragment(fragment, "00000000-0000-4000-8000-00000000000b");
    expect([...bob.publicKey]).not.toEqual([...card.publicKey]);
  });

  it("a stripped card shard, or a version 2 ceremony relabelled as version 1, never opens", async () => {
    const { nfc_card: _dropped, ...core } = ceremony.shards;
    const asV1 = { ...ceremony, version: 1, shards: core } as RecoveryCeremony;
    await expect(recoverMasterKey({ ceremony: asV1, memberId: ALICE, factorSecretKeys: pick("device_prf", "paper_guardian") })).rejects.toThrow(RecoveryError);
    const missing = { ...ceremony, shards: core } as unknown as RecoveryCeremony;
    await expect(recoverMasterKey({ ceremony: missing, memberId: ALICE, factorSecretKeys: pick("device_prf", "paper_guardian") })).rejects.toThrow(RecoveryError);
  });

  it("shards cannot move between factors or ceremonies", async () => {
    const swapped = { ...ceremony, shards: { ...ceremony.shards, nfc_card: ceremony.shards.paper_guardian } } as RecoveryCeremony;
    await expect(recoverMasterKey({ ceremony: swapped, memberId: ALICE, factorSecretKeys: { nfc_card: paper.keys.secretKey, device_prf: device.secretKey } })).rejects.toThrow(RecoveryError);
    const second = await createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: pub });
    const mixed = { ...ceremony, shards: { ...ceremony.shards, nfc_card: second.shards.nfc_card } } as RecoveryCeremony;
    await expect(recoverMasterKey({ ceremony: mixed, memberId: ALICE, factorSecretKeys: pick("nfc_card", "device_prf") })).rejects.toThrow(RecoveryError);
  });

  it("refuses a card key equal to another factor's key", async () => {
    await expect(createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: { ...pub, nfc_card: server.publicKey } })).rejects.toThrow(TypeError);
    const { draft, deviceShare } = await beginRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: { paper_guardian: paper.keys.publicKey, server_guardian: server.publicKey, nfc_card: card.publicKey } });
    expect(() => completeRecoveryCeremony(draft, deviceShare, card.publicKey)).toThrow(TypeError);
    expect(deviceShare.every((b) => b === 0)).toBe(true);
  });
});

describe("version 1 (2-of-3) stays as it was", async () => {
  const v1 = await createRecoveryCeremony({
    masterKey: master,
    memberId: ALICE,
    factorPublicKeys: { device_prf: device.publicKey, paper_guardian: paper.keys.publicKey, server_guardian: server.publicKey },
  });

  it("has three shards and opens with any two of them", async () => {
    expect(v1.version).toBe(1);
    expect(Object.keys(v1.shards).sort()).toEqual(["device_prf", "paper_guardian", "server_guardian"]);
    expect([...(await recoverMasterKey({ ceremony: v1, memberId: ALICE, factorSecretKeys: pick("paper_guardian", "server_guardian") }))]).toEqual([...master]);
  });

  it("refuses a card factor (the ceremony has no card shard) instead of skipping it", async () => {
    await expect(recoverMasterKey({ ceremony: v1, memberId: ALICE, factorSecretKeys: pick("nfc_card", "device_prf") })).rejects.toThrow(RecoveryError);
  });

  it("a card shard grafted onto a version 1 ceremony makes it unopenable", async () => {
    const v2 = await createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: pub });
    const grafted = { ...v1, version: 2, shards: { ...v1.shards, nfc_card: v2.shards.nfc_card } } as RecoveryCeremony;
    await expect(recoverMasterKey({ ceremony: grafted, memberId: ALICE, factorSecretKeys: pick("device_prf", "paper_guardian") })).rejects.toThrow(RecoveryError);
  });
});
