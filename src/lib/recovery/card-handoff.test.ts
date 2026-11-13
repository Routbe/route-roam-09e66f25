// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  CARD_HANDOFF_CHANNEL, deliverCardSecret, findCardListeners, parseHandoffMessage, waitForCardSecret, type CardListener,
} from "./card-handoff";

const secret = () => crypto.getRandomValues(new Uint8Array(32));
const until = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("ROUT Card hand-off between tabs", () => {
  it("delivers the secret to the one waiting tab, wipes the sender copy and gets a receipt", async () => {
    const ctrl = new AbortController();
    const waiting = waitForCardSecret("setup", ctrl.signal);
    await until(20);
    const listeners = await findCardListeners(undefined, 80);
    expect(listeners).toHaveLength(1);
    expect(listeners[0]!.purpose).toBe("setup");
    const s = secret();
    const copy = s.slice();
    expect(await deliverCardSecret(listeners[0]!, s)).toBe(true);
    expect([...s].every((b) => b === 0)).toBe(true);
    const got = await waiting;
    expect([...got]).toEqual([...copy]);
  });

  it("never puts the secret on the channel in plaintext", async () => {
    const spy = new BroadcastChannel(CARD_HANDOFF_CHANNEL);
    const seen: string[] = [];
    spy.onmessage = (e) => seen.push(JSON.stringify(e.data));
    const ctrl = new AbortController();
    const waiting = waitForCardSecret("login", ctrl.signal);
    await until(20);
    const [l] = await findCardListeners(undefined, 80);
    const s = secret();
    const hex = Buffer.from(s).toString("hex");
    const b64 = Buffer.from(s).toString("base64url");
    await deliverCardSecret(l!, s);
    (await waiting).fill(0);
    spy.close();
    expect(seen.some((m) => m.includes('"t":"card"'))).toBe(true);
    for (const m of seen) {
      expect(m).not.toContain(hex);
      expect(m).not.toContain(b64);
    }
  });

  it("refuses ciphertext for another session, purpose or public key", async () => {
    const ctrl = new AbortController();
    const waiting = waitForCardSecret("restore", ctrl.signal);
    await until(20);
    const [l] = await findCardListeners(undefined, 80);
    // Same session, wrong purpose: the key and the AAD differ, the waiting tab answers ok:false.
    expect(await deliverCardSecret({ ...l!, purpose: "setup" }, secret())).toBe(false);
    // Another tab's public key: the waiting tab cannot derive the key.
    const other = new AbortController();
    const otherWaiting = waitForCardSecret("restore", other.signal);
    await until(20);
    const both = await findCardListeners(undefined, 80);
    const foreign = both.find((x) => x.sid !== l!.sid)!;
    expect(await deliverCardSecret({ ...l!, pub: foreign.pub }, secret())).toBe(false);
    // The right delivery still works afterwards.
    const s = secret();
    const copy = s.slice();
    expect(await deliverCardSecret(l!, s)).toBe(true);
    expect([...(await waiting)]).toEqual([...copy]);
    other.abort();
    await expect(otherWaiting).rejects.toThrow();
  });

  it("accepts exactly one card per session", async () => {
    const ctrl = new AbortController();
    const waiting = waitForCardSecret("setup", ctrl.signal);
    await until(20);
    const [l] = await findCardListeners(undefined, 80);
    expect(await deliverCardSecret(l!, secret())).toBe(true);
    await waiting;
    expect(await deliverCardSecret(l!, secret())).toBe(false); // nobody answers any more
    expect(await findCardListeners(undefined, 80)).toEqual([]);
  });

  it("stops on abort and never delivers to an expired listener", async () => {
    const ctrl = new AbortController();
    const waiting = waitForCardSecret("setup", ctrl.signal);
    ctrl.abort();
    await expect(waiting).rejects.toThrow();
    const expired: CardListener = { sid: "A".repeat(22), purpose: "setup", pub: "A".repeat(87), exp: Date.now() - 1 };
    const s = secret();
    expect(await deliverCardSecret(expired, s)).toBe(false);
    expect([...s].every((b) => b === 0)).toBe(true);
  });

  it("drops malformed messages", () => {
    expect(parseHandoffMessage({ v: 1, t: "who" })).toEqual({ v: 1, t: "who" });
    expect(parseHandoffMessage({ v: 1, t: "who", extra: 1 })).toBeNull();
    expect(parseHandoffMessage({ v: 2, t: "who" })).toBeNull();
    expect(parseHandoffMessage({ v: 1, t: "here", sid: "A".repeat(22), purpose: "admin", pub: "A".repeat(87), exp: 1 })).toBeNull();
    expect(parseHandoffMessage({ v: 1, t: "card", sid: "A".repeat(22), epk: "A".repeat(87), iv: "A".repeat(16), ct: "A".repeat(63) })).toBeNull();
    expect(parseHandoffMessage("card")).toBeNull();
    expect(parseHandoffMessage(null)).toBeNull();
  });
});
