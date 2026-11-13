import { describe, expect, it } from "vitest";
import { backoffDelay, withSerializableRetry } from "@/lib/db-retry";

const sqlErr = (code: string) => Object.assign(new Error("x"), { code });
const noSleep = { sleep: async () => {}, random: () => 0.5 };

describe("serializable retry", () => {
  it("retries a serialization failure and returns the later success", async () => {
    let calls = 0;
    const out = await withSerializableRetry(async () => {
      calls++;
      if (calls < 3) throw sqlErr("40001");
      return "ok";
    }, noSleep);
    expect(out).toBe("ok");
    expect(calls).toBe(3);
  });

  it("retries a deadlock too", async () => {
    let calls = 0;
    await withSerializableRetry(async () => { if (++calls === 1) throw sqlErr("40P01"); return 1; }, noSleep);
    expect(calls).toBe(2);
  });

  it("never retries other errors (e.g. a unique violation)", async () => {
    let calls = 0;
    await expect(withSerializableRetry(async () => { calls++; throw sqlErr("23505"); }, noSleep)).rejects.toThrow();
    expect(calls).toBe(1);
  });

  it("gives up after 5 attempts by default", async () => {
    let calls = 0;
    await expect(withSerializableRetry(async () => { calls++; throw sqlErr("40001"); }, noSleep)).rejects.toThrow();
    expect(calls).toBe(5);
  });

  it("doubles the backoff ceiling per attempt and caps it", () => {
    const max = () => 0.999999;
    expect(backoffDelay(0, 20, 500, max)).toBe(19);
    expect(backoffDelay(3, 20, 500, max)).toBe(159);
    expect(backoffDelay(10, 20, 500, max)).toBe(499);
  });
});
