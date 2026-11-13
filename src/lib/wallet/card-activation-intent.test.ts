import { describe, expect, it } from "vitest";
import { ACTIVATION_INTENT_MS, startActivationIntent, takeActivationIntent } from "./card-activation-intent";

describe("card activation intent", () => {
  it("arms exactly one tap within 5 minutes", () => {
    startActivationIntent(1_000);
    expect(takeActivationIntent(1_000 + ACTIVATION_INTENT_MS - 1)).toBe(true);
    expect(takeActivationIntent(1_000)).toBe(false);
  });
  it("expires after 5 minutes", () => {
    startActivationIntent(1_000);
    expect(takeActivationIntent(1_000 + ACTIVATION_INTENT_MS + 1)).toBe(false);
  });
});
