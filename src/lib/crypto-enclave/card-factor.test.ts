// @vitest-environment node
import { describe, expect, it } from "vitest";
import { CARD_FRAGMENT_PARAM, CardFactorError, cardFactorKeys, cardFactorKeysFromFragment, cardFragment, parseCardFragment } from "./card-factor";

const ALICE = "00000000-0000-4000-8000-00000000000a";
const secret = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);

describe("ROUT Card recovery factor (URL fragment, never sent to a server)", () => {
  it("round-trips 32 bytes through the rk1 fragment", () => {
    const f = cardFragment(secret);
    expect(f.startsWith(`#${CARD_FRAGMENT_PARAM}=`)).toBe(true);
    expect(f).toHaveLength(1 + 4 + 43);
    expect([...parseCardFragment(f)]).toEqual([...secret]);
    expect([...parseCardFragment(f.slice(1))]).toEqual([...secret]);
  });

  it("derives the same factor key from the fragment as from the raw secret", () => {
    expect([...cardFactorKeysFromFragment(cardFragment(secret), ALICE).publicKey]).toEqual([...cardFactorKeys(secret, ALICE).publicKey]);
  });

  it("refuses anything that is not exactly one rk1 value of 32 bytes", () => {
    const good = cardFragment(secret).slice(1 + 4);
    const bad = [
      "",
      "#",
      `#rk2=${good}`,
      `#rk1=${good}=`,
      `#rk1=${good.slice(0, 42)}`,
      `#rk1=${good}A`,
      `#rk1=${good.slice(0, 42)}B`, // non-zero padding bits
      `#rk1=${good.slice(0, 42)}+`,
      `#x=1&rk1=${good}`,
      `#rk1=${good}&x=1`,
      `#rk1=${"A".repeat(43)}`, // all-zero secret
    ];
    for (const f of bad) expect(() => parseCardFragment(f), f).toThrow(CardFactorError);
    expect(() => cardFragment(new Uint8Array(31))).toThrow(CardFactorError);
    expect(() => cardFragment(new Uint8Array(32))).toThrow(CardFactorError);
  });
});
