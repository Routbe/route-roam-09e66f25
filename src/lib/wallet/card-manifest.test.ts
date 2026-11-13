import { describe, expect, it } from "vitest";
import { parseCardManifest } from "./card-manifest";

describe("parseCardManifest", () => {
  it("reads one chip per line with an optional activation code", () => {
    expect(parseCardManifest("04a1b2c3d4e5f6\n04:A1:B2:C3:D4:E5:F7,abcd-1234")).toEqual({
      ok: true,
      cards: [{ uid: "04A1B2C3D4E5F6" }, { uid: "04A1B2C3D4E5F7", activationCode: "ABCD-1234" }],
    });
  });
  it("refuses a bad UID, a duplicate and more than 5000 cards", () => {
    expect(parseCardManifest("04A1B2").ok).toBe(false);
    expect(parseCardManifest("04A1B2C3D4E5F6\n04A1B2C3D4E5F6").ok).toBe(false);
    const many = Array.from({ length: 5001 }, (_, i) => (0x04000000000000 + i).toString(16).padStart(14, "0")).join("\n");
    expect(parseCardManifest(many).ok).toBe(false);
  });
});
