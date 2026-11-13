import { describe, expect, it } from "vitest";
import { pickConversionDesign, suggestedConversionSlug } from "./workspace-conversion-rules";

const V = { payload: { displayName: "Verified" }, published: true };
const A = { payload: { displayName: "Alias" }, published: true };

describe("conversion design", () => {
  it("verified design goes live, alias design is kept as concept", () => {
    expect(pickConversionDesign({ verified: true, verifiedDraft: V, aliasDraft: A })).toEqual({ live: V.payload, concept: A.payload });
  });
  it("unverified account carries the alias design", () => {
    expect(pickConversionDesign({ verified: false, verifiedDraft: V, aliasDraft: A }).live).toEqual(A.payload);
  });
  it("an unpublished design is never made live", () => {
    expect(pickConversionDesign({ verified: true, verifiedDraft: { ...V, published: false }, aliasDraft: null })).toEqual({ live: null, concept: V.payload });
  });
  it("no designs → nothing", () => {
    expect(pickConversionDesign({ verified: true, verifiedDraft: null, aliasDraft: null })).toEqual({ live: null, concept: null });
  });
});

describe("suggested slug", () => {
  it("keeps the old username, dots become dashes", () => {
    expect(suggestedConversionSlug("maximilien.brussels", "Maximilien")).toBe("maximilien-brussels");
  });
});

describe("conversion workspace logo", () => {
  it("the live design's uploaded photo becomes the workspace logo", async () => {
    const { conversionWorkspaceLogo } = await import("./workspace-conversion-rules");
    const photo = "/api/public/avatar?path=12345678-1234-1234-1234-123456789abc%2Favatar-1731481234.webp";
    expect(conversionWorkspaceLogo({ avatarUrl: photo })).toBe(photo);
  });
  it("no live design, no photo or an invalid photo gives no logo", async () => {
    const { conversionWorkspaceLogo } = await import("./workspace-conversion-rules");
    expect(conversionWorkspaceLogo(null)).toBeNull();
    expect(conversionWorkspaceLogo({ avatarUrl: "" })).toBeNull();
    expect(conversionWorkspaceLogo({ avatarUrl: "javascript:alert(1)" })).toBeNull();
  });
});
