import { describe, expect, it } from "vitest";
import { adminAccessDecision } from "@/lib/auth/sign-in-policy";
import { studioPageParam } from "@/lib/studio-page-param";

describe("admin UI gate", () => {
  it("refuses non-admins", () => expect(adminAccessDecision(false, true)).toBe("forbidden"));
  it("asks admins without 2FA to set it up", () => expect(adminAccessDecision(true, false)).toBe("two_factor_setup_required"));
  it("lets admins with 2FA in", () => expect(adminAccessDecision(true, true)).toBe("allow"));
});

describe("/studio page search param", () => {
  it("keeps page=booking", () => expect(studioPageParam("booking")).toBe("booking"));
  it("drops unknown pages", () => expect(studioPageParam("admin")).toBeUndefined());
});
