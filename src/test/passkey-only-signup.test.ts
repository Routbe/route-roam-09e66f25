// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import { isPasskeyAccountCreation, runPasskeyAccountCreation } from "@/lib/auth/account-creation-scope";
import { finalizeEnrollment } from "@/lib/auth/passkey-enrollment.server";
import { signSignupTicket } from "@/lib/auth/signup-ticket";

vi.mock("@/lib/minor-safety.server", () => ({ recordSignupAge: async () => undefined }));

const SECRET = "x".repeat(48);

describe("passkey-only account creation", () => {
  it("is refused outside the passkey sign-up ceremony", () => {
    expect(isPasskeyAccountCreation()).toBe(false);
  });

  it("is allowed only inside the passkey sign-up scope", async () => {
    expect(await runPasskeyAccountCreation(async () => isPasskeyAccountCreation())).toBe(true);
    expect(isPasskeyAccountCreation()).toBe(false);
  });

  it("creates the account from a verified sign-up ticket inside the passkey scope", async () => {
    const ticket = await signSignupTicket(
      SECRET,
      { email: "new@example.com", name: "New", dob: "1990-01-01", parentEmail: null, consent: "test" } as never,
      Math.floor(Date.now() / 1000),
    );
    let scopedDuringCreate = false;
    const adapter = {
      findUserByEmail: async () => null,
      createUser: async () => {
        scopedDuringCreate = isPasskeyAccountCreation();
        return { id: "11111111-1111-4111-8111-111111111111" };
      },
    };
    await expect(finalizeEnrollment(SECRET, adapter, ticket)).resolves.toEqual({ userId: "11111111-1111-4111-8111-111111111111" });
    expect(scopedDuringCreate).toBe(true);
  });

  it("refuses enrollment without a sign-up ticket or recovery token", async () => {
    const adapter = { findUserByEmail: async () => null, createUser: async () => ({ id: "x" }) };
    await expect(finalizeEnrollment(SECRET, adapter, "bogus")).rejects.toThrow("passkey_enrollment_required");
  });
});
