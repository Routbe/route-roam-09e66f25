import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Passkey-only account creation.
 *
 * A Better Auth user row may only be created while a verified first-passkey
 * ceremony (signed sign-up ticket) is finalising. Every other path — e-mail
 * sign-up, magic link, social/OIDC callbacks, plugins — is refused by the
 * `user.create.before` database hook in better-auth.server.ts.
 */
const scope = new AsyncLocalStorage<{ via: "passkey-signup" }>();

export function runPasskeyAccountCreation<T>(fn: () => Promise<T>): Promise<T> {
  return scope.run({ via: "passkey-signup" }, fn);
}

export function isPasskeyAccountCreation(): boolean {
  return scope.getStore()?.via === "passkey-signup";
}

export const PASSKEY_SIGNUP_REQUIRED = "passkey_signup_required";
