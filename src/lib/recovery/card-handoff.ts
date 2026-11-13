/**
 * ROUT Card hand-off between tabs of one browser.
 *
 * On iPhone (and on Android when no page is scanning) a card tap opens /t in a
 * new tab. The recovery secret lives only in that URL's fragment, which the
 * browser never sends anywhere. /t hands it to the tab that asked for the card
 * (setup, restore or sign-in by recovery) over a BroadcastChannel, never in
 * plaintext: the waiting tab offers a fresh P-256 public key (private half
 * non-extractable), /t answers with an ephemeral ECDH key and AES-256-GCM
 * ciphertext keyed by HKDF over the shared secret and bound to the session id,
 * the purpose and both public keys. Other tabs see only public keys and
 * ciphertext; a session accepts exactly one card and expires after 5 minutes.
 *
 * Both sides wipe every secret byte view they own; the caller owns (and wipes)
 * the secret a listener resolves with, normally by transferring it to the
 * crypto worker.
 */
import { CARD_SECRET_BYTES } from "@/lib/crypto-enclave/card-fragment";

export const CARD_HANDOFF_CHANNEL = "rout-card-factor-v1";
export const CARD_HANDOFF_TTL_MS = 5 * 60_000;
/** How long /t waits for waiting tabs to announce themselves. */
export const CARD_HANDOFF_DISCOVERY_MS = 600;
const ACK_TIMEOUT_MS = 4_000;
const DOMAIN = "rout.card-handoff.v1";

export type CardHandoffPurpose = "setup" | "restore" | "login";
const PURPOSES: readonly CardHandoffPurpose[] = ["setup", "restore", "login"];

/** A waiting tab, as /t sees it: only public values. */
export type CardListener = { sid: string; purpose: CardHandoffPurpose; pub: string; exp: number };

type Msg =
  | { v: 1; t: "who" }
  | { v: 1; t: "here"; sid: string; purpose: CardHandoffPurpose; pub: string; exp: number }
  | { v: 1; t: "card"; sid: string; epk: string; iv: string; ct: string }
  | { v: 1; t: "got"; sid: string; ok: boolean };

const SID_RE = /^[A-Za-z0-9_-]{22}$/; // 16 bytes
const PUB_RE = /^[A-Za-z0-9_-]{87}$/; // 65-byte uncompressed P-256 point
const IV_RE = /^[A-Za-z0-9_-]{16}$/; // 12 bytes
const CT_RE = /^[A-Za-z0-9_-]{64}$/; // 32-byte secret + 16-byte tag = 48 bytes

const b64u = (bytes: Uint8Array) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (value: string) => {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  const bin = atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const utf8 = (s: string) => new TextEncoder().encode(s);
const randomB64u = (n: number) => b64u(crypto.getRandomValues(new Uint8Array(n)));

/** Strict message shape check: anything unexpected is dropped. */
export function parseHandoffMessage(data: unknown): Msg | null {
  if (!data || typeof data !== "object") return null;
  const m = data as Record<string, unknown>;
  if (m.v !== 1 || typeof m.t !== "string") return null;
  const keys = Object.keys(m).sort().join(",");
  switch (m.t) {
    case "who":
      return keys === "t,v" ? { v: 1, t: "who" } : null;
    case "here":
      return keys === "exp,pub,purpose,sid,t,v" && typeof m.sid === "string" && SID_RE.test(m.sid)
        && typeof m.pub === "string" && PUB_RE.test(m.pub) && PURPOSES.includes(m.purpose as CardHandoffPurpose)
        && typeof m.exp === "number" && Number.isFinite(m.exp)
        ? { v: 1, t: "here", sid: m.sid, purpose: m.purpose as CardHandoffPurpose, pub: m.pub, exp: m.exp } : null;
    case "card":
      return keys === "ct,epk,iv,sid,t,v" && typeof m.sid === "string" && SID_RE.test(m.sid)
        && typeof m.epk === "string" && PUB_RE.test(m.epk) && typeof m.iv === "string" && IV_RE.test(m.iv)
        && typeof m.ct === "string" && CT_RE.test(m.ct)
        ? { v: 1, t: "card", sid: m.sid, epk: m.epk, iv: m.iv, ct: m.ct } : null;
    case "got":
      return keys === "ok,sid,t,v" && typeof m.sid === "string" && SID_RE.test(m.sid) && typeof m.ok === "boolean"
        ? { v: 1, t: "got", sid: m.sid, ok: m.ok } : null;
    default:
      return null;
  }
}

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

/** AES-256-GCM key from ECDH(P-256) bits via HKDF-SHA-256, bound to the session and purpose. */
async function channelKey(priv: CryptoKey, peerPub: string, sid: string, purpose: CardHandoffPurpose, usage: KeyUsage): Promise<CryptoKey> {
  const peer = await crypto.subtle.importKey("raw", unb64u(peerPub), ECDH, false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, priv, 256));
  try {
    const ikm = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: unb64u(sid), info: utf8(`${DOMAIN}|key|${purpose}`) },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  } finally {
    bits.fill(0);
  }
}

const aad = (sid: string, purpose: CardHandoffPurpose, pub: string, epk: string) => utf8(`${DOMAIN}|${sid}|${purpose}|${pub}|${epk}`);

type ChannelLike = Pick<BroadcastChannel, "postMessage" | "close" | "addEventListener" | "removeEventListener">;
const openChannel = (): ChannelLike => new BroadcastChannel(CARD_HANDOFF_CHANNEL);

export function cardHandoffSupported(): boolean {
  return typeof BroadcastChannel === "function" && typeof crypto !== "undefined" && !!crypto.subtle;
}

/**
 * Waiting side. Resolves with the 32-byte card secret delivered by /t (the
 * caller wipes it), or rejects on abort or after the time-to-live.
 */
export async function waitForCardSecret(purpose: CardHandoffPurpose, signal: AbortSignal, channel: ChannelLike = openChannel()): Promise<Uint8Array> {
  const pair = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
  const pub = b64u(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const sid = randomB64u(16);
  const exp = Date.now() + CARD_HANDOFF_TTL_MS;
  const here: Msg = { v: 1, t: "here", sid, purpose, pub, exp };

  return new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    let opening = false;
    const timer = setTimeout(() => finish(new DOMException("expired", "TimeoutError")), CARD_HANDOFF_TTL_MS);
    function finish(result: Uint8Array | Error) {
      if (settled) {
        if (result instanceof Uint8Array) result.fill(0);
        return;
      }
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      channel.removeEventListener("message", onMessage as EventListener);
      channel.close();
      if (result instanceof Uint8Array) resolve(result);
      else reject(result);
    }
    function onAbort() {
      finish(new DOMException("aborted", "AbortError"));
    }
    async function onMessage(e: MessageEvent) {
      const m = parseHandoffMessage(e.data);
      if (!m || settled) return;
      if (m.t === "who") {
        if (Date.now() < exp) channel.postMessage(here);
        return;
      }
      if (m.t !== "card" || m.sid !== sid || opening || Date.now() >= exp) return;
      opening = true;
      let plain: Uint8Array | null = null;
      try {
        const key = await channelKey(pair.privateKey, m.epk, sid, purpose, "decrypt");
        plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(m.iv), additionalData: aad(sid, purpose, pub, m.epk) }, key, unb64u(m.ct)));
        if (plain.length !== CARD_SECRET_BYTES || plain.every((b) => b === 0)) throw new Error("bad_secret");
      } catch {
        plain?.fill(0);
        opening = false;
        if (!settled) channel.postMessage({ v: 1, t: "got", sid, ok: false } satisfies Msg);
        return;
      }
      channel.postMessage({ v: 1, t: "got", sid, ok: true } satisfies Msg);
      finish(plain);
    }
    if (signal.aborted) return onAbort();
    signal.addEventListener("abort", onAbort, { once: true });
    channel.addEventListener("message", onMessage as EventListener);
    // Announce now as well, in case /t was opened just before this tab started waiting.
    channel.postMessage(here);
  });
}

/** /t side: which tabs are waiting for a card right now. */
export async function findCardListeners(channel: ChannelLike = openChannel(), windowMs = CARD_HANDOFF_DISCOVERY_MS): Promise<CardListener[]> {
  const found = new Map<string, CardListener>();
  const onMessage = (e: MessageEvent) => {
    const m = parseHandoffMessage(e.data);
    if (m?.t === "here" && m.exp > Date.now()) found.set(m.sid, { sid: m.sid, purpose: m.purpose, pub: m.pub, exp: m.exp });
  };
  channel.addEventListener("message", onMessage as EventListener);
  channel.postMessage({ v: 1, t: "who" } satisfies Msg);
  await new Promise((r) => setTimeout(r, windowMs));
  channel.removeEventListener("message", onMessage as EventListener);
  channel.close();
  return [...found.values()];
}

/**
 * /t side: seals the secret to one waiting tab and waits for its receipt.
 * Wipes `secret` in every case. Resolves true only when that tab confirmed it
 * opened the card.
 */
export async function deliverCardSecret(listener: CardListener, secret: Uint8Array, channel: ChannelLike = openChannel()): Promise<boolean> {
  try {
    if (secret.length !== CARD_SECRET_BYTES || listener.exp <= Date.now()) return false;
    const eph = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
    const epk = b64u(new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)));
    const key = await channelKey(eph.privateKey, listener.pub, listener.sid, listener.purpose, "encrypt");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(listener.sid, listener.purpose, listener.pub, epk) }, key, secret as Uint8Array<ArrayBuffer>));
    secret.fill(0);
    return await new Promise<boolean>((resolve) => {
      const done = (ok: boolean) => {
        clearTimeout(timer);
        channel.removeEventListener("message", onMessage as EventListener);
        channel.close();
        resolve(ok);
      };
      const timer = setTimeout(() => done(false), ACK_TIMEOUT_MS);
      const onMessage = (e: MessageEvent) => {
        const m = parseHandoffMessage(e.data);
        if (m?.t === "got" && m.sid === listener.sid) done(m.ok);
      };
      channel.addEventListener("message", onMessage as EventListener);
      channel.postMessage({ v: 1, t: "card", sid: listener.sid, epk, iv: b64u(iv), ct: b64u(ct) } satisfies Msg);
    });
  } finally {
    secret.fill(0);
  }
}
