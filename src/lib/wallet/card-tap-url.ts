/**
 * Browser-safe helpers for reading a ROUT Card tap (NTAG 424 DNA SUN URL:
 * https://<origin>/t?p=<PICCData, 32 hex>&m=<CMAC, 16 hex>). Used by /t and by
 * the step-up dialog's Web NFC reader. Nothing here verifies anything: the
 * server checks the CMAC and the counter.
 */
import { cardSecretFromUrl } from "@/lib/crypto-enclave/card-fragment";

export type CardTapParams = { p: string; m: string };

const P_RE = /^[0-9A-Fa-f]{32}$/;
const M_RE = /^[0-9A-Fa-f]{16}$/;

/** The tap parameters from a URL (absolute, or without scheme as some readers return it); null when absent or malformed. */
export function parseCardTapUrl(text: string | null | undefined): CardTapParams | null {
  if (!text || text.length > 512) return null;
  const q = text.indexOf("?");
  if (q < 0) return null;
  const path = text.slice(0, q).replace(/^https?:\/\//i, "");
  if (!/^[^/]*\/t\/?$/.test(path)) return null;
  const params = new URLSearchParams(text.slice(q + 1).split("#")[0]);
  const p = params.get("p") ?? "";
  const m = params.get("m") ?? "";
  return P_RE.test(p) && M_RE.test(m) ? { p, m } : null;
}

/** Minimal Web NFC surface (Chrome on Android); not in the TypeScript DOM library. */
type NdefRecordLike = { recordType: string; data?: DataView | null };
type NdefReadingEvent = Event & { message: { records: readonly NdefRecordLike[] } };
type NdefReaderLike = EventTarget & { scan(options?: { signal?: AbortSignal }): Promise<void> };
type NdefReaderCtor = new () => NdefReaderLike;

function ndefCtor(): NdefReaderCtor | null {
  if (typeof window === "undefined") return null;
  const c = (window as unknown as { NDEFReader?: NdefReaderCtor }).NDEFReader;
  return typeof c === "function" ? c : null;
}

/** Whether this browser can read the card itself (Web NFC). Call after hydration only. */
export function webNfcAvailable(): boolean {
  return ndefCtor() !== null && typeof window !== "undefined" && window.isSecureContext;
}

/** The ROUT Card tap inside one NDEF message, if any. */
export function tapFromNdefRecords(records: readonly NdefRecordLike[]): CardTapParams | null {
  for (const r of records) {
    if ((r.recordType !== "url" && r.recordType !== "absolute-url") || !r.data) continue;
    const found = parseCardTapUrl(new TextDecoder().decode(r.data));
    if (found) return found;
  }
  return null;
}

/**
 * The ROUT Card recovery secret (`#rk1=` fragment, card-fragment.ts) inside one
 * NDEF message, only from a genuine /t tap URL; a fresh buffer the caller wipes.
 */
export function cardSecretFromNdefRecords(records: readonly NdefRecordLike[]): Uint8Array | null {
  for (const r of records) {
    if ((r.recordType !== "url" && r.recordType !== "absolute-url") || !r.data) continue;
    const url = new TextDecoder().decode(r.data);
    if (!parseCardTapUrl(url)) continue;
    const secret = cardSecretFromUrl(url);
    if (secret) return secret;
  }
  return null;
}

/**
 * Reads one ROUT Card recovery secret with Web NFC (Chrome on Android). Resolves
 * with the first tap that carries a valid fragment; a card without one (not yet
 * re-personalised) calls onNoFragment and keeps listening. Rejects when NFC is
 * unavailable, the permission is refused or the signal aborts.
 */
export async function scanCardSecret(signal: AbortSignal, onNoFragment?: () => void): Promise<Uint8Array> {
  const Ctor = ndefCtor();
  if (!Ctor) throw new Error("web_nfc_unavailable");
  const reader = new Ctor();
  return new Promise<Uint8Array>((resolve, reject) => {
    const stop = () => reject(new DOMException("aborted", "AbortError"));
    if (signal.aborted) return stop();
    signal.addEventListener("abort", stop, { once: true });
    reader.addEventListener("reading", (e) => {
      if (signal.aborted) return;
      const records = (e as NdefReadingEvent).message?.records ?? [];
      const secret = cardSecretFromNdefRecords(records);
      if (secret) {
        signal.removeEventListener("abort", stop);
        resolve(secret);
      } else if (tapFromNdefRecords(records)) onNoFragment?.();
    }, { signal });
    reader.scan({ signal }).catch(reject);
  });
}

/**
 * Starts a Web NFC scan (needs a user gesture the first time: it asks for the
 * NFC permission). Calls onTap for every readable ROUT Card tap until the
 * signal aborts. Rejects when NFC is unavailable or the permission is refused.
 */
export async function scanCardTaps(signal: AbortSignal, onTap: (tap: CardTapParams) => void, onUnreadable?: () => void): Promise<void> {
  const Ctor = ndefCtor();
  if (!Ctor) throw new Error("web_nfc_unavailable");
  const reader = new Ctor();
  reader.addEventListener("reading", (e) => {
    if (signal.aborted) return;
    const tap = tapFromNdefRecords((e as NdefReadingEvent).message?.records ?? []);
    if (tap) onTap(tap);
    else onUnreadable?.();
  }, { signal });
  reader.addEventListener("readingerror", () => { if (!signal.aborted) onUnreadable?.(); }, { signal });
  await reader.scan({ signal });
}

/**
 * What a tap on /t may do. A step-up is confirmed only when the signed-in member
 * pressed "confirm" on /t; any other tap is a public authenticity proof and never
 * completes an open step-up, so an unrelated tap cannot approve a request
 * started elsewhere (for example from a stolen session).
 */
export type CardTapPurpose = "proof" | "step_up";
export function cardTapRoute(purpose: CardTapPurpose, signedIn: boolean): "step_up" | "proof" | "refuse" {
  if (purpose === "step_up") return signedIn ? "step_up" : "refuse";
  return "proof";
}
