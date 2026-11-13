/**
 * Pure locale negotiation shared by the server render and the browser, so the
 * first server frame is already in the visitor's language and hydration never
 * swaps English for Dutch (or another locale) after paint.
 *
 * Order: explicit choice (rout_lang cookie), then Accept-Language by q-value,
 * then English as the international default.
 */
export const NEGOTIABLE_LOCALES = ["nl", "en", "fr", "de"] as const;
export type NegotiatedLocale = (typeof NEGOTIABLE_LOCALES)[number];

export function isNegotiableLocale(value: unknown): value is NegotiatedLocale {
  return typeof value === "string" && (NEGOTIABLE_LOCALES as readonly string[]).includes(value);
}

/** Highest-q supported primary language tag; ties keep the header order. */
export function localeFromAcceptLanguage(header: string | null | undefined): NegotiatedLocale | null {
  if (!header) return null;
  const ranked = header
    .split(",")
    .slice(0, 32)
    .map((part, index) => {
      const [rawTag = "", ...params] = part.trim().split(";");
      const qParam = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
      const q = qParam ? Number.parseFloat(qParam.slice(2)) : 1;
      return { tag: rawTag.trim().toLowerCase().split("-")[0] ?? "", q: Number.isFinite(q) ? q : 0, index };
    })
    .filter((entry) => entry.q > 0 && isNegotiableLocale(entry.tag))
    .sort((a, b) => b.q - a.q || a.index - b.index);
  return (ranked[0]?.tag as NegotiatedLocale | undefined) ?? null;
}

export function negotiateLocale(input: { cookie?: string | null; acceptLanguage?: string | null }): NegotiatedLocale {
  const cookie = input.cookie ? safeDecode(input.cookie) : null;
  if (isNegotiableLocale(cookie)) return cookie;
  return localeFromAcceptLanguage(input.acceptLanguage) ?? "en";
}

function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

/** Value of one cookie in a raw Cookie header / document.cookie string. */
export function readCookieValue(cookieHeader: string, name: string): string | null {
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}
