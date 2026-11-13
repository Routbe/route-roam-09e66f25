import i18next from "i18next";
import { getRequest } from "@tanstack/react-start/server";
import { negotiateLocale, readCookieValue, type NegotiatedLocale } from "@/lib/locale-negotiation";

/**
 * Server only. The shared i18next instance is a process-wide singleton, yet ~100
 * components call `i18n.t()` directly while rendering. On the server those calls
 * now translate into the locale of the request being rendered (negotiated
 * exactly like the root route: rout_lang cookie, then Accept-Language), so the
 * server HTML matches the first client frame and concurrent requests never
 * share a language. Outside a request the instance behaves as before.
 */
const negotiated = new WeakMap<Request, NegotiatedLocale>();

export function currentRequestLocale(): NegotiatedLocale | null {
  let request: Request | undefined;
  try {
    request = getRequest();
  } catch {
    return null;
  }
  if (!request) return null;
  let locale = negotiated.get(request);
  if (!locale) {
    locale = negotiateLocale({
      cookie: readCookieValue(request.headers.get("cookie") ?? "", "rout_lang"),
      acceptLanguage: request.headers.get("accept-language"),
    });
    negotiated.set(request, locale);
  }
  return locale;
}

type TArgs = [key: unknown, second?: unknown, third?: unknown];
let installed = false;

export function installRequestScopedTranslator(): void {
  if (installed) return;
  installed = true;
  const baseT = i18next.t.bind(i18next) as (...args: TArgs) => unknown;
  const withLng = (options: unknown, lng: string) =>
    options && typeof options === "object" ? { lng, ...(options as Record<string, unknown>) } : { lng };
  const scopedT = (...[key, second, third]: TArgs) => {
    const lng = currentRequestLocale();
    if (!lng) return baseT(key, second, third);
    // t(key, defaultValue, options) and t(key, options); an explicit lng (getFixedT) always wins.
    return typeof second === "string" ? baseT(key, second, withLng(third, lng)) : baseT(key, withLng(second, lng));
  };
  i18next.t = scopedT as typeof i18next.t;

  for (const field of ["language", "resolvedLanguage"] as const) {
    let stored = i18next[field];
    Object.defineProperty(i18next, field, {
      configurable: true,
      enumerable: true,
      get: () => currentRequestLocale() ?? stored,
      set: (value: string | undefined) => {
        stored = value as typeof stored;
      },
    });
  }
}
