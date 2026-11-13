import { createIsomorphicFn } from "@tanstack/react-start";
import { negotiateLocale, readCookieValue, type NegotiatedLocale } from "@/lib/locale-negotiation";

const LOCALE_COOKIE = "rout_lang";

/**
 * Locale for the root render. The server negotiates from the cookie and
 * Accept-Language; its answer is dehydrated with the root context, so the first
 * client frame matches. Later client navigations reuse the cookie or the
 * language already on <html>.
 */
export const readRequestLocale = createIsomorphicFn()
  .server(async (): Promise<NegotiatedLocale> => {
    const { getRequestHeader } = await import("@tanstack/react-start/server");
    const cookieHeader = getRequestHeader("cookie") ?? "";
    return negotiateLocale({ cookie: readCookieValue(cookieHeader, LOCALE_COOKIE), acceptLanguage: getRequestHeader("accept-language") });
  })
  .client(async (): Promise<NegotiatedLocale> =>
    negotiateLocale({ cookie: readCookieValue(document.cookie, LOCALE_COOKIE), acceptLanguage: document.documentElement.lang }),
  );
