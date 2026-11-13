import { createIsomorphicFn } from "@tanstack/react-start";
import { isNegotiableLocale, negotiateLocale, readCookieValue, type NegotiatedLocale } from "@/lib/locale-negotiation";

const LOCALE_COOKIE = "rout_lang";

/**
 * Locale for the root render. The server negotiates from the cookie and
 * Accept-Language; its answer is dehydrated with the root context, so the first
 * client frame matches. Later client navigations reuse the language already
 * on <html>, falling back to the cookie.
 */
export const readRequestLocale = createIsomorphicFn()
  .server(async (): Promise<NegotiatedLocale> => {
    const { getRequestHeader } = await import("@tanstack/react-start/server");
    const cookieHeader = getRequestHeader("cookie") ?? "";
    return negotiateLocale({ cookie: readCookieValue(cookieHeader, LOCALE_COOKIE), acceptLanguage: getRequestHeader("accept-language") });
  })
  .client(async (): Promise<NegotiatedLocale> => {
    // <html lang> mirrors the language on screen (I18nProvider keeps it current), including an account-applied one.
    const onScreen = document.documentElement.lang;
    if (isNegotiableLocale(onScreen)) return onScreen;
    return negotiateLocale({ cookie: readCookieValue(document.cookie, LOCALE_COOKIE), acceptLanguage: null });
  });
