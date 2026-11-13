import { describe, expect, it } from "vitest";
import { localeFromAcceptLanguage, negotiateLocale, readCookieValue } from "./locale-negotiation";

describe("locale negotiation for the first server frame", () => {
  it("an explicit rout_lang cookie beats the browser language", () => {
    expect(negotiateLocale({ cookie: "de", acceptLanguage: "nl-BE,nl;q=0.9" })).toBe("de");
  });

  it("a Flemish browser without a cookie gets Dutch", () => {
    expect(negotiateLocale({ cookie: null, acceptLanguage: "nl-BE,nl;q=0.9,en;q=0.8" })).toBe("nl");
  });

  it("Accept-Language is ranked by q-value, not by position", () => {
    expect(localeFromAcceptLanguage("en;q=0.3, fr-BE;q=0.9, nl;q=0.5")).toBe("fr");
  });

  it("unsupported languages are skipped and q=0 is refused", () => {
    expect(localeFromAcceptLanguage("es-ES, nl;q=0, de;q=0.4")).toBe("de");
  });

  it("an unknown cookie value falls back to the browser, then English", () => {
    expect(negotiateLocale({ cookie: "xx", acceptLanguage: "fr" })).toBe("fr");
    expect(negotiateLocale({ cookie: "%E0%A4%A", acceptLanguage: null })).toBe("en");
  });

  it("reads one cookie out of a full Cookie header", () => {
    expect(readCookieValue("a=1; rout_lang=nl; b=2", "rout_lang")).toBe("nl");
    expect(readCookieValue("xrout_lang=fr", "rout_lang")).toBeNull();
  });
});
