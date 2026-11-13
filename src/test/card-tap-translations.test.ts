import { describe, expect, it } from "vitest";
import en from "@/locales/pages/interface.en.json";
import nl from "@/locales/pages/interface.nl.json";
import fr from "@/locales/pages/interface.fr.json";
import de from "@/locales/pages/interface.de.json";

const bundles = { en, nl, fr, de } as Record<string, Record<string, string>>;

describe("ROUT Card tap page (/t) in four languages", () => {
  it("every card tap message exists and is filled in for nl, en, fr and de", () => {
    const keys = Object.keys(nl).filter((k) => k.startsWith("cardTap."));
    expect(keys.length).toBe(27);
    for (const [locale, bundle] of Object.entries(bundles)) {
      for (const k of keys) expect(bundle[k]?.trim(), `${locale}:${k}`).toBeTruthy();
      expect(Object.keys(bundle).filter((k) => k.startsWith("cardTap.")).sort(), locale).toEqual([...keys].sort());
    }
  });

  it("the anti-hijack confirmation buttons are translated per language", () => {
    expect([nl["cardTap.confirm.yes"], nl["cardTap.confirm.no"]]).toEqual(["Ja, ik bevestig", "Nee, dit was ik niet"]);
    expect([en["cardTap.confirm.yes"], en["cardTap.confirm.no"]]).toEqual(["Yes, I confirm", "No, this wasn't me"]);
    expect([fr["cardTap.confirm.yes"], fr["cardTap.confirm.no"]]).toEqual(["Oui, je confirme", "Non, ce n'était pas moi"]);
    expect([de["cardTap.confirm.yes"], de["cardTap.confirm.no"]]).toEqual(["Ja, ich bestätige", "Nein, das war ich nicht"]);
  });
});
