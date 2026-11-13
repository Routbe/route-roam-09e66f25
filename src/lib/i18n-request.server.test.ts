import { describe, expect, it, vi } from "vitest";

let current: Request | undefined;
vi.mock("@tanstack/react-start/server", () => ({
  getRequest: () => {
    if (!current) throw new Error("no request context");
    return current;
  },
}));

const { i18n } = await import("@/lib/i18n");
const { installRequestScopedTranslator, currentRequestLocale } = await import("./i18n-request.server");
installRequestScopedTranslator();

const req = (headers: Record<string, string>) => new Request("https://rout.be/info", { headers });

describe("server translations follow the request being rendered", () => {
  it("a Flemish request renders Dutch strings through the shared instance", () => {
    current = req({ "accept-language": "nl-BE,nl;q=0.9" });
    expect(i18n.t("menu.checkingSession")).toBe("Je sessie wordt gecontroleerd");
    expect(i18n.language).toBe("nl");
  });

  it("the rout_lang cookie wins over the browser language", () => {
    current = req({ "accept-language": "nl", cookie: "rout_lang=de" });
    expect(currentRequestLocale()).toBe("de");
    expect(i18n.t("menu.checkingSession")).toBe("Sitzung wird geprüft");
  });

  it("an explicit lng (getFixedT) is never overridden", () => {
    current = req({ "accept-language": "nl" });
    expect(i18n.getFixedT("fr")("menu.checkingSession")).toBe("Vérification de votre session");
  });

  it("outside a request the instance keeps its own language", () => {
    current = undefined;
    expect(currentRequestLocale()).toBeNull();
    expect(i18n.t("menu.checkingSession")).toBe("Checking your session");
  });
});
