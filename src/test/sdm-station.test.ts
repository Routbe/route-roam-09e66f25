// @vitest-environment node
/** The station file must place the SDM mirrors exactly where the chip writes them. */
import { describe, expect, it } from "vitest";
import { sdmNdefFile, stationConfig } from "@/lib/vault/sdm-tap.server";

const ascii = (b: Uint8Array) => new TextDecoder().decode(b);
const BATCH = "11111111-2222-4333-8444-555555555555";

describe("NTAG 424 DNA station configuration", () => {
  it("builds a Type 4 NDEF file whose URL body starts at byte 7", () => {
    const { file, url } = sdmNdefFile("https://rout.be");
    expect(url).toBe(`https://rout.be/t?p=${"0".repeat(32)}&m=${"0".repeat(16)}`);
    const nlen = (file[0]! << 8) | file[1]!;
    expect(nlen).toBe(file.length - 2);
    expect(Array.from(file.slice(2, 7))).toEqual([0xd1, 0x01, file.length - 6, 0x55, 0x04]);
    expect(ascii(file.slice(7))).toBe(url.slice("https://".length));
  });

  it("points the PICCData and CMAC mirrors at the placeholders", () => {
    const { file, piccOffset, macOffset } = sdmNdefFile("https://rout.be");
    expect(ascii(file.slice(piccOffset - 2, piccOffset))).toBe("p=");
    expect(ascii(file.slice(piccOffset, piccOffset + 32))).toBe("0".repeat(32));
    expect(ascii(file.slice(macOffset - 2, macOffset))).toBe("m=");
    expect(ascii(file.slice(macOffset, macOffset + 16))).toBe("0".repeat(16));
    expect(macOffset + 16).toBe(file.length);
    // rout.be: URL body at 7, "rout.be/t?p=" is 12 chars, "&m=" 3 more after 32.
    expect(piccOffset).toBe(19);
    expect(macOffset).toBe(54);
  });

  it("encodes ChangeFileSettings with SDM on, encrypted UID+counter and keys 1/2", () => {
    const cfg = stationConfig(BATCH, "https://rout.be");
    expect(cfg.changeFileSettings.payloadHex).toBe("4000E0C1FF12" + "130000" + "360000" + "360000");
    expect(cfg.sdm.uidInPiccData).toBe(true);
    expect(cfg.sdm.encryptedPiccData.keyNo).toBe(1);
    expect(cfg.sdm.sdmMac.keyNo).toBe(2);
  });

  it("carries no key material and refuses a non-https origin", () => {
    const cfg = stationConfig(BATCH);
    const hexFields = JSON.stringify(cfg).match(/"\w*Hex"/g);
    expect(hexFields).toEqual(['"fileHex"', '"payloadHex"']);
    // The only long hex run in the file is the NDEF file itself, i.e. the public URL.
    expect(new TextDecoder().decode(Uint8Array.from(cfg.ndef.fileHex.match(/../g)!.map((h) => parseInt(h, 16))).slice(7))).toBe(cfg.ndef.urlTemplate.slice(8));
    expect(() => sdmNdefFile("http://rout.be")).toThrow();
  });
});
