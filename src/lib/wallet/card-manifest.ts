/**
 * Parses a writing-station manifest: one chip per line, "UID[,activation code]",
 * or a JSON array of { uid, activationCode? }. Raw UIDs only travel to the
 * server, which turns them into keyed hashes (sdm-tap.server.ts).
 */
export type ManifestCard = { uid: string; activationCode?: string };
export type ManifestParse = { ok: true; cards: ManifestCard[] } | { ok: false; error: string };

const UID = /^[0-9A-F]{14}$/;
const CODE = /^[0-9A-Z-]{4,32}$/;
export const MANIFEST_MAX_CARDS = 5000;

export function parseCardManifest(input: string): ManifestParse {
  const text = input.trim();
  if (!text) return { ok: false, error: "Het manifest is leeg." };
  let rows: { uid: unknown; activationCode?: unknown }[];
  if (text.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (!Array.isArray(parsed)) return { ok: false, error: "Ongeldig JSON-manifest." };
      rows = parsed as typeof rows;
    } catch {
      return { ok: false, error: "Ongeldig JSON-manifest." };
    }
  } else {
    rows = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => {
        const [uid, code] = l.split(/[,;\t]/).map((x) => x.trim());
        return code ? { uid, activationCode: code } : { uid };
      });
  }
  if (rows.length > MANIFEST_MAX_CARDS) return { ok: false, error: `Maximaal ${MANIFEST_MAX_CARDS} kaarten per import.` };
  const seen = new Set<string>();
  const cards: ManifestCard[] = [];
  for (const [i, r] of rows.entries()) {
    const uid = typeof r?.uid === "string" ? r.uid.replace(/[:\s]/g, "").toUpperCase() : "";
    if (!UID.test(uid)) return { ok: false, error: `Regel ${i + 1}: een UID is 14 hexadecimale tekens.` };
    if (seen.has(uid)) return { ok: false, error: `Regel ${i + 1}: dubbele UID.` };
    seen.add(uid);
    const rawCode = r?.activationCode;
    if (rawCode !== undefined && rawCode !== "") {
      const code = typeof rawCode === "string" ? rawCode.trim().toUpperCase() : "";
      if (!CODE.test(code)) return { ok: false, error: `Regel ${i + 1}: ongeldige activatiecode.` };
      cards.push({ uid, activationCode: code });
    } else cards.push({ uid });
  }
  return { ok: true, cards };
}
