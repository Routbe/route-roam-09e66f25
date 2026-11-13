// @vitest-environment node
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ACKNOWLEDGED_HISTORY } from "../../scripts/migration-history-allowlist";
import { checksumOf, historyFindings, listMigrationFiles, pendingFiles } from "../../scripts/migration-plan";

const ROOT = join(__dirname, "..", "..");
const DB_DIR = join(ROOT, "db");
const current = new Map(listMigrationFiles(DB_DIR).map((f) => [f, checksumOf(readFileSync(join(DB_DIR, f), "utf8"))]));

describe("migration history check", () => {
  const ack = [
    { filename: "95_gone.sql", neonChecksum: "aaa", kind: "file-removed" as const },
    { filename: "91_edited.sql", neonChecksum: "bbb", kind: "edited-after-apply" as const },
  ];
  const files = new Map([
    ["91_edited.sql", "file91"],
    ["92_ok.sql", "file92"],
  ]);

  it("accepts a removed file only with the exact recorded checksum", () => {
    expect(historyFindings([{ filename: "95_gone.sql", checksum: "aaa" }], files, ack)).toEqual([]);
    expect(historyFindings([{ filename: "95_gone.sql", checksum: "zzz" }], files, ack)).toEqual([
      { filename: "95_gone.sql", problem: "missing-file", recorded: "zzz" },
    ]);
  });

  it("accepts an edited file only with the exact recorded checksum", () => {
    expect(historyFindings([{ filename: "91_edited.sql", checksum: "bbb" }], files, ack)).toEqual([]);
    expect(historyFindings([{ filename: "91_edited.sql", checksum: "ccc" }], files, ack)[0]?.problem).toBe("checksum-drift");
  });

  it("reports an unacknowledged drift or missing file", () => {
    expect(historyFindings([{ filename: "92_ok.sql", checksum: "other" }], files, ack)[0]?.problem).toBe("checksum-drift");
    expect(historyFindings([{ filename: "93_unknown.sql", checksum: "x" }], files, ack)[0]?.problem).toBe("missing-file");
  });

  it("passes a fresh database where the edited file was recorded with its current checksum", () => {
    expect(historyFindings([{ filename: "91_edited.sql", checksum: "file91" }], files, ack)).toEqual([]);
  });

  it("flags a removed-file acknowledgement when the file is back in db/", () => {
    const back = new Map([...files, ["95_gone.sql", "restored"]]);
    expect(historyFindings([{ filename: "95_gone.sql", checksum: "aaa" }], back, ack)[0]?.problem).toBe("acknowledged-file-present");
  });

  it("lists files without a row as pending, not as findings", () => {
    expect(pendingFiles([{ filename: "92_ok.sql", checksum: "file92" }], ["91_edited.sql", "92_ok.sql"])).toEqual(["91_edited.sql"]);
  });
});

describe("acknowledged history in this repository", () => {
  it("names exactly the four deviations found in Neon on 2026-11-13", () => {
    expect(ACKNOWLEDGED_HISTORY.map((a) => [a.filename, a.kind])).toEqual([
      ["95_question_stories.sql", "file-removed"],
      ["0169_workspace_icon.sql", "file-removed"],
      ["0209_recovery_vault_pairwise.sql", "edited-after-apply"],
      ["91_shadowban.sql", "edited-after-apply"],
    ]);
    for (const a of ACKNOWLEDGED_HISTORY) expect(a.neonChecksum).toMatch(/^[0-9a-f]{64}$/);
  });

  it("keeps removed files out of db/ and documented in db-archive/", () => {
    for (const a of ACKNOWLEDGED_HISTORY.filter((x) => x.kind === "file-removed")) {
      expect(current.has(a.filename)).toBe(false);
      expect(existsSync(join(ROOT, "db-archive", a.filename))).toBe(true);
    }
  });

  it("keeps edited files in db/ with a checksum that differs from the acknowledged one", () => {
    for (const a of ACKNOWLEDGED_HISTORY.filter((x) => x.kind === "edited-after-apply")) {
      expect(current.get(a.filename)).toBeDefined();
      expect(current.get(a.filename)).not.toBe(a.neonChecksum);
    }
  });
});

describe("0254 pairwise register hardening", () => {
  const sql = readFileSync(join(DB_DIR, "0254_pairwise_register_search_path.sql"), "utf8");

  it("pins search_path to pg_catalog and never grants PUBLIC", () => {
    expect(sql).toMatch(/security definer set search_path = pg_catalog as/);
    expect(sql).not.toMatch(/search_path (=|to) 'public'/);
    expect(sql).toMatch(/revoke execute on function public\.rout_pairwise_register\(text, text, text\) from public/);
    expect(sql).not.toMatch(/grant [^;]* to public/i);
  });
});
