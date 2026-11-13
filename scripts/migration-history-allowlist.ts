/**
 * Acknowledged historical deviations in public.schema_migrations (Neon).
 *
 * Each entry pins the exact checksum Neon recorded. A row is accepted only
 * when filename AND checksum match an entry here; anything else is reported
 * by scripts/migration-history-check.ts. Neon's rows are never rewritten.
 *
 * Analysed read-only on 2026-11-13: none of the recorded texts exists in any
 * commit of the repository, so none can be restored byte for byte.
 */
export type AcknowledgedHistory = {
  filename: string;
  /** sha256 exactly as stored in public.schema_migrations.checksum */
  neonChecksum: string;
  /** file-removed: no file in db/ anymore. edited-after-apply: file in db/ differs from what ran. */
  kind: "file-removed" | "edited-after-apply";
  reason: string;
};

export const ACKNOWLEDGED_HISTORY: readonly AcknowledgedHistory[] = [
  {
    filename: "95_question_stories.sql",
    neonChecksum: "9e282f2bb6c5c67743864d20dd511dd6a32a1a588e9d4a8755b7dcc0dc035fa5",
    kind: "file-removed",
    reason: "profile_questions.story_until + index now live in 0000_baseline.sql; see db-archive/95_question_stories.sql",
  },
  {
    filename: "0169_workspace_icon.sql",
    neonChecksum: "9568b4ef232aaeedd02ee9b590894bb8175f1f6851a197eba556d14a15d443f7",
    kind: "file-removed",
    reason: "duplicate number 0169; re-issued as 0172_workspace_icon.sql; see db-archive/0169_workspace_icon.sql",
  },
  {
    filename: "0209_recovery_vault_pairwise.sql",
    neonChecksum: "44ae1db9679dd0ec2ce4524198f5f3044146b1f87be4424eb6fcb6cff06387ac",
    kind: "edited-after-apply",
    reason: "its 3-of-5 recovery objects were removed by 0243; rout_pairwise_register re-pinned to pg_catalog by 0254",
  },
  {
    filename: "91_shadowban.sql",
    neonChecksum: "4187079478efaf76e14560e1913148ae8200d695fe3f9cc81ec28426f18147c9",
    kind: "edited-after-apply",
    reason: "text edited after apply; profiles.is_shadowbanned exists in Neon and in 0000_baseline.sql",
  },
];
