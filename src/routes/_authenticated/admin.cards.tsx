import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Download, KeyRound, Loader2, Plus, ShieldOff, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  createCardBatchFn,
  exportCardBatchFn,
  importCardManifestFn,
  listCardBatchesFn,
  listCardStationsFn,
  registerCardStationFn,
  retireCardStationFn,
} from "@/lib/wallet/card-admin.functions";
import { parseCardManifest } from "@/lib/wallet/card-manifest";

export const Route = createFileRoute("/_authenticated/admin/cards")({
  head: () => ({
    meta: [
      { title: "ROUT Card-batches | ROUT" },
      { name: "description", content: "Productieruns van ROUT Cards: stations koppelen, batch aanmaken, versleutelde stationbundel exporteren en manifest importeren." },
      { name: "robots", content: "noindex, nofollow" },
      { property: "og:title", content: "ROUT Card-batches | ROUT" },
      { property: "og:description", content: "Productieruns van ROUT Cards beheren." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: AdminCards,
});

/** 64 hex in groups of four, so the admin can compare it with the station's display. */
const groupFp = (fp: string) => fp.match(/.{1,4}/g)?.join(" ") ?? fp;

function AdminCards() {
  const qc = useQueryClient();
  const list = useServerFn(listCardBatchesFn);
  const listStations = useServerFn(listCardStationsFn);
  const create = useServerFn(createCardBatchFn);
  const exportCfg = useServerFn(exportCardBatchFn);
  const importManifest = useServerFn(importCardManifestFn);
  const registerStation = useServerFn(registerCardStationFn);
  const retireStation = useServerFn(retireCardStationFn);
  const batches = useQuery({ queryKey: ["admin", "card-batches"], queryFn: () => list() });
  const stations = useQuery({ queryKey: ["admin", "card-stations"], queryFn: () => listStations() });
  const [label, setLabel] = useState("");
  const [stationLabel, setStationLabel] = useState("");
  const [stationKey, setStationKey] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [manifestFor, setManifestFor] = useState<string | null>(null);
  const [manifest, setManifest] = useState("");
  const [stationFor, setStationFor] = useState<Record<string, string>>({});

  const activeStations = (stations.data ?? []).filter((s) => !s.retiredAt);
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin"] });

  async function run(key: string, fn: () => Promise<void>, failure: string) {
    setBusy(key);
    setMessage(null);
    try {
      await fn();
    } catch {
      setMessage(failure);
    } finally {
      setBusy(null);
    }
  }

  const onCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!label.trim()) return;
    void run("create", async () => {
      await create({ data: { label: label.trim() } });
      setLabel("");
      setMessage("Batch aangemaakt.");
      await refresh();
    }, "Batch aanmaken mislukt.");
  };

  const onRegisterStation = (e: React.FormEvent) => {
    e.preventDefault();
    void run("station", async () => {
      const r = await registerStation({ data: { label: stationLabel.trim(), publicKey: stationKey.trim() } });
      if (!r.ok) {
        setMessage("Station geweigerd: de sleutel is geen geldige P-256 publieke sleutel, of is al gekoppeld.");
        return;
      }
      setStationLabel("");
      setStationKey("");
      setMessage(`Station gekoppeld. Controleer deze vingerafdruk op het station zelf: ${groupFp(r.fingerprint)}`);
      await refresh();
    }, "Station koppelen mislukt.");
  };

  const onRetireStation = (stationId: string, name: string) => {
    if (!window.confirm(`Station "${name}" definitief uitschakelen? Het krijgt daarna nooit meer sleutels.`)) return;
    void run(`retire:${stationId}`, async () => {
      const r = await retireStation({ data: { stationId } });
      setMessage(r.ok ? "Station uitgeschakeld." : "Uitschakelen geweigerd.");
      await refresh();
    }, "Uitschakelen mislukt.");
  };

  const onExport = (batchId: string) => {
    const stationId = stationFor[batchId] ?? activeStations[0]?.stationId;
    const station = activeStations.find((s) => s.stationId === stationId);
    if (!station) return;
    if (!window.confirm(`Sleutels van deze batch versleutelen voor "${station.label}"?\n\nVingerafdruk:\n${groupFp(station.fingerprint)}\n\nDeze export wordt in het beveiligingslogboek vastgelegd.`)) return;
    void run(`export:${batchId}`, async () => {
      const bundle = await exportCfg({ data: { batchId, stationId: station.stationId } });
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `rout-card-station-${batchId}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setMessage(`Stationbundel gedownload, versleuteld voor ${station.label}.`);
      await refresh();
    }, "Export geweigerd of mislukt.");
  };

  const onImport = (batchId: string) => {
    const cards = parseCardManifest(manifest);
    if (!cards.ok) {
      setMessage(cards.error);
      return;
    }
    void run(`import:${batchId}`, async () => {
      const r = await importManifest({ data: { batchId, cards: cards.cards } });
      setMessage(r.ok ? `${r.imported} kaarten geïmporteerd (bekende kaarten overgeslagen).` : "Import geweigerd.");
      if (r.ok) {
        setManifest("");
        setManifestFor(null);
      }
      await refresh();
    }, "Import mislukt.");
  };

  return (
    <main className="mx-auto max-w-4xl space-y-8 p-4 sm:p-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">ROUT Card-batches</h1>
        <p className="text-sm text-muted-foreground">
          Koppel een schrijfstation, maak een productierun en exporteer de stationbundel. De sleutels worden op de server versleuteld voor dat ene station (HPKE, P-256, AES-256-GCM); onversleuteld verlaten ze de server nooit.
        </p>
      </header>

      {message && (
        <p role="status" className="break-words rounded-xl border border-border bg-muted/40 p-3 text-sm">
          {message}
        </p>
      )}

      <section className="space-y-3" aria-labelledby="stations-title">
        <h2 id="stations-title" className="text-lg font-medium">Schrijfstations</h2>
        <form onSubmit={onRegisterStation} className="space-y-2 rounded-2xl border border-border bg-card p-4">
          <label className="block text-sm">
            <span className="mb-1 block text-muted-foreground">Naam van het station</span>
            <Input value={stationLabel} onChange={(e) => setStationLabel(e.target.value)} maxLength={80} placeholder="Station Brussel 1" />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-muted-foreground">Publieke sleutel van de beveiligde module (P-256, PEM of hex)</span>
            <Textarea
              value={stationKey}
              onChange={(e) => setStationKey(e.target.value)}
              rows={4}
              spellCheck={false}
              className="font-mono text-xs"
              placeholder={"-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----"}
            />
          </label>
          <Button type="submit" disabled={busy !== null || !stationLabel.trim() || stationKey.trim().length < 64}>
            {busy === "station" ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <KeyRound className="size-4" aria-hidden />} Station koppelen
          </Button>
        </form>
        {stations.isError ? (
          <p className="text-sm text-destructive">Stations konden niet geladen worden.</p>
        ) : (stations.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">Nog geen stations gekoppeld. Zonder station kun je geen bundel exporteren.</p>
        ) : (
          <ul className="space-y-2">
            {(stations.data ?? []).map((s) => (
              <li key={s.stationId} className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-3 rounded-2xl border border-border bg-card p-3">
                <div className="min-w-0">
                  <p className="truncate font-medium">
                    {s.label}
                    {s.retiredAt ? <span className="ml-2 text-xs text-muted-foreground">uitgeschakeld</span> : null}
                  </p>
                  <p className="break-all font-mono text-xs text-muted-foreground">{groupFp(s.fingerprint)}</p>
                </div>
                {!s.retiredAt && (
                  <Button size="sm" variant="outline" className="shrink-0" disabled={busy !== null} onClick={() => onRetireStation(s.stationId, s.label)}>
                    <ShieldOff className="size-4" aria-hidden /> Uitschakelen
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-3" aria-labelledby="batches-title">
        <h2 id="batches-title" className="text-lg font-medium">Batches</h2>
        <form onSubmit={onCreate} className="flex flex-col gap-2 rounded-2xl border border-border bg-card p-4 sm:flex-row sm:items-end">
          <label className="min-w-0 flex-1 text-sm">
            <span className="mb-1 block text-muted-foreground">Naam van de batch</span>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} placeholder="Batch 2026-A" />
          </label>
          <Button type="submit" disabled={busy !== null || !label.trim()}>
            {busy === "create" ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Plus className="size-4" aria-hidden />} Batch aanmaken
          </Button>
        </form>

        {batches.isPending ? (
          <Loader2 className="size-5 animate-spin text-muted-foreground" aria-label="Laden" />
        ) : batches.isError ? (
          <p className="text-sm text-destructive">Batches konden niet geladen worden. Je hebt de adminrol en tweestapsverificatie nodig.</p>
        ) : batches.data.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nog geen batches.</p>
        ) : (
          batches.data.map((b) => (
            <article key={b.batchId} className="space-y-3 rounded-2xl border border-border bg-card p-4">
              <div className="min-w-0">
                <h3 className="truncate font-medium">{b.label}</h3>
                <p className="text-xs text-muted-foreground">
                  {b.cards} kaarten · {b.activeCards} actief · aangemaakt {b.createdAt.slice(0, 10)}
                  {b.exportedAt ? ` · geëxporteerd ${b.exportedAt.slice(0, 10)}` : ""}
                  {b.retiredAt ? " · buiten gebruik" : ""}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Station voor deze export"
                  className="h-9 min-w-0 max-w-full rounded-md border border-input bg-background px-2 text-sm"
                  value={stationFor[b.batchId] ?? activeStations[0]?.stationId ?? ""}
                  onChange={(e) => setStationFor((m) => ({ ...m, [b.batchId]: e.target.value }))}
                  disabled={activeStations.length === 0 || !!b.retiredAt}
                >
                  {activeStations.length === 0 ? <option value="">Geen station</option> : null}
                  {activeStations.map((s) => (
                    <option key={s.stationId} value={s.stationId}>
                      {s.label} · {s.fingerprint.slice(0, 8)}
                    </option>
                  ))}
                </select>
                <Button size="sm" variant="outline" disabled={busy !== null || !!b.retiredAt || activeStations.length === 0} onClick={() => onExport(b.batchId)}>
                  {busy === `export:${b.batchId}` ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Download className="size-4" aria-hidden />} Stationbundel
                </Button>
                <Button size="sm" variant="outline" disabled={busy !== null || !!b.retiredAt} onClick={() => setManifestFor(manifestFor === b.batchId ? null : b.batchId)} aria-expanded={manifestFor === b.batchId}>
                  <Upload className="size-4" aria-hidden /> Manifest
                </Button>
              </div>
              {manifestFor === b.batchId && (
                <div className="space-y-2">
                  <Textarea
                    value={manifest}
                    onChange={(e) => setManifest(e.target.value)}
                    rows={6}
                    spellCheck={false}
                    className="font-mono text-xs"
                    placeholder={"Eén chip per regel: UID (14 hex), optioneel gevolgd door een komma en de activatiecode\n04A1B2C3D4E5F6,ABCD-1234"}
                  />
                  <Button size="sm" disabled={busy !== null || !manifest.trim()} onClick={() => onImport(b.batchId)}>
                    {busy === `import:${b.batchId}` ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null} Importeren
                  </Button>
                </div>
              )}
            </article>
          ))
        )}
      </section>
    </main>
  );
}
