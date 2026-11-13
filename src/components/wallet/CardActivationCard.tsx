import { useState } from "react";
import { Nfc } from "lucide-react";
import { Button } from "@/components/ui/button";
import { startActivationIntent } from "@/lib/wallet/card-activation-intent";

/** "Activeer je ROUT Card": arms the next tap on /t (this tab, 5 minutes). */
export function CardActivationCard() {
  const [armed, setArmed] = useState(false);
  return (
    <section aria-labelledby="rout-card-activate" className="space-y-3 rounded-2xl border border-border bg-card p-4 sm:p-5">
      <h2 id="rout-card-activate" className="flex items-center gap-2 text-lg font-medium">
        <Nfc className="size-4" aria-hidden /> Fysieke ROUT Card
      </h2>
      {armed ? (
        <div role="status" className="space-y-2 text-sm text-muted-foreground">
          <p className="font-medium text-foreground">Houd je nieuwe ROUT Card tegen de achterkant van je telefoon.</p>
          <p>Open de link die verschijnt in dit venster. Je hebt 5 minuten; daarna start je opnieuw.</p>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">Nieuwe kaart ontvangen? Koppel ze met één tik aan je account. Een kaart kan maar één keer gekoppeld worden.</p>
      )}
      <Button
        variant={armed ? "outline" : "default"}
        onClick={() => {
          startActivationIntent();
          setArmed(true);
        }}
      >
        {armed ? "Opnieuw starten" : "Activeer je ROUT Card"}
      </Button>
    </section>
  );
}
