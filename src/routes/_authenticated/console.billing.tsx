import { createFileRoute, Link } from "@tanstack/react-router";
import { Gauge, ReceiptText, ShieldCheck } from "lucide-react";
import { ConsoleCard, ConsolePage } from "@/components/console/ConsolePage";
import { useI18n } from "@/lib/i18n";
import { RATE_RULES } from "@/lib/rate-limit-rules";

export const Route = createFileRoute("/_authenticated/console/billing")({
  head: () => ({ meta: [
    { title: "Billing & Usage | ROUT Console" }, { name: "description", content: "Limieten, fair use en facturatie voor ROUT-integraties." },
    { property: "og:title", content: "Billing & Usage | ROUT Console" }, { property: "og:description", content: "Limieten, fair use en facturatie voor ROUT-integraties." },
    { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary" }, { name: "robots", content: "noindex,nofollow" },
  ]}), component: BillingConsole,
});

/** Limits shown here come from the same rules the server enforces. */
function BillingConsole() {
  const { t } = useI18n();
  const limits = [
    t("pages.developers.limit.token", { n: RATE_RULES.oauthToken.limit }),
    t("console.billing.limitAuthorize", { n: RATE_RULES.oauthAuthorize.limit }),
    t("pages.developers.limit.auth", { n: RATE_RULES.authAttempt.limit }),
    t("pages.developers.limit.app", { n: RATE_RULES.appCreate.limit }),
  ];
  return <ConsolePage title={t("console.billing.title")} description={t("console.billing.description")}>
    <div className="grid gap-4 md:grid-cols-2">
      <ConsoleCard title={t("console.billing.planTitle")}>
        <div className="flex items-start gap-3 text-sm text-muted-foreground">
          <ReceiptText className="mt-0.5 h-5 w-5 shrink-0 text-foreground" aria-hidden />
          <div className="space-y-2">
            <p className="font-medium text-foreground">{t("console.billing.planName")}</p>
            <p>{t("console.billing.planText")}</p>
          </div>
        </div>
      </ConsoleCard>
      <ConsoleCard title={t("console.billing.limitsTitle")}>
        <div className="flex items-start gap-3 text-sm text-muted-foreground">
          <Gauge className="mt-0.5 h-5 w-5 shrink-0 text-foreground" aria-hidden />
          <div className="space-y-3">
            <ul className="list-disc space-y-1 pl-4">{limits.map((l) => <li key={l}>{l}</li>)}</ul>
            <p>{t("console.billing.limitsText")}</p>
          </div>
        </div>
      </ConsoleCard>
    </div>
    <ConsoleCard title={t("console.billing.fairUseTitle")}>
      <div className="flex items-start gap-3 text-sm text-muted-foreground">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-foreground" aria-hidden />
        <div className="space-y-2">
          <p>{t("console.billing.fairUseText")}</p>
          <Link to="/terms" hash="api" className="inline-flex text-primary underline underline-offset-4">{t("console.billing.termsLink")}</Link>
        </div>
      </div>
    </ConsoleCard>
  </ConsolePage>;
}
