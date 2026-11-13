import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Loader2, LogOut, ShieldCheck, ShieldX } from "lucide-react";

import { AdminPortalContext } from "@/components/admin/AdminPortalNav";
import { AppLayout } from "@/components/layout/AppLayout";
import { TwoFactorSetup } from "@/components/auth/TwoFactorSetup";
import { Button } from "@/components/ui/button";
import { myAdminPermissions } from "@/lib/admin-access.functions";
import { adminAccessDecision } from "@/lib/auth/sign-in-policy";
import { authClient } from "@/lib/auth-client";

export const Route = createFileRoute("/_authenticated/admin")({
  head: () => ({ meta: [{ title: 'ROUT — Administration' }, { name: "description", content: 'Manage the ROUT platform.' }, { property: "og:title", content: 'ROUT — Administration' }, { property: "og:description", content: 'Manage the ROUT platform.' }, { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" }] }), 
  component: AdminPortalLayout,
});

/** Admins see the portal only once 2FA is on; the server enforces the same rule on every admin call. */
function AdminPortalLayout() {
  const fetchAccess = useServerFn(myAdminPermissions);
  const access = useQuery({ queryKey: ["admin-access"], queryFn: () => fetchAccess(), staleTime: 60_000, retry: false });

  if (access.isLoading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  const data = access.data;
  const isAdmin = Boolean(data && (data.fullAdmin || data.permissions.length > 0));
  // No data (error or refusal) counts as no access: non-admins never see an admin screen.
  const decision = data && !access.isError ? adminAccessDecision(isAdmin, data.twoFactorEnabled) : "forbidden";
  if (decision === "forbidden") return <AdminForbidden />;
  if (decision === "two_factor_setup_required") {
    return <AdminTwoFactorRequired onEnabled={() => void access.refetch()} />;
  }

  return (
    <AdminPortalContext.Provider value={true}>
      <Outlet />
    </AdminPortalContext.Provider>
  );
}

function AdminForbidden() {
  const { t } = useTranslation();
  return (
    <AppLayout>
      <div className="flex min-h-[calc(100vh-4rem)] w-full items-center justify-center bg-background p-4 text-foreground">
        <div role="alert" className="w-full max-w-md space-y-4 rounded-2xl border border-border bg-card p-5 sm:p-7">
          <h1 className="flex items-center gap-2 font-display text-2xl text-foreground">
            <ShieldX className="h-5 w-5 text-destructive" aria-hidden /> {t("admin.forbidden.title")}
          </h1>
          <p className="text-sm text-muted-foreground">{t("admin.forbidden.body")}</p>
          <Button asChild className="w-full"><Link to="/dashboard">{t("admin.forbidden.back")}</Link></Button>
        </div>
      </div>
    </AppLayout>
  );
}

function AdminTwoFactorRequired({ onEnabled }: { onEnabled: () => void }) {
  const { t } = useTranslation();
  const signOut = async () => {
    await authClient.signOut().catch(() => null);
    window.location.replace("/auth/sign-in");
  };
  return (
    <AppLayout>
      <div className="flex min-h-[calc(100vh-4rem)] w-full items-center justify-center bg-background p-4 text-foreground">
        <div className="w-full max-w-md space-y-4 rounded-2xl border border-border bg-card p-5 sm:p-7">
          <div className="space-y-1">
            <h1 className="flex items-center gap-2 font-display text-2xl text-foreground">
              <ShieldCheck className="h-5 w-5 text-primary" aria-hidden /> {t("auth.mf.setupTitle")}
            </h1>
            <p className="text-sm text-muted-foreground">{t("auth.mf.setupAdminBody")}</p>
          </div>
          <TwoFactorSetup onEnabled={onEnabled} />
          <Button type="button" variant="ghost" onClick={() => void signOut()} className="w-full gap-2 text-muted-foreground">
            <LogOut className="h-4 w-4" /> {t("auth.mf.signOut")}
          </Button>
        </div>
      </div>
    </AppLayout>
  );
}
