import { useEffect, useState } from "react";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import { canSwitchShellMode, detectShellMode, isAdminPath, MODE_OVERRIDE_KEY, type ShellMode } from "@/lib/app-mode";
import { cn } from "@/lib/utils";

/** Floating [Publiek] / [Admin] switch for development and previews; never on pinned builds. */
export function DevModeToggle() {
  const navigate = useNavigate();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [visible, setVisible] = useState(false);
  const [open, setOpen] = useState(false);
  useEffect(() => setVisible(canSwitchShellMode()), []);
  if (!visible) return null;
  // The admin sign-in lives on /auth too, so the stored override decides there.
  const active: ShellMode = isAdminPath(path) || (path.startsWith("/auth") && detectShellMode() === "admin") ? "admin" : "public";

  const pick = (mode: ShellMode) => {
    try {
      window.localStorage.setItem(MODE_OVERRIDE_KEY, mode);
    } catch {
      /* storage blocked */
    }
    if (mode === "public" && path.startsWith("/auth")) window.location.assign("/auth/sign-in");
    else void navigate({ to: mode === "admin" ? "/admin" : "/" } as never);
  };

  // Studio has its own fixed bottom action bar below lg; the switch would cover it.
  // On phones the switch collapses to one small chip so it never covers page content.
  return (
    <div role="group" aria-label="Weergave wisselen" className={cn("fixed bottom-[max(1rem,env(safe-area-inset-bottom))] right-4 z-[100] flex items-center gap-1 rounded-full border-2 border-primary bg-background p-1 text-sm font-medium shadow-xl", path.startsWith("/studio") && "hidden lg:flex")}>
      <button type="button" aria-expanded={open} onClick={() => setOpen((v) => !v)} className="min-h-11 rounded-full px-3 text-xs uppercase tracking-wide text-muted-foreground sm:hidden">
        {open ? "×" : active === "public" ? "Publiek" : "Admin"}
      </button>
      <span className="hidden px-2 text-xs uppercase tracking-wide text-muted-foreground sm:inline">Omgeving</span>
      {(["public", "admin"] as const).map((m) => (
        <button
          key={m}
          type="button"
          aria-pressed={active === m}
          onClick={() => pick(m)}
          className={cn("min-h-11 rounded-full px-3", open ? "inline-flex items-center" : "hidden sm:inline-flex sm:items-center", active === m ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")}
        >
          {m === "public" ? "Publiek" : "Admin"}
        </button>
      ))}
    </div>
  );
}
