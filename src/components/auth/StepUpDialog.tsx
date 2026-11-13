import { useCallback, useEffect, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Fingerprint, KeyRound, LifeBuoy, Loader2, LockKeyhole, Mail, MessageSquare, Nfc, ShieldCheck } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { completeStepUp, getStepUpOptions, sendStepUpEmail, sendStepUpSms } from "@/lib/auth/step-up.functions";
import { beginCardStepUpFn, cardStepUpTapFn, claimCardStepUpFn } from "@/lib/auth/card-step-up.functions";
import { isStepUpRequiredError, type StepUpMethod } from "@/lib/auth/step-up-rules";
import { scanCardTaps, webNfcAvailable } from "@/lib/wallet/card-tap-url";
import { authClient } from "@/lib/auth-client";
import { i18n, useTranslation } from "@/lib/i18n";

/** ROUT card actions accept every active factor (SMS, recovery code, password too); a scan only a real second factor. */
export type StepUpScope = "card_reveal" | "card_lifecycle" | "card_scan";
type Waiter = { resolve: (ok: boolean) => void; action?: StepUpScope };
/** ROUT Card tap: an intent is open (waiting), this phone reads NFC (scanning), or it ended. */
type CardPhase = "idle" | "starting" | "waiting" | "scanning" | "checking" | "expired" | "failed";
const CARD_POLL_MS = 2000;
let opener: ((w: Waiter) => void) | null = null;

/** Opens the step-up dialog; resolves true once verified. */
export function requestStepUp(action?: StepUpScope): Promise<boolean> {
  return new Promise((resolve) => (opener ? opener({ resolve, action }) : resolve(false)));
}

/** Runs fn; on a 401 Step-Up Required asks for verification once and retries. */
export async function withStepUp<T>(fn: () => Promise<T>, action?: StepUpScope): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (!isStepUpRequiredError(e)) throw e;
    if (!(await requestStepUp(action))) throw new Error(i18n.t("stepUp.cancelled"));
    return fn();
  }
}

export function StepUpDialog() {
  const { t } = useTranslation();
  const [waiter, setWaiter] = useState<Waiter | null>(null);
  const [methods, setMethods] = useState<StepUpMethod[]>([]);
  const [method, setMethod] = useState<StepUpMethod | null>(null);
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const options = useServerFn(getStepUpOptions);
  const complete = useServerFn(completeStepUp);
  const sendEmail = useServerFn(sendStepUpEmail);
  const sendSms = useServerFn(sendStepUpSms);
  const beginCard = useServerFn(beginCardStepUpFn);
  const claimCard = useServerFn(claimCardStepUpFn);
  const tapCard = useServerFn(cardStepUpTapFn);
  const [cardPhase, setCardPhase] = useState<CardPhase>("idle");
  const [cardDeadline, setCardDeadline] = useState(0);
  const [now, setNow] = useState(0);
  const [nfc, setNfc] = useState(false);
  const scanAbort = useRef<AbortController | null>(null);
  const waiterRef = useRef<Waiter | null>(null);
  waiterRef.current = waiter;

  useEffect(() => {
    opener = (w) => {
      setWaiter(w);
      setCode("");
      setSecret("");
      setSent(false);
      setError(null);
      setLoaded(false);
      setMethods([]);
      setCardPhase("idle");
      void options({ data: w.action ? { action: w.action } : undefined }).then((r) => {
        setMethods(r.methods);
        setMethod(r.methods[0] ?? null);
        setLoaded(true);
      }).catch(() => setLoaded(true));
    };
    return () => {
      opener = null;
    };
  }, [options]);

  const stopScan = useCallback(() => {
    scanAbort.current?.abort();
    scanAbort.current = null;
  }, []);

  const close = useCallback((ok: boolean) => {
    stopScan();
    setCardPhase("idle");
    waiterRef.current?.resolve(ok);
    waiterRef.current = null;
    setWaiter(null);
  }, [stopScan]);

  useEffect(() => setNfc(webNfcAvailable()), []);

  // Choosing the card opens a single-use intent; the tap can then arrive here
  // (Web NFC), on /t in another tab, or on another signed-in phone.
  const startCard = useCallback(async () => {
    stopScan();
    setError(null);
    setCardPhase("starting");
    try {
      const action = waiterRef.current?.action;
      const r = await beginCard({ data: action === "card_reveal" || action === "card_lifecycle" ? { action } : {} });
      if (r.status === "waiting") {
        setCardDeadline(Date.now() + r.expiresInSec * 1000);
        setNow(Date.now());
        setCardPhase("waiting");
      } else {
        setError(t(r.status === "limited" ? "stepUp.cardLimited" : "stepUp.cardUnavailable"));
        setCardPhase("failed");
      }
    } catch {
      setError(t("ui.failed"));
      setCardPhase("failed");
    }
  }, [beginCard, stopScan, t]);

  useEffect(() => {
    if (waiter && method === "card" && cardPhase === "idle") void startCard();
    if (method !== "card") stopScan();
  }, [waiter, method, cardPhase, startCard, stopScan]);

  // Poll for a tap that completed elsewhere; also right away when the tab becomes visible again.
  useEffect(() => {
    if (method !== "card" || (cardPhase !== "waiting" && cardPhase !== "scanning")) return;
    let stopped = false;
    let inFlight = false;
    const tick = async () => {
      if (stopped || inFlight) return;
      setNow(Date.now());
      if (Date.now() >= cardDeadline) {
        stopScan();
        setCardPhase("expired");
        return;
      }
      inFlight = true;
      try {
        const r = await claimCard();
        if (!stopped && r.status === "done") close(true);
        else if (!stopped && r.status === "none") setCardPhase("expired");
      } catch {
        /* keep waiting; the deadline still ends it */
      } finally {
        inFlight = false;
      }
    };
    const id = window.setInterval(() => void tick(), CARD_POLL_MS);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    const onVisible = () => { if (document.visibilityState === "visible") void tick(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stopped = true;
      window.clearInterval(id);
      window.clearInterval(clock);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [method, cardPhase, cardDeadline, claimCard, close, stopScan]);

  useEffect(() => () => stopScan(), [stopScan]);

  async function scanWithThisPhone() {
    stopScan();
    const ctrl = new AbortController();
    scanAbort.current = ctrl;
    setError(null);
    setCardPhase("scanning");
    let handling = false;
    try {
      await scanCardTaps(ctrl.signal, (tap) => {
        if (handling || ctrl.signal.aborted) return;
        handling = true;
        setCardPhase("checking");
        void tapCard({ data: tap }).then((r) => {
          if (ctrl.signal.aborted) return;
          if (r.status === "done") return close(true);
          // The intent stays open: another tap (here or elsewhere) may still confirm.
          setError(t(r.status === "limited" ? "stepUp.cardLimited" : "stepUp.cardDenied"));
          setCardPhase(r.status === "limited" ? "failed" : "scanning");
        }).catch(() => {
          setError(t("ui.failed"));
          setCardPhase("scanning");
        }).finally(() => { handling = false; });
      }, () => setError(t("stepUp.cardUnreadable")));
    } catch {
      if (ctrl.signal.aborted) return;
      scanAbort.current = null;
      setError(t("stepUp.cardNfcBlocked"));
      setCardPhase("waiting");
    }
  }

  async function verify() {
    if (!method) return;
    setBusy(true);
    setError(null);
    try {
      const action = waiter?.action;
      if (method === "passkey") {
        const r = await authClient.signIn.passkey();
        if (r?.error) throw new Error(t("stepUp.passkeyFailed"));
        await complete({ data: { method, ...(action ? { action } : {}) } });
      } else if (method === "backup") {
        await complete({ data: { method, backupCode: secret.trim(), ...(action ? { action } : {}) } });
      } else if (method === "password") {
        await complete({ data: { method, password: secret, ...(action ? { action } : {}) } });
      } else {
        await complete({ data: { method, code, ...(action ? { action } : {}) } });
      }
      close(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("ui.failed"));
    } finally {
      setBusy(false);
    }
  }

  const label: Record<StepUpMethod, string> = { passkey: t("stepUp.passkey"), totp: t("stepUp.totp"), email: t("stepUp.email"), sms: t("stepUp.sms"), backup: t("stepUp.backup"), password: t("stepUp.password"), card: t("stepUp.card") };
  const icon = { passkey: Fingerprint, totp: KeyRound, email: Mail, sms: MessageSquare, backup: LifeBuoy, password: LockKeyhole, card: Nfc };
  const cardLeft = Math.max(0, Math.ceil((cardDeadline - now) / 1000));
  const cardOpen = cardPhase === "waiting" || cardPhase === "scanning" || cardPhase === "checking";
  const codeMethod = method === "totp" || ((method === "email" || method === "sms") && sent);
  const ready = method === "passkey" || (codeMethod && code.length === 6) || ((method === "backup" || method === "password") && secret.trim().length >= (method === "backup" ? 6 : 1));

  return (
    <Dialog open={!!waiter} onOpenChange={(o) => !o && close(false)}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" /> {t("stepUp.title")}
          </DialogTitle>
          <DialogDescription>{waiter?.action ? t("stepUp.cardDescription") : t("stepUp.description")}</DialogDescription>
        </DialogHeader>
        {loaded && waiter?.action && methods.length === 0 && (
          <p role="alert" className="rounded-md border border-border bg-muted p-2 text-sm">{t("stepUp.needTwoFactor")}</p>
        )}
        {methods.length > 1 && (
          <div className="flex flex-wrap gap-2">
            {methods.map((m) => {
              const I = icon[m];
              return (
                <Button key={m} size="sm" variant={m === method ? "default" : "outline"} onClick={() => { setMethod(m); setCode(""); setSecret(""); setSent(false); setError(null); if (m !== "card") { stopScan(); setCardPhase("idle"); } }} className="gap-1.5" aria-pressed={m === method}>
                  <I className="h-4 w-4" /> {label[m]}
                </Button>
              );
            })}
          </div>
        )}
        {method === "email" && (
          <p className="rounded-md border border-border bg-muted p-2 text-xs text-muted-foreground">
            {t("stepUp.emailHint")}
          </p>
        )}
        {method === "email" && !sent && (
          <Button variant="outline" disabled={busy} onClick={() => void sendEmail().then(() => setSent(true)).catch((e: Error) => setError(e.message))}>
            {t("stepUp.send")}
          </Button>
        )}
        {method === "sms" && !sent && (
          <Button variant="outline" disabled={busy} onClick={() => void sendSms().then(() => setSent(true)).catch((e: Error) => setError(e.message))}>
            {t("stepUp.sendSms")}
          </Button>
        )}
        {codeMethod && (
          <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="123456" value={code} aria-label={label[method!]}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
        )}
        {method === "backup" && (
          <Input autoComplete="off" spellCheck={false} maxLength={40} placeholder="xxxxx-xxxxx" value={secret} aria-label={label.backup}
            className="font-mono" onChange={(e) => setSecret(e.target.value)} />
        )}
        {method === "password" && (
          <Input type="password" autoComplete="current-password" maxLength={256} value={secret} aria-label={label.password}
            onChange={(e) => setSecret(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && ready) void verify(); }} />
        )}
        {method === "card" && (
          <div className="flex flex-col items-center gap-3 rounded-md border border-border bg-muted p-4 text-center" aria-live="polite">
            <div className="relative flex h-16 w-16 items-center justify-center">
              {cardOpen && <span className="absolute inset-0 rounded-full bg-primary/15 motion-safe:animate-ping" aria-hidden />}
              {cardPhase === "starting" || cardPhase === "checking"
                ? <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" aria-hidden />
                : <Nfc className="relative h-9 w-9 text-primary" strokeWidth={1.5} aria-hidden />}
            </div>
            {cardPhase === "expired" ? (
              <p className="text-sm">{t("stepUp.cardExpired")}</p>
            ) : cardOpen ? (
              <>
                <p className="text-sm font-medium">{cardPhase === "scanning" ? t("stepUp.cardScanning") : cardPhase === "checking" ? t("stepUp.cardChecking") : t("stepUp.cardTapHint")}</p>
                {nfc && cardPhase === "waiting" && (
                  <Button size="sm" className="gap-1.5" onClick={() => void scanWithThisPhone()}>
                    <Nfc className="h-4 w-4" aria-hidden /> {t("stepUp.cardScan")}
                  </Button>
                )}
                <p className="text-xs text-muted-foreground">{nfc ? t("stepUp.cardOtherDeviceNfc") : t("stepUp.cardOtherDevice")}</p>
                <p className="text-xs tabular-nums text-muted-foreground" role="timer">{t("stepUp.cardTimeLeft", { time: `${Math.floor(cardLeft / 60)}:${String(cardLeft % 60).padStart(2, "0")}` })}</p>
              </>
            ) : null}
          </div>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => close(false)}>{t("ui.cancel")}</Button>
          {method === "card" ? (
            (cardPhase === "expired" || cardPhase === "failed") && (
              <Button onClick={() => void startCard()}>{t("stepUp.cardRetry")}</Button>
            )
          ) : (
            <Button disabled={busy || !method || !ready} onClick={() => void verify()}>
              {method === "passkey" ? t("stepUp.usePasskey") : t("stepUp.confirm")}
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
