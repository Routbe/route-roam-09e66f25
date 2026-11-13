/**
 * Retry for SERIALIZABLE batches. Only 40001 (serialization_failure) and 40P01
 * (deadlock_detected) are retried: PostgreSQL rolled the whole transaction back,
 * so re-running it cannot double-apply. Every other error surfaces at once.
 */
export const RETRYABLE_SQLSTATES = new Set(["40001", "40P01"]);

export type RetryOptions = {
  attempts?: number;
  baseMs?: number;
  maxMs?: number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
};

export function isRetryableSqlError(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && RETRYABLE_SQLSTATES.has(code);
}

/** Exponential backoff with full jitter: delay in [0, min(maxMs, baseMs * 2^n)). */
export function backoffDelay(attempt: number, baseMs: number, maxMs: number, random: () => number): number {
  return Math.floor(random() * Math.min(maxMs, baseMs * 2 ** attempt));
}

export async function withSerializableRetry<T>(fn: () => Promise<T>, opts: RetryOptions = {}): Promise<T> {
  const attempts = opts.attempts ?? 5;
  const baseMs = opts.baseMs ?? 20;
  const maxMs = opts.maxMs ?? 500;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = opts.random ?? Math.random;
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (!isRetryableSqlError(err) || attempt + 1 >= attempts) throw err;
      await sleep(backoffDelay(attempt, baseMs, maxMs, random));
    }
  }
}
