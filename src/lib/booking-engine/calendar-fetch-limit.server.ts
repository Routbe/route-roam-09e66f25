import { hitRateLimit } from "@/lib/rate-limit-db.server";
import { RATE_RULES } from "@/lib/rate-limit-rules";

/**
 * Adding or refreshing an outside calendar makes the server fetch an address
 * the member chose. Each member gets RATE_RULES.calendarFetch of those per
 * window across every instance; an unavailable counter refuses.
 */
export async function allowCalendarFetch(userId: string): Promise<boolean> {
  const r = await hitRateLimit("booking_calendar_fetch", userId, RATE_RULES.calendarFetch, { failClosed: true });
  return r.ok;
}
