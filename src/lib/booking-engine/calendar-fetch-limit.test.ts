import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = { hits: 0, fail: false };
vi.mock("@/lib/neon", () => ({
  sql: vi.fn(async () => {
    if (state.fail) throw new Error("unavailable");
    state.hits += 1;
    // Start of the window on the database clock, no hits in the previous window.
    return [{ hits: state.hits, prev: 0, now_ms: 0 }];
  }),
}));

import { allowCalendarFetch } from "./calendar-fetch-limit.server";

beforeEach(() => { state.hits = 0; state.fail = false; });
afterEach(() => vi.restoreAllMocks());

it("allows a member 20 calendar fetches per hour and refuses the 21st", async () => {
  for (let i = 0; i < 20; i++) expect(await allowCalendarFetch("member-a")).toBe(true);
  expect(await allowCalendarFetch("member-a")).toBe(false);
});

it("refuses calendar fetches when the shared counter is unavailable", async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  state.fail = true;
  expect(await allowCalendarFetch("member-a")).toBe(false);
});
