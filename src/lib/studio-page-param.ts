/** Only `booking` opens a Studio page from the URL; anything else is dropped. */
export function studioPageParam(value: unknown): "booking" | undefined {
  return value === "booking" ? "booking" : undefined;
}
