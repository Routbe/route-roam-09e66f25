import { lazy, type ComponentType, type LazyExoticComponent } from "react";

/**
 * MDX page modules keyed by `${path}:${locale}`. A page whose module was
 * preloaded before hydration renders synchronously inside its Suspense
 * boundary, so the server HTML hydrates in place instead of flashing the
 * loading text when any provider updates during hydration.
 */
type DocModule = { default: ComponentType };
const modules = import.meta.glob<DocModule>("/src/content/**/*.mdx");

const loaders = new Map<string, () => Promise<DocModule>>();
for (const [file, load] of Object.entries(modules)) {
  const locale = /\.(en|fr|de)\.mdx$/.exec(file)?.[1] ?? "nl";
  const path = file.replace("/src/content", "").replace(/\.(en|fr|de)\.mdx$/, ".mdx").replace(/\.mdx$/, "").replace(/\/index$/, "");
  loaders.set(`${path}:${locale}`, load);
}

const resolved = new Map<string, ComponentType>();
const lazies = new Map<string, LazyExoticComponent<ComponentType>>();

function keyFor(path: string, locale: string): string | null {
  const exact = `${path}:${locale}`;
  if (loaders.has(exact)) return exact;
  const fallback = `${path}:nl`;
  return loaders.has(fallback) ? fallback : null;
}

function load(key: string): Promise<ComponentType> {
  const loader = loaders.get(key);
  if (!loader) return Promise.reject(new Error(`unknown doc ${key}`));
  return loader().then((mod) => {
    resolved.set(key, mod.default);
    return mod.default;
  });
}

/** Component for a doc page: the real module when already loaded, otherwise a lazy wrapper. */
export function docComponent(path: string, locale: string): ComponentType | null {
  const key = keyFor(path, locale);
  if (!key) return null;
  const ready = resolved.get(key);
  if (ready) return ready;
  let lazyComponent = lazies.get(key);
  if (!lazyComponent) {
    lazyComponent = lazy(() => load(key).then((component) => ({ default: component })));
    lazies.set(key, lazyComponent);
  }
  return lazyComponent;
}

export function hasDoc(path: string, locale: string): boolean {
  return keyFor(path, locale) !== null;
}

/** Loads the doc module for a pathname, if one exists; never rejects. */
export async function preloadDoc(pathname: string, locale: string): Promise<void> {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  const key = keyFor(path, locale);
  if (!key || resolved.has(key)) return;
  await load(key).catch(() => undefined);
}
