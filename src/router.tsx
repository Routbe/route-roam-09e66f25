import { QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";
import { preloadDoc } from "@/components/mdx/doc-modules";

export const getRouter = () => {
  const queryClient = new QueryClient();

  const router = createRouter({
    routeTree,
    context: { queryClient },
    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
    // Before hydration: load the server-rendered doc page's module so its HTML hydrates in place.
    hydrate: async () => {
      await preloadDoc(window.location.pathname, document.documentElement.lang || "en");
    },
  });

  return router;
};
