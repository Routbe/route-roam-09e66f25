import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/features/cookieless-analytics")({ head: ({ match }) => docHead("/features/cookieless-analytics", match.context.locale), component: Page });
function Page() { return <DocPage path="/features/cookieless-analytics" />; }
