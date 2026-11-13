import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/safety/terms")({ head: ({ match }) => docHead("/safety/terms", match.context.locale), component: Page });
function Page() { return <DocPage path="/safety/terms" />; }
