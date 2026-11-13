import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/safety/zero-knowledge")({ head: ({ match }) => docHead("/safety/zero-knowledge", match.context.locale), component: Page });
function Page() { return <DocPage path="/safety/zero-knowledge" />; }
