import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/safety/data-deletion")({ head: ({ match }) => docHead("/safety/data-deletion", match.context.locale), component: Page });
function Page() { return <DocPage path="/safety/data-deletion" />; }
