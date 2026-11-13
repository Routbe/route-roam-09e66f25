import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/features/link-management")({ head: ({ match }) => docHead("/features/link-management", match.context.locale), component: Page });
function Page() { return <DocPage path="/features/link-management" />; }
