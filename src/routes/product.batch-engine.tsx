import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/product/batch-engine")({ head: ({ match }) => docHead("/product/batch-engine", match.context.locale), component: Page });
function Page() { return <DocPage path="/product/batch-engine" />; }
