import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/guide/")({ head: ({ match }) => docHead("/guide", match.context.locale), component: Page });
function Page() { return <DocPage path="/guide" />; }
