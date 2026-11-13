import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/compare/linktree-alternative")({ head: ({ match }) => docHead("/compare/linktree-alternative", match.context.locale), component: Page });
function Page() { return <DocPage path="/compare/linktree-alternative" />; }
