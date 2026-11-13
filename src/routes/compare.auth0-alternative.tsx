import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/compare/auth0-alternative")({ head: ({ match }) => docHead("/compare/auth0-alternative", match.context.locale), component: Page });
function Page() { return <DocPage path="/compare/auth0-alternative" />; }
