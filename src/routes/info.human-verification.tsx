import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/info/human-verification")({ head: ({ match }) => docHead("/info/human-verification", match.context.locale), component: Page });
function Page() { return <DocPage path="/info/human-verification" />; }
