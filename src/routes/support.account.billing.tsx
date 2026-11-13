import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/support/account/billing")({ head: ({ match }) => docHead("/support/account/billing", match.context.locale), component: Page });
function Page() { return <DocPage path="/support/account/billing" />; }
