import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/support/account/delete-account")({ head: ({ match }) => docHead("/support/account/delete-account", match.context.locale), component: Page });
function Page() { return <DocPage path="/support/account/delete-account" />; }
