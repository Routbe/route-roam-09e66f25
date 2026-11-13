import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/support/workspace/getting-started/invite-team")({ head: ({ match }) => docHead("/support/workspace/getting-started/invite-team", match.context.locale), component: Page });
function Page() { return <DocPage path="/support/workspace/getting-started/invite-team" />; }
