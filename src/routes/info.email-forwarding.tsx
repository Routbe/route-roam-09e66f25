import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/info/email-forwarding")({ head: ({ match }) => docHead("/info/email-forwarding", match.context.locale), component: Page });
function Page() { return <DocPage path="/info/email-forwarding" />; }
