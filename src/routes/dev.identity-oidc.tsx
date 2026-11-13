import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/dev/identity-oidc")({ head: ({ match }) => docHead("/dev/identity-oidc", match.context.locale), component: Page });
function Page() { return <DocPage path="/dev/identity-oidc" />; }
