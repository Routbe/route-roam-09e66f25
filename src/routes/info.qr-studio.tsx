import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/info/qr-studio")({ head: ({ match }) => docHead("/info/qr-studio", match.context.locale), component: Page });
function Page() { return <DocPage path="/info/qr-studio" />; }
