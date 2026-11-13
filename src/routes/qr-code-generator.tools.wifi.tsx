import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/qr-code-generator/tools/wifi")({ head: ({ match }) => docHead("/qr-code-generator/tools/wifi", match.context.locale), component: Page });
function Page() { return <DocPage path="/qr-code-generator/tools/wifi" />; }
