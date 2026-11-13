import { createFileRoute } from "@tanstack/react-router";
import { DocPage } from "@/components/mdx/DocPage";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/qr-code-generator/media/image")({ head: ({ match }) => docHead("/qr-code-generator/media/image", match.context.locale), component: Page });
function Page() { return <DocPage path="/qr-code-generator/media/image" />; }
