import { createFileRoute, redirect } from "@tanstack/react-router";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/developer/ai-mcp")({ head: ({ match }) => docHead("/dev/ai-mcp", match.context.locale), beforeLoad: () => { throw redirect({ href: "/dev/ai-mcp", statusCode: 301 }); } });
