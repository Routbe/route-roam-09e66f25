import { createFileRoute, redirect } from "@tanstack/react-router";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/about/badges")({ head: ({ match }) => docHead("/info/badges", match.context.locale), beforeLoad: () => { throw redirect({ href: "/info/badges", statusCode: 301 }); } });
