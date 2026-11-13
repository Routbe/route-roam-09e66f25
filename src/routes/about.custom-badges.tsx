import { createFileRoute, redirect } from "@tanstack/react-router";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/about/custom-badges")({ head: ({ match }) => docHead("/info/custom-badges", match.context.locale), beforeLoad: () => { throw redirect({ href: "/info/custom-badges", statusCode: 301 }); } });
