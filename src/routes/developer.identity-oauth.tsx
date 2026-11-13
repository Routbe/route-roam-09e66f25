import { createFileRoute, redirect } from "@tanstack/react-router";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/developer/identity-oauth")({ head: ({ match }) => docHead("/dev/identity-oidc", match.context.locale), beforeLoad: () => { throw redirect({ href: "/dev/identity-oidc", statusCode: 301 }); } });
