import { createFileRoute, redirect } from "@tanstack/react-router";
import { docHead } from "@/lib/docs-catalog";
export const Route = createFileRoute("/developer/credentials")({ head: ({ match }) => docHead("/dev/credentials-api", match.context.locale), beforeLoad: () => { throw redirect({ href: "/dev/credentials-api", statusCode: 301 }); } });
