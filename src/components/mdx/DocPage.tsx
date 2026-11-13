import { Suspense } from "react";
import { MDXProvider } from "@mdx-js/react";
import { DocsLayout } from "@/layouts/DocsLayout";
import { SEOLayout } from "@/layouts/SEOLayout";
import { getDoc } from "@/lib/docs-catalog";
import { mdxComponents } from "./components";
import { useI18n } from "@/lib/i18n";
import { docComponent } from "./doc-modules";
export function DocPage({ path }: { path: string }) {
  const { locale, t } = useI18n();
  const doc = getDoc(path, locale); const Content = docComponent(path, locale);
  if (!doc || !Content) return <p>Artikel niet beschikbaar.</p>;
  const Layout = ["about", "info", "dev", "safety"].includes(doc.category) ? DocsLayout : SEOLayout;
  return <Layout doc={doc}><MDXProvider components={mdxComponents}><Suspense fallback={<p className="text-muted-foreground">{t("docs.loading")}</p>}><Content /></Suspense></MDXProvider></Layout>;
}
