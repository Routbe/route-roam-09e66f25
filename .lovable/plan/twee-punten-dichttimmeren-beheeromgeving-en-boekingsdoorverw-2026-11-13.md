# Twee punten dichttimmeren: beheeromgeving en boekingsdoorverwijzing

Gelezen vóór dit plan: `docs/HANDOVER.md` (de regels daaruit volg ik), `_authenticated/admin.tsx`, `_authenticated/studio_.booking.tsx`, `studio.tsx`, `Studio.tsx`, `admin-access.*` en `sign-in-policy.ts`. Externe diensten (Stripe, Scaleway, Apple/Google Wallet) blijven liggen tot de commerciële lancering.

## 1. Beheeromgeving houdt niet-beheerders tegen in het scherm zelf

**Wat nu gebeurt:** de omgeving vraagt je rechten op, maar weigert alleen beheerders zonder tweestapsverificatie. Een gewone gebruiker krijgt toch de beheerpagina te zien, die daarna faalt op de server.

**Wat ik ga doen:**
- De bestaande regel `adminAccessDecision` volledig toepassen. Bij "geen toegang" (geen beheerder, of rechten konden niet geladen worden) verschijnt één nette pagina met "Geen toegang tot beheer", een korte uitleg en een knop terug naar je dashboard. Er wordt dan geen enkel beheerscherm getoond en er gaan geen beheeraanvragen naar de server.
- Tweestapsverificatie blijft verplicht voor beheerders, net als nu.
- De beveiliging op de server blijft ongewijzigd; dit is een extra laag in het scherm.
- De nieuwe teksten komen in de vier talen in `src/locales/pages/interface.{nl,en,fr,de}.json`.

## 2. `/studio/booking` komt gegarandeerd op de boekingspagina

**Oorzaak:** de doorverwijzing gaat naar `/studio?page=booking`, maar `/studio` laat alleen `mode`, `type`, `url` en `workspace` toe. Daardoor valt `page` uit het adres. Studio leest `page` rechtstreeks uit de adresbalk en opent zo de profielbouwer in plaats van de boekingen.

**Wat ik ga doen:**
- `page` toevoegen aan de toegelaten adresparameters van `/studio` (alleen de waarde `booking`, andere waarden worden genegeerd).
- Studio laat de boekingspagina openen op basis van die gecontroleerde waarde, ook wanneer je binnen de app navigeert en niet alleen bij het laden van de pagina.
- De doorverwijzing zonder de `as never`-omweg, zodat een fout in de toekomst al bij het bouwen opvalt.

## Controle

- Twee kleine tests naast de bestaande:
  - de toegangsregel: geen beheerder geeft "geen toegang", beheerder zonder tweestapsverificatie moet die eerst instellen, beheerder met tweestapsverificatie mag erin;
  - `/studio` houdt `page=booking` vast en negeert onbekende waarden.
- De bestaande admin-, studio- en boekingstests opnieuw draaien.
- Een echte inlog-test in de voorvertoning is niet mogelijk zolang de app-databaseverbinding ontbreekt. Wil je dat ik dat ook in de browser controleer, dan vraag ik op dat moment de `DATABASE_URL` (`rout_app`) via het beveiligde formulier.

## Technische details

- `src/routes/_authenticated/admin.tsx`: `decision = data ? adminAccessDecision(isAdmin, data.twoFactorEnabled) : "forbidden"` (ook bij `access.isError`); bij `"forbidden"` een `AdminForbidden`-scherm in `AppLayout` met `Link to="/dashboard"`; `retry: false` op de query zodat een weigering niet blijft herhalen.
- `src/routes/studio.tsx`: `page: search["page"] === "booking" ? "booking" as const : undefined` in `validateSearch`.
- `src/components/imported-pages/Studio.tsx`: `useSearch({ strict: false })` lezen en `setPageMode("booking")` bij `page === "booking"`; de huidige `window.location`-check vervalt.
- `src/routes/_authenticated/studio_.booking.tsx`: `redirect({ to: "/studio", search: { page: "booking" }, replace: true })`.
- Geen wijzigingen aan de database, de kluis, de migraties of de serverbeveiliging.
