# Architecture Decision Log (short ADRs)
Keep entries to 3–6 lines. Record decisions that change interfaces, dependencies, security, or scope. Do not record every minor refactor.

## ADR-001 — 2026-11-22 — Spring Boot modular monolith
**Status:** accepted. **Context:** Three students and an academic delivery; minimize integration work. **Decision:** one Java 21/Spring Boot 4.1.3 process, Thymeleaf views, MySQL, Maven. **Alternatives:** Node, React SPA + API, microservices. **Consequence:** fast single-deploy demo; separate React/API possible later but is not required now.

## ADR-002 — 2026-11-22 — Spring Security session instead of JWT
**Status:** accepted. **Context:** The reference custom JWT implementation contains revocation/race pitfalls; app is same-origin server-rendered. **Decision:** built-in form login + HttpSession, CSRF enabled, session fixation defense. **Consequence:** dramatically less bespoke auth code; browser cookie sessions, not mobile API tokens.

## ADR-003 — 2026-11-22 — Email-first activation + random action links
**Status:** accepted. **Context:** Prevent pre-registration with attacker-chosen password and OTP brute force. **Decision:** collect email first; only recipient chooses password after single-use 256-bit link. Store SHA-256 hash and purpose/expiry in DB. **Consequence:** SMTP setup required for manual activation; no six-digit OTP UI.

## ADR-004 — 2026-11-22 — Versioned SQL and simple session invalidation
**Status:** accepted. **Context:** Reference SQL drifts from queries; password resets need to revoke old sessions. **Decision:** Flyway-only schema, `ddl-auto=validate`; increment `authVersion` on reset and compare for each authenticated request. **Consequence:** small DB lookup per protected request; avoids additional Spring Session infrastructure in this milestone.

## ADR-005 — 2026-11-22 — Limits for first assessment
**Status:** accepted. **Decision:** No Google OAuth, AI, paid services, public REST API, frontend SPA, admin screens, skill/request modules or background workers in authentication milestone. **Consequence:** implement and test one coherent vertical slice; future modules fit modular-monolith packages.

## ADR-006 — 2026-11-22 — Native Windows integration services
**Status:** accepted. **Decision:** Use the existing local MySQL 8 database and native Mailpit for Windows smoke tests. Automated tests run the same V1 migration on H2 in MySQL mode with fake email.
**Consequence:** Startup reads shared datasource configuration from environment variables. Live MySQL and SMTP checks run using the [README](../README.md).
