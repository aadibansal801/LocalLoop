# Codex Task — Build LocalLoop Authentication Milestone 1

You are the implementation agent. Use GPT-6.2 Sol, high effort internally, but **optimize for low token use**: concise tool output and summaries, no repeated deliberation, no unsolicited architecture essays, no full-file dumps in final output. Solve and test autonomously. You have permission to add/edit files in this project, but **do not delete or overwrite unrelated existing work**.

## Read once and follow these handoff docs
1. `docs/ARCHITECTURE.md` — source of truth for product, stack, schema, security flows, routes and deferred features.
2. `docs/SECURITY_AUDIT.md` — reference Node implementation findings to avoid.
3. `docs/STATUS.md` and `docs/DECISIONS.md` — current progress and locked decisions.
4. `docs/TEST_LOG.md` — execution log and acceptance criteria.

If files are missing, use this prompt's constraints and create the small docs structure. **Do not extract/review `backend.zip` or `node_modules`; that audit is complete. Do not copy any secrets.** Inspect existing repository structure before changing files; if empty, initialize the project.

## Objective
Produce a **working, clean, secure, tested authentication vertical slice** for LocalLoop, not scaffolding or a prototype. Stack: Java 21, Spring Boot 4.1.3, Spring Security form/session auth, Spring MVC + Thymeleaf, Bootstrap/minimal CSS, MySQL 8, JPA, Flyway, Spring Mail, Maven Wrapper, JUnit/MockMvc. One deployable modular monolith. Use Spring Boot 4.1-compatible dependencies/imports (WebMVC starter instead of deprecated web starter), managed versions. Never introduce a React app, JWT, refresh-token service, Redis, microservices, OAuth, or unrelated product features.

## Build requirements (implement end to end)
1. **DB**: Flyway `V1__auth_tables.sql` for `users` + `email_action_tokens` exactly as in architecture docs; JPA `ddl-auto=validate`; normalized unique email; transactional token consumption and DB uniqueness/concurrency rules. Do not use `ddl-auto=update` or independent `schema.sql`.
2. **Email-first registration**: public registration takes **email only**, generic acknowledgment; optional exact `ALLOWED_EMAIL_DOMAIN`, normalized email. Only an email recipient following the activation link may set display name and password. Do not accept a password before email verification; no pre-registration takeover. Repeated registrations never replace a verified user's password and support resend/cooldown for pending users.
3. **Action tokens**: 32-byte CSPRNG URL-safe random link; save only SHA-256 token hash, purpose (ACTIVATE/RESET), expiry (24h/30m), one active token per purpose/user; single-use even with concurrent requests. `GET` displays form without consuming token; CSRF-protected `POST` performs consume + account state update transactionally. Build links from configured public base URL, not request Host. Handle expiry/replay/invalid purpose cleanly.
4. **Password policy**: validated *identically* on activation and reset (12–72 UTF-8 bytes for BCrypt); BCrypt hash at rest; no plaintext password storage or logging. Keep form input DTOs distinct from entities to prevent accidental binding of role/verification state.
5. **Login/logout**: use Spring Security formLogin / HttpSession rather than custom password-controller logic. Only verified, enabled users can log in; generic errors. Proper session fixation protection, HttpOnly+SameSite cookies, secure cookies under production HTTPS, session expiration, POST-only logout with CSRF. Minimal protected `/dashboard` showing current user's safe details. `/admin/**` reserved for ADMIN, public signup always USER. No unnecessary admin controller.
6. **Password recovery**: generic forgot-password response, separate short-lived RESET link, one-use reset; increment `authVersion` to invalidate *all* prior sessions. Check principal version + disabled flag against current DB state on **every authenticated request** (small query acceptable), invalidate stale sessions. Do not auto-login on reset/activation.
7. **Security hygiene**: leave Spring Security CSRF enabled on all unsafe requests. Include no-store/no-referrer on token-bearing pages. Guard all form fields and errors; Thymeleaf autoescaping; don't expose password hashes/tokens/stack traces. Conservative bounded auth request rate limiting (per IP and per normalized email as appropriate) and email issuance cooldown; document single-node limitations. No trust in arbitrary forwarded headers. Event logging only for sanitized authentication outcomes; no secrets/tokens in logs. Fail safely if required prod config missing.
8. **Email + development**: `EmailGateway` interface with SMTP implementation; in tests use a fake/capture sender, no outgoing network. Add `.env.example` with placeholders, `.gitignore`, and Windows-first README commands. Prefer optional minimal `compose.yaml` for MySQL+Mailpit, or clear manual local MySQL/SMTP setup. Never commit real secrets. SMTP failure must allow subsequent retry without exposing an action token.
9. **UI**: clean, responsive but simple Thymeleaf pages for register, activate/set password, login, forgot, reset, and dashboard; useful validation and redirect/flash messages. No UI framework beyond Bootstrap and tiny CSS. Limit dependencies to needed components.

## Tests — required, not optional
Run the Maven test suite and fix failures. Cover:
- Unauthenticated dashboard redirects; admin path denies USER; public signup cannot set role.
- Email normalization + duplicate handling + optional domain enforcement; registration doesn't accept/store a pre-verification password.
- Token stored hashed, wrong purpose/expired/replayed token rejected; two competing consume requests yield **at most one success**.
- Activation requires valid password and marks account verified; pending/disabled accounts cannot log in.
- Login good/bad password; session fixation defense where testable; logout invalidates session; missing CSRF on form POST is blocked.
- Forgot-password has generic response; reset enforces same password policy; used/expired reset token rejected; old authenticated session no longer works after reset.
- Rate limit/cooldown behavior, sanitized output/logs, invalid input. No outbound mail in tests.

Use appropriate JUnit + Spring MVC/Security tests and fast test database (H2 in MySQL mode if Flyway migration is compatible); document coverage gaps. Also perform a real MySQL migration/auth smoke run **if MySQL is available**, else explicitly mark it `NOT RUN` and provide the exact Windows steps. Do not silently skip tests or misreport success.

## Docs + low-token execution discipline
- Work sequentially in one coherent pass: inspect existing files once → minimal schema+entities → security config/auth services/controllers → Thymeleaf UI → targeted tests → run/fix → docs/README.
- Favor simple direct Java. No abstract repositories, custom security frameworks, excessive patterns, giant exception hierarchies, unused utilities, comments explaining obvious code, or duplicate tests. No premature refactoring or scope expansion.
- Retain `docs/ARCHITECTURE.md` as design contract. Update `docs/STATUS.md` with exact completed/remaining/checklist, `docs/TEST_LOG.md` with commands, real pass/fail counts and environment, `docs/SECURITY_AUDIT.md` with implemented mitigations and known gaps, and `docs/DECISIONS.md` **only** for changed material decisions. Documentation should be brief, factual and current. Never append long unstructured activity logs.
- Keep dependencies and file count minimal; format consistently; check `git diff --check`; verify no `.env`, credentials, private keys, raw tokens, or generated build outputs are tracked.
- When something fails, fix root cause and rerun relevant tests; avoid workaround chains. If tooling/DB/SMTP is missing, finish all other work, identify the blocker precisely, and give exact local verification command.
- Final response **max 200 words**: what runs, key files/features, command + exact test results, any remaining blockers, and next milestone. **Do not paste source files or recite your reasoning.**

## Definition of done
On a machine with required Java/MySQL/SMTP development services, user can request activation email → activate and choose password → log in → view authenticated dashboard → log out → request reset → reset password → old session denied → log in with new password. Security tests pass, migration is reproducible, and docs truthfully reflect what was verified. Do not implement skills/requests/applications until asked.
