# LocalLoop — Architecture Contract
Status: approved for Authentication Milestone 1 (2026-11-22). This file defines design constraints, not proof of implementation.

## Product / delivery scope
LocalLoop is a college/community skill-discovery and collaboration platform. Two entry points will eventually exist: (1) post a request for help and receive applications; (2) discover a member advertising skills/availability and approach them. Start as a single-campus, no-payment app. Later: profiles/skills, requests, applications, discovery, minimal admin. **This milestone implements authentication only.** No search, messaging, Google OAuth, AI ranking, payments, repository integration, microservices, or GPS now.

## Stack and physical boundaries
- Java 21; Spring Boot **4.1.3** (patched release), Maven Wrapper, Spring MVC, Thymeleaf/Bootstrap, Spring Security, Spring Data JPA, Bean Validation, MySQL 8, Flyway with MySQL support, Spring Mail, SLF4J, JUnit/MockMvc. Use Boot dependency management; no unnecessary version overrides.
- One deployable Spring Boot **modular monolith**, one MySQL database, server-rendered HTML and same-origin requests. Default session-based login with Spring Security. **No JWT / refresh tokens / blacklist / Redis.**
- Runtime config from env vars/profiles; never commit passwords, SMTP credentials, or action tokens. `.env.example` only. Dev/test e-mail via local Mailpit SMTP or test double; never send real mail in tests.
- In production, enforce HTTPS and secure cookies. Local HTTP is permitted for development only. No trust of arbitrary `X-Forwarded-For` headers.

## Package-by-feature layout (initial code)
```
src/main/java/com/localloop/
  LocalLoopApplication.java
  config/SecurityConfig.java
  auth/AuthController.java
  auth/AuthService.java
  auth/EmailActionToken.java
  auth/EmailActionTokenRepository.java
  auth/EmailGateway.java
  auth/SmtpEmailGateway.java
  auth/AuthenticatedUser.java
  auth/CustomUserDetailsService.java
  auth/AuthVersionFilter.java
  user/User.java
  user/UserRepository.java
  common/ [only if a genuine shared concern emerges]
src/main/resources/
  db/migration/V1__auth_tables.sql
  templates/ [login, register, activate, forgot-password, reset-password, dashboard]
  static/css/ [one small stylesheet or Bootstrap CDN-free/local as practical]
src/test/...
```
Names are guidance, not a mandate for extra abstraction. Future sibling packages: `profile`, `skill`, `request`, `application`, `discovery`, `admin`. No empty placeholders now.

## Security design — email-first account activation
**Do not accept/store a chosen password before the user proves ownership of the email address.** This avoids the pre-registration trap where an attacker registers another person's email with an attacker-controlled password and the recipient later verifies that account.
1. `GET/POST /register`: collect email only. Normalize trim/lowercase; validate address and optional exact configured campus domain. For an eligible address, create an unverified account and issue an activation link, subject to cooldown. Existing unverified account may have its link reissued; existing verified account is left unchanged. Respond generically in all cases. No login session created.
2. Activation link: 32 cryptographically random bytes, URL-safe encoded. Store **only SHA-256 hash** in DB. Mail includes absolute link built from trusted configured `app.base-url`, never from request Host. Expiry: 24 h. One active token per user+purpose; replacing a token invalidates the prior one.
3. `GET /activate?token=...`: render name+new-password form but **do not consume on GET** (email scanners prefetch links). `POST /activate`: CSRF protected; under transaction lock token/user, recheck purpose, expiry, unused status and user state, validate name/password, hash BCrypt, mark verified, consume token. Single use even under concurrent POSTs. Redirect to login; no auto-login.
4. Spring Security handles `POST /login` and `POST /logout`; `GET /login` is custom Thymeleaf. Only verified, enabled users with password hash can log in. Default role is USER; never accept role from request. Session ID rotates on login, logout invalidates session. `/dashboard` authenticated; `/admin/**` ADMIN only (no admin UI in milestone).
5. `GET/POST /forgot-password`: generic acknowledgment for every input regardless of account existence/type; if verified local account exists, issue short-lived (30-minute) distinct RESET token, subject to cooldown. `GET /reset-password?token=...` displays form without consuming; CSRF-protected `POST /reset-password` uses it once atomically, sets BCrypt password, increments user `authVersion`, consumes token, redirects to login. Reset does not log the user in.
6. Every protected request compares the `authVersion` captured in session principal at login against the user's current DB value. On mismatch or disabled user, invalidate session and deny/redirect. This makes password resets and administrative disabling effective for old sessions without Spring Session/Redis. Cost: one small DB read per authenticated request, acceptable for single-campus MVP. Test this behavior.

## DB source of truth
Flyway exclusively manages schema; Hibernate `ddl-auto=validate` (never update/create). MySQL 8 migration V1:
- `users`: id BIGINT auto-increment PK; email VARCHAR(254) NOT NULL UNIQUE (stored lowercase); display_name nullable until activation; password_hash nullable until activation; role VARCHAR(16) DEFAULT 'USER'; email_verified_at nullable; disabled BOOLEAN NOT NULL default false; auth_version BIGINT NOT NULL default 0; last_auth_email_at nullable; created_at/updated_at timestamps. Future profile/skills fields can be introduced in later migrations only.
- `email_action_tokens`: id BIGINT PK; user_id FK users; purpose VARCHAR(24) (ACTIVATE/RESET); token_hash CHAR(64) NOT NULL UNIQUE; expires_at timestamp; consumed_at nullable; created_at timestamp; UNIQUE(user_id, purpose) so rotation replaces existing purpose token. Use row locking, transaction, and conditional updates to prevent double consume.
- DB uniqueness, not Bloom filters, decides duplicates. Handle racing inserts by catching uniqueness exceptions and showing generic responses. Do not include unneeded tables or premature indexes.

## Security defaults / edge conditions
- Password policy for creation and reset: 12–72 **UTF-8 bytes** with BCrypt (prevent 72-byte truncation), max request body size, validation on server, generic login errors. No plaintext anywhere at rest or in logs. Follow current Spring Security BCrypt support; work factor may use Spring defaults unless benchmark warrants tuning.
- Session: HttpOnly cookie; SameSite=Lax, Secure=true in HTTPS production, reasonable idle timeout (30 min), CSRF on **all** unsafe methods including login, logout, token confirmation. Configure security headers and prevent caching/referrer leakage on pages displaying tokens (`Cache-Control: no-store`, `Referrer-Policy: no-referrer`). Never use `GET` for state-changing operations.
- Authentication and mail issuance: simple, bounded rate limits for one-node deployment: login attempts by client IP and normalized email; activation/reset mail issuance per account/email with cooldown, and modest IP limit. Limit storage growth; no self-built distributed limiter. Explicitly document limits under multi-node deployment. Never trust forwarded client IP unless trusted proxy is configured.
- Token handling: no token/password/session data in application logs, error pages, or database log dumps. Avoid third-party scripts/analytics and external resources on token-bearing pages. Do not reveal whether an email account exists, including via status codes, timing where practical, or provider-specific errors.
- Username generation, Google sign-in, multi-factor authentication, account deletion, and invitation-only registration are deferred. Email-domain policy is configurable (`ALLOWED_EMAIL_DOMAIN`); blank in local demo is permissible but must be clearly stated as **not** strong community verification.
- Mail delivery: after DB transaction commits, send synchronously via an `EmailGateway` interface and SMTP implementation; tests use a fake. Failed sends must not disclose tokens and must have a documented retry/resend path with cooldown. No background queues or custom outbox in MVP.

## URLs and authorization contract
| Method / route | Access | Behavior |
|---|---|---|
| GET, POST `/register` | public | email-only initiation; generic response |
| GET `/activate?token=...` | public | view form, no mutation |
| POST `/activate` | public + CSRF | one-use activation and password setup |
| GET `/login` | public | form |
| POST `/login` | Spring Security form login | creates session |
| POST `/logout` | authenticated + CSRF | invalidates session |
| GET, POST `/forgot-password` | public | generic response; issue reset if eligible |
| GET `/reset-password?token=...` | public | view form, no mutation |
| POST `/reset-password` | public + CSRF | reset password and revoke old sessions |
| GET `/dashboard` | authenticated | minimal landing with name/email/role only |
| `/admin/**` | ADMIN | reserve restriction; don't implement admin screens yet |

## Future domain design (DO NOT IMPLEMENT IN AUTH MILESTONE)
- `skills` + `user_skills`; `service_requests` owned by a user, status OPEN/IN_PROGRESS/COMPLETED/CANCELLED; `request_required_skills`; `applications` applicant/request/status with UNIQUE(request_id, applicant_id). Profiles expose only approved public data.
- Request owner alone accepts/rejects applicants; applicant cannot apply to own request; one accepted collaborator in MVP, transactional updates to avoid double acceptance. Search is ordinary SQL filters first; optional simple deterministic ranking later.
- Moderation roles are server-controlled; no code hosting, source sharing, payments or messaging required to demonstrate collaboration lifecycle.

## Build/test/deployment constraints
- Use plain controllers+services+repositories, DTO/form objects only when necessary, no generic base classes, no unnecessary interfaces except `EmailGateway`, no Lombok unless clearly justifiable, no event bus or CQRS.
- Boot version **4.1.3**: prefer `spring-boot-starter-webmvc` (not the deprecated `spring-boot-starter-web`); check official Boot 4 test dependencies/imports rather than copying Boot 3 sample imports. Use Spring Boot Maven parent for managed versions.
- Add Maven Wrapper for Windows and Linux. Add README with MySQL + Mailpit setup, environment variables, commands, and exact manual browser demo. Tests must work without real SMTP. Prefer H2 for fast local tests when migrations are portable; also verify one actual MySQL schema migration/smoke run when available. Never claim MySQL integration tested if it was not.
