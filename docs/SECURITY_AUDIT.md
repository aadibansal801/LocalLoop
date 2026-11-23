# Security Audit — Reference Node.js Backend (Sanitized)
**2026-11-22.** Inspected supplied `backend.zip` (ThreadIt Node.js/Express authentication subsystem), not a live deployment. Local dynamic probes used synthetic JWT secret, stubbed repository, and no outbound SMTP or external DB. Probe results are **isolated demonstrations**, not penetration-test proof of a production exploit.

## Reusable ideas
Layered controller/service/repository separation; BCrypt for passwords; PostgreSQL placeholders in queries; email ownership verification as a goal; Google ID-token audience/email_verified checks; HttpOnly/SameSite cookies; basic throttling.

## Findings and evidence
| ID | Severity | Evidence in uploaded archive | What was wrong / observed | LocalLoop action |
|---|---|---|---|---|
| A01 | Critical handling risk | `.env` is present inside archive; `src/modules/auth/auth.controller.js:7` and `middlewares/requireAuth.js:4` | Real-looking secret/credential fields included; hardcoded fallback JWT key. Values intentionally not retained here. | Do not import file; rotate exposed real secrets; env-only config, no fallback secret. |
| A02 | Critical functionality | `databse.sql:3-10,11-19`; `auth.repository.js:5,20,32,69` | SQL lacks `otp`, `otp_expires_at`, `is_verified`; missing `;` after refresh_tokens CREATE. Schema as supplied does not support code. | Versioned Flyway migrations + schema validation + integration smoke test. |
| A03 | High | `memoryState.js:3-12`, `auth.controller.js:159-163` | JWT revocation is process-local; simulated process reload removed revoked JTI. | Spring Security sessions; no JWT blacklist. |
| A04 | High | `auth.service.js:164-181` | refresh selects then deletes then inserts without an atomic consume. Two concurrent mock DB reads of same original succeeded. | No refresh-token rotation at all. |
| A05 | High | `auth.service.js:100-108,235-248` | OTP stored in plaintext and no per-code verification-attempt counter. 12 wrong OTP calls all reached `Invalid OTP` with no state mutation. | High-entropy hashed single-use email links, row-locked atomic consumption. |
| A06 | High | `auth.controller.js:212-224`, `auth.service.js:235-247` | Password-reset endpoint has no new-password length policy. Local probe accepted one character. | Shared password validator for activate/reset. |
| A07 | High | `auth.service.js:247-248`; `requireAuth.js:15-24` | Reset removes refresh tokens but an issued access JWT remains valid; demonstrated with mocked reset + signed test token. | Persist `authVersion` and check on every authenticated request. |
| A08 | High functionality | `middlewares/optionalAuth.js:2,12`, `memoryState.js:42` | `tokenBlacklist` import mismatches exported `tokenBlackList`; valid JWT ignored without error. | Use Spring Security authentication context, no duplicate optional auth implementation. |
| A09 | Medium | `core/memoryState.js:17-27` | `.digest('readUInt32BE')` returns a Buffer; numeric modulo yields NaN. Allocated username reported free in local test. Even a fixed Bloom filter can yield false positives and is not DB authority. | Do not implement Bloom filter; DB unique indexes. |
| A10 | Medium / context dependent | `auth.routes.js:17-19`, `app.js:8-15`, `auth.controller.js:156-182` | No CSRF middleware. Local handler accepts logout POST without CSRF token. SameSite Strict mitigates normal cross-site browser attacks; browser exploit not established. | Default Spring Security CSRF incl. login/logout/form actions. |
| A11 | Medium | `auth.service.js:75-98` | User persists before sending email; if sending fails, no resend route and user cannot create same account again. | Resend/cooldown and retry-safe email initiation. |
| A12 | Medium | `auth.controller.js:76-88,133-154`; `auth.service.js:139-158,216-232` | Signup/login normalization inconsistent; provider/verification-specific errors disclose status. Per-IP-only rate limiting is inadequate for targeted attacks. | Canonical email, generic public errors, restrained per-IP & per-account throttling. |
| A13 | Medium | `auth.repository.js:38-55`; SQL refresh token columns | Raw refresh tokens stored; `token_family` used as token itself, no family/replay tracking. | No refresh-token table. |
| A14 | Medium | `auth.service.js:75-98,100-109` | A third party can pre-register a victim email with a chosen password, and verification later could activate attacker-chosen credentials. Requires victim to follow verification; no live exploitation claimed. | Email-first registration; choose password only after possession proof. |
| A15 | Low / future | `auth.service.js:112-136` | Google ID-token verification has useful checks, but account linkage is bound to email/provider and lacks a separate provider-subject mapping. | Google sign-in deferred. If added later, use verified provider subject and explicit linking rules. |

## What was actually tested
An isolated Node harness reproduced **8/8 targeted behaviors**: Bloom false negative; optionalAuth ignores valid JWT; concurrent refresh reuse under mocked repository scheduling; one-character reset password accepted; 12 invalid OTP guesses with no per-code tracking; previously issued access JWT still accepted after reset; logout handler accepts request without a CSRF value; and blacklist state absent after module reload. No real SMTP/database or browser-level cross-site test was run. Schema errors are static findings only, not a live migration attempt. No claims of full penetration testing or live account takeover.

## Java authentication controls

- Registration accepts only a normalized email. The optional campus domain is matched exactly. A DB unique key and a retry after a conflicting insert handle concurrent signups. Role is set by the server.
- Activation and reset use 256-bit random tokens with SHA-256 hashes at rest. Links use the configured origin, and token pages use no-store and no-referrer. Redemption locks the account and conditionally consumes the token in the same transaction as the credential update.
- Both confirmation flows validate 12–72 UTF-8 bytes and use BCrypt. Form values and SMTP exceptions are excluded from application auth event logs. Hibernate constraint diagnostics are suppressed because they can contain submitted values.
- Spring Security gates login on verification and account status, rotates session IDs and protects unsafe methods with CSRF. Logout invalidates the session. Each authenticated request checks the account version and disabled flag. Reset advances that version, revoking prior sessions.
- Sessions are cookie-only with HttpOnly, SameSite=Lax and a 30-minute idle timeout. The production profile requires HTTPS, a secure session cookie and SMTP STARTTLS. Runtime credentials come from environment variables.
- Login, mail and token confirmations use bounded in-process rate limits keyed by socket IP and, where appropriate, normalized email. Mail is sent after commit. A failed send can be retried after the one-minute account cooldown.

## Remaining verification and limits

- Live MySQL locking and migration, SMTP delivery, and production TLS require the checks in [TEST_LOG.md](TEST_LOG.md) and the [README](../README.md).
- Synchronous SMTP can make eligible requests take longer despite identical HTTP responses. Rate-limit counters reset on restart and are local to one node. A proxy would aggregate clients under its socket IP.
- Reset or disabling takes effect when a session is next checked. A request already authorized before the credential change can finish. Any future role-change operation must also advance `authVersion`.
- The automated suite exercises the Milestone 1 flows. Interactive browser verification and production penetration testing were not performed.

References: OWASP Authentication, Forgot Password, Session Management, Password Storage, Logging cheat sheets; Spring Security reference for form login, CSRF, session fixation.
