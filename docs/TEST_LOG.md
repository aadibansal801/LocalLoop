# Test execution log
Record actual command, environment, result and remaining risk. Never claim a command ran if it did not. Keep latest execution at top.

## 2026-11-23 — Native SMTP recovery

- LocalLoop returned HTTP 200 on `127.0.0.1:8081/register`. The default SMTP port `1025` was initially unbound.
- Started native Mailpit 1.34.0 on loopback after verifying the release archive checksum. A synthetic message sent over SMTP was confirmed in the Mailpit inbox API.
- Windows sleep and resume events coincided with the Hikari housekeeping delays. The full application activation and reset smoke against MySQL remains **NOT RUN**.

## 2026-11-22 — Java authentication

- Windows, Microsoft OpenJDK 21.0.13.1, Maven 3.9.11, Spring Boot 4.1.3, H2 2.4.240 in MySQL mode, fake mail.
- `.\mvnw.cmd -B -ntp clean verify` **BUILD SUCCESS**. 14 tests passed, 0 failures, 0 errors, 0 skipped. Maven repackaged the executable application JAR.
- Flyway applied V1 and created migration history. Hibernate schema validation passed. Flyway warned that its latest verified H2 version is 2.3.232.
- MockMvc covered CSRF, normalization, domain checks, generic responses, HTML escaping, role restrictions, logout, SMTP failure recovery, rate limits and sanitized auth logs. The database tests covered expiring tokens, purpose isolation, replay, concurrent signup and redemption, and revocation of both prior sessions after reset. An embedded Tomcat request verified HttpOnly, SameSite=Lax and session cookie rotation.
- Windows reported `httpd` listening on port 8080 and accepted a test bind on 8081. The new configuration test verified that local email links use port 8081 by default and follow a `SERVER_PORT` override.
- `git diff --check` passed using a temporary Git index because the handoff contained no Git metadata. The index excluded local env files, key files and build output. The Unix wrapper passed `bash -n`.
- Live MySQL 8 migration and authentication smoke **NOT RUN**. The datasource environment variables are unset. Production TLS, browser smoke and Mailpit SMTP delivery were also **NOT RUN**. Follow the [Windows verification steps](../README.md#verify-native-mysql-and-smtp) against the existing database.

## 2026-11-22 — Reference Node.js review

An isolated Node.js harness reproduced 8/8 targeted weaknesses with mocked persistence and synthetic credentials. The source SQL was inspected statically. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Acceptance criteria
Registration and activation, verified login, pending and disabled account rejection, logout, generic recovery, single-use reset, prior-session revocation, CSRF enforcement, secret handling, migration on the intended MySQL version and reproducible startup.
