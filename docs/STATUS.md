# Authentication Milestone 1

Last updated 2026-11-23.

## Implemented

- Java 21, Spring Boot 4.1.3, Maven Wrapper, Thymeleaf, Spring Security and JPA.
- Flyway V1 for users and email action tokens, with Hibernate schema validation.
- Email-only registration, activation, login, logout and password recovery.
- Purpose-bound expiring tokens, atomic redemption, resend cooldown and SMTP retry.
- Protected dashboard, ADMIN restriction, CSRF, rate limits and session revocation after reset or account disabling.
- PowerShell setup for the pre-provisioned MySQL database and native Mailpit.

## Verification and next steps

- Clean Java 21 build and packaged application verified. All 14 automated tests passed, including the H2 Flyway migration, concurrent redemption, embedded Tomcat session rotation and local email origin configuration. See [TEST_LOG.md](TEST_LOG.md) and [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
- Native Mailpit accepted a loopback SMTP test message. The full activation and reset smoke against live MySQL is **NOT RUN**. The agent environment has no datasource credentials. See the [README](../README.md) for native verification steps.
- Profile editing, skills, requests, applications, discovery and admin screens remain deferred.
