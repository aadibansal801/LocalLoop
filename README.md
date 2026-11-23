# LocalLoop

Authentication Milestone 1 is a Java 21 and Spring Boot 4.1.3 application with Thymeleaf, Spring Security sessions and Flyway-managed MySQL 8 tables.

## Start on Windows

Run these commands in PowerShell from the project directory. Use a JDK 21 installation for `JAVA_HOME`. The Maven Wrapper downloads Maven and dependencies on first use.

Start [native Mailpit](#verify-native-mysql-and-smtp) before requesting activation or reset links. LocalLoop sends mail to `127.0.0.1:1025` by default. Open the [Mailpit inbox](http://127.0.0.1:8025) to read the messages.

```powershell
java -version
Test-NetConnection localhost -Port 3306

$env:SPRING_DATASOURCE_URL = 'jdbc:mysql://localhost:3306/localloop'
$env:SPRING_DATASOURCE_USERNAME = 'localloop_app'
$env:SPRING_DATASOURCE_PASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host 'Local MySQL application password' -AsSecureString)).Password
$env:SPRING_MAIL_HOST = '127.0.0.1'
$env:SPRING_MAIL_PORT = '1025'
$env:APP_MAIL_FROM = 'localloop@example.test'

.\mvnw.cmd spring-boot:run
```

Use the pre-provisioned `localloop` database and `localloop_app` account. The account needs schema migration and application data permissions on that database. At startup Flyway applies `V1__auth_tables.sql` and records it in `flyway_schema_history`. Hibernate validates the resulting schema.

Open [LocalLoop](http://localhost:8081/login) after startup. Set `SERVER_PORT` if you need another local port. The default origin in activation and reset emails follows `SERVER_PORT`. If you already exported `APP_BASE_URL`, update it to match or clear it with `Remove-Item Env:APP_BASE_URL -ErrorAction SilentlyContinue`.

`.env.example` lists the settings. Spring Boot reads exported environment variables and does not load a `.env` file automatically. Set `ALLOWED_EMAIL_DOMAIN` to the exact campus domain if required. A blank value allows any valid supported address and offers no campus-membership assurance.

## Run tests

```powershell
.\mvnw.cmd test
```

The automated suite uses H2 in MySQL mode and fake email. It applies the same Flyway migration and exercises the Spring Security filter chain, Thymeleaf forms and embedded Tomcat. See [the test log](docs/TEST_LOG.md) for results and remaining live checks.

## Verify native MySQL and SMTP

1. Download and extract the Windows Mailpit binary. Run it in a separate PowerShell window. [Mailpit installation](https://mailpit.axllent.org/docs/install/)

   ```powershell
   .\mailpit.exe --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025
   ```

2. Start LocalLoop with the variables above. Check the startup log for Flyway validation and a running application. In another PowerShell window, query the migration history. MySQL prompts locally for the application password.

   ```powershell
   mysql.exe --protocol=TCP --host=localhost --port=3306 --user=localloop_app --password --database=localloop --execute='SELECT version, description, success FROM flyway_schema_history ORDER BY installed_rank; SHOW TABLES;'
   ```

   Expect a successful version `1` entry and the tables `users`, `email_action_tokens`, and `flyway_schema_history`.

3. Open [registration](http://localhost:8081/register), submit a new test address, and open the message in [Mailpit](http://127.0.0.1:8025). Open the activation link twice before submitting it, then set a display name and a password of 12–72 UTF-8 bytes. Submitting the same activation link again should fail.
4. Sign in, verify the name, email and USER role on the dashboard, then sign out. Sign in again in two separate browser profiles.
5. Once at least 60 seconds have passed since the last account email was issued, request a reset at [forgot password](http://localhost:8081/forgot-password). Open the new message, set a different password, and confirm that submitting the reset link again fails. Revisit the dashboard in both prior sessions and confirm both require sign-in. Confirm the old password fails and the new one succeeds.
6. Restart LocalLoop and confirm Flyway reports the schema is up to date.

If you see `Authentication email delivery failed`, check the listener with `Test-NetConnection 127.0.0.1 -Port 1025`. Start Mailpit if `TcpTestSucceeded` is false. Submit the same address again after the one-minute account cooldown to request a fresh link. A replacement link supersedes the previous link for its purpose.

## Production profile

Set `SPRING_PROFILES_ACTIVE=prod` with a public HTTPS `APP_BASE_URL`, valid TLS keystore settings (`SERVER_SSL_KEY_STORE`, `SERVER_SSL_KEY_STORE_PASSWORD`), and `SERVER_PORT` matching the deployed origin. Supply the datasource variables, `APP_MAIL_FROM` and `SPRING_MAIL_HOST`, `SPRING_MAIL_PORT`, `SPRING_MAIL_USERNAME`, `SPRING_MAIL_PASSWORD` for authenticated SMTP with STARTTLS. The app terminates TLS itself, uses secure session cookies and ignores forwarded headers. Configure the exact campus domain before using email addresses as a membership check.

Login allows 20 attempts per IP and 5 per normalized email per minute. Email requests allow 10 per IP and 3 per email per minute, with one send per account per minute. Link confirmations allow 15 per IP per minute. These bounded rate limits are local to one process. Requests behind a proxy share that proxy’s socket IP.
