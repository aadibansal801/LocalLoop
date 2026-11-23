package com.localloop.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailSendException;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.localloop.user.User;
import com.localloop.user.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:auth;MODE=MySQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa", "spring.datasource.password=",
        "app.allowed-email-domain=example.edu", "app.base-url=https://local.example.edu"
})
@ActiveProfiles("test")
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
@Import(AuthenticationTest.Fixtures.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthenticationTest {
    private static final String EMAIL = "member@example.edu";
    private static final String PASSWORD = "a secure password";
    private static final String NEW_PASSWORD = "a new secure password";
    private static final String ACK = "If the address is eligible, you’ll receive an email with next steps.";

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired TestClock clock;
    @Autowired FakeMail mail;
    @Value("${local.server.port}") int port;

    @BeforeEach
    void clean() {
        jdbc.update("delete from email_action_tokens");
        jdbc.update("delete from users");
        clock.advance(Duration.ofDays(2));
        mail.messages.clear();
        mail.fail = false;
    }

    @Test
    void publicFormsAndCsrf() throws Exception {
        mvc.perform(get("/dashboard")).andExpect(status().isFound())
                .andExpect(header().string("Location", endsWith("/login")));
        for (String path : List.of("/register", "/login", "/forgot-password")) {
            mvc.perform(get(path)).andExpect(status().isOk())
                    .andExpect(content().string(containsString("name=\"_csrf\"")));
        }
        mvc.perform(get("/register")).andExpect(content().string(not(containsString("name=\"password\""))));
        for (String path : List.of("/register", "/activate", "/login", "/logout", "/forgot-password", "/reset-password")) {
            mvc.perform(post(path)).andExpect(status().isForbidden());
        }
        assertThat(users.count()).isZero();
        assertThat(mail.messages).isEmpty();
    }

    @Test
    void registrationNormalizesEnforcesDomainAndSendsOnlyHashedToken() throws Exception {
        for (String address : List.of("member@sub.example.edu", "member@example.edu.invalid", "invalid", "")) {
            submitEmail("/register", address);
        }
        assertThat(users.count()).isZero();
        mvc.perform(post("/register").with(csrf()).param("email", "  MEMBER@Example.EDU  ")
                        .param("password", "attacker password").param("role", "ADMIN").param("disabled", "true")
                        .header("Host", "untrusted.example").header("X-Forwarded-Host", "untrusted.example"))
                .andExpect(redirectedUrl("/register")).andExpect(flash().attribute("message", ACK));
        User pending = users.findByEmail(EMAIL).orElseThrow();
        assertThat(pending.role()).isEqualTo(User.Role.USER);
        assertThat(pending.verified()).isFalse();
        assertThat(pending.disabled()).isFalse();
        assertThat(pending.displayName()).isNull();
        assertThat(pending.passwordHash()).isNull();
        assertThat(mail.messages).hasSize(1);
        assertThat(mail.messages.getFirst().recipient()).isEqualTo(EMAIL);
        URI link = mail.link();
        assertThat(link.getHost()).isEqualTo("local.example.edu");
        assertThat(link.getScheme()).isEqualTo("https");
        assertThat(link.getPath()).isEqualTo("/activate");
        String token = mail.token();
        assertThat(Base64.getUrlDecoder().decode(token)).hasSize(32);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII));
        assertThat(jdbc.queryForObject("select token_hash from email_action_tokens", String.class))
                .isEqualTo(HexFormat.of().formatHex(digest)).isNotEqualTo(token);

        submitEmail("/register", EMAIL);
        assertThat(mail.messages).hasSize(1);
        assertThat(users.count()).isEqualTo(1);
        clock.advance(Duration.ofMinutes(1));
        submitEmail("/register", EMAIL);
        assertThat(mail.messages).hasSize(2);
        assertThat(mail.token()).isNotEqualTo(token);
        mvc.perform(confirm("/activate", token, PASSWORD)).andExpect(model().attributeExists("error"));
        assertThat(jdbc.queryForObject("select count(*) from email_action_tokens", Integer.class)).isEqualTo(1);
    }

    @Test
    void activationRequiresValidNameAndPasswordAndNeverConsumesOnGet() throws Exception {
        String token = register();
        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/activate").param("token", token)).andExpect(status().isOk())
                    .andExpect(model().attribute("token", token))
                    .andExpect(content().string(containsString("name=\"_csrf\"")))
                    .andExpect(header().string("Cache-Control", containsString("no-store")))
                    .andExpect(header().string("Referrer-Policy", "no-referrer"));
        }
        mvc.perform(get("/activate").param("token", "<script>evil</script>"))
                .andExpect(content().string(not(containsString("<script>evil</script>"))));
        mvc.perform(confirm("/reset-password", token, PASSWORD)).andExpect(model().attributeExists("error"));
        mvc.perform(confirm("/activate", token, "short")).andExpect(model().attributeExists("error"));
        mvc.perform(confirm("/activate", token, "é".repeat(37))).andExpect(model().attributeExists("error"));
        mvc.perform(post("/activate").with(csrf()).param("token", token).param("password", PASSWORD)
                        .param("name", "  ")).andExpect(model().attributeExists("error"));
        String multibyte = "é".repeat(36);
        MvcResult result = mvc.perform(confirm("/activate", token, multibyte)).andExpect(redirectedUrl("/login"))
                .andReturn();
        User verified = users.findByEmail(EMAIL).orElseThrow();
        assertThat(verified.verified()).isTrue();
        assertThat(verified.role()).isEqualTo(User.Role.USER);
        assertThat(passwords.matches(multibyte, verified.passwordHash())).isTrue();
        assertThat(verified.passwordHash()).startsWith("$2").isNotEqualTo(multibyte);
        mvc.perform(get("/dashboard").session((MockHttpSession) result.getRequest().getSession(false)))
                .andExpect(header().string("Location", endsWith("/login")));
        mvc.perform(confirm("/activate", token, NEW_PASSWORD)).andExpect(model().attributeExists("error"));

        clock.advance(Duration.ofMinutes(1));
        submitEmail("/register", EMAIL);
        assertThat(mail.messages).hasSize(1);
        assertThat(users.findByEmail(EMAIL).orElseThrow().passwordHash()).isEqualTo(verified.passwordHash());
    }

    @Test
    void activationExpiresAtTwentyFourHours() throws Exception {
        String token = register();
        clock.advance(Duration.ofHours(24));
        mvc.perform(get("/activate").param("token", token)).andExpect(model().attributeDoesNotExist("token"));
        mvc.perform(confirm("/activate", token, PASSWORD)).andExpect(model().attributeExists("error"));
        assertThat(users.findByEmail(EMAIL).orElseThrow().verified()).isFalse();
    }

    @Test
    void userCannotAccessAdminAndLogoutRequiresAuthenticatedPost() throws Exception {
        String token = register();
        mvc.perform(login(EMAIL, PASSWORD)).andExpect(redirectedUrl("/login?error"));
        mvc.perform(confirm("/activate", token, PASSWORD)).andExpect(redirectedUrl("/login"));
        mvc.perform(login(EMAIL, "incorrect")).andExpect(redirectedUrl("/login?error"));
        MvcResult success = mvc.perform(login(" MEMBER@EXAMPLE.EDU ", PASSWORD))
                .andExpect(redirectedUrl("/dashboard")).andReturn();
        MockHttpSession session = (MockHttpSession) success.getRequest().getSession(false);
        mvc.perform(get("/dashboard").session(session)).andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;b&gt;Member&lt;/b&gt;")))
                .andExpect(content().string(containsString(EMAIL)))
                .andExpect(content().string(not(containsString(PASSWORD))));
        mvc.perform(get("/admin/reserved").session(session)).andExpect(status().isForbidden());
        mvc.perform(get("/logout").session(session)).andExpect(status().isNotFound());
        mvc.perform(post("/logout").session(session)).andExpect(status().isForbidden());
        assertThat(session.isInvalid()).isFalse();
        mvc.perform(post("/logout").session(session).with(csrf())).andExpect(redirectedUrl("/login?logout"));
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(post("/logout").with(csrf())).andExpect(header().string("Location", endsWith("/login")));
    }

    @Test
    void embeddedServerIssuesCookieAndRotatesItOnLogin() throws Exception {
        activate();
        URI login = URI.create("http://127.0.0.1:" + port + "/login");
        try (HttpClient client = HttpClient.newHttpClient()) {
            var page = client.send(HttpRequest.newBuilder(login).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertThat(page.statusCode()).isEqualTo(200);
            String initialCookie = page.headers().firstValue("Set-Cookie").orElseThrow();
            assertThat(initialCookie).contains("JSESSIONID=", "HttpOnly", "SameSite=Lax");
            var csrf = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(page.body());
            assertThat(csrf.find()).isTrue();
            var request = HttpRequest.newBuilder(login)
                    .header("Cookie", initialCookie.split(";", 2)[0])
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("username=member%40example.edu"
                            + "&password=a+secure+password&_csrf=" + csrf.group(1)))
                    .build();
            var response = client.send(request, HttpResponse.BodyHandlers.discarding());
            assertThat(response.statusCode()).isEqualTo(302);
            assertThat(response.headers().firstValue("Location").orElseThrow()).endsWith("/dashboard");
            String authenticatedCookie = response.headers().firstValue("Set-Cookie").orElseThrow();
            assertThat(authenticatedCookie).contains("HttpOnly", "SameSite=Lax").isNotEqualTo(initialCookie);

            for (String cookie : List.of(initialCookie, authenticatedCookie)) {
                var dashboard = HttpRequest.newBuilder(login.resolve("/dashboard"))
                        .header("Cookie", cookie.split(";", 2)[0]).GET().build();
                int expected = cookie.equals(initialCookie) ? 302 : 200;
                assertThat(client.send(dashboard, HttpResponse.BodyHandlers.discarding()).statusCode()).isEqualTo(expected);
            }
        }
    }

    @Test
    void disablingAccountRevokesSessionEvenOnPublicPage() throws Exception {
        activate();
        MockHttpSession session = signIn(PASSWORD);
        jdbc.update("update users set disabled = true where email = ?", EMAIL);
        mvc.perform(get("/login").session(session)).andExpect(status().isOk());
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(login(EMAIL, PASSWORD)).andExpect(redirectedUrl("/login?error"));
        submitEmail("/forgot-password", EMAIL);
        assertThat(mail.messages).hasSize(1);
    }

    @Test
    void resetHasGenericResponsesAndRevokesBothOldSessions() throws Exception {
        String activation = register();
        submitEmail("/forgot-password", EMAIL);
        submitEmail("/forgot-password", "unknown@example.edu");
        assertThat(mail.messages).hasSize(1);
        mvc.perform(confirm("/activate", activation, PASSWORD)).andExpect(redirectedUrl("/login"));
        MockHttpSession first = signIn(PASSWORD);
        MockHttpSession second = signIn(PASSWORD);
        String reset = requestReset();
        mvc.perform(get("/reset-password").param("token", reset)).andExpect(model().attribute("token", reset))
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
        mvc.perform(confirm("/activate", reset, NEW_PASSWORD)).andExpect(model().attributeExists("error"));
        mvc.perform(confirm("/reset-password", reset, "short")).andExpect(model().attributeExists("error"));
        mvc.perform(confirm("/reset-password", reset, "é".repeat(37))).andExpect(model().attributeExists("error"));
        MvcResult success = mvc.perform(confirm("/reset-password", reset, NEW_PASSWORD))
                .andExpect(redirectedUrl("/login")).andReturn();
        mvc.perform(get("/dashboard").session((MockHttpSession) success.getRequest().getSession(false)))
                .andExpect(header().string("Location", endsWith("/login")));
        mvc.perform(confirm("/reset-password", reset, PASSWORD)).andExpect(model().attributeExists("error"));
        for (MockHttpSession stale : List.of(first, second)) {
            mvc.perform(get("/dashboard").session(stale)).andExpect(header().string("Location", endsWith("/login")));
            assertThat(stale.isInvalid()).isTrue();
        }
        mvc.perform(login(EMAIL, PASSWORD)).andExpect(redirectedUrl("/login?error"));
        mvc.perform(get("/dashboard").session(signIn(NEW_PASSWORD))).andExpect(status().isOk());
        assertThat(users.findByEmail(EMAIL).orElseThrow().authVersion()).isEqualTo(1);
    }

    @Test
    void resetExpiresAtThirtyMinutes() throws Exception {
        activate();
        String token = requestReset();
        clock.advance(Duration.ofMinutes(30));
        mvc.perform(get("/reset-password").param("token", token)).andExpect(model().attributeDoesNotExist("token"));
        mvc.perform(confirm("/reset-password", token, NEW_PASSWORD)).andExpect(model().attributeExists("error"));
        assertThat(users.findByEmail(EMAIL).orElseThrow().authVersion()).isZero();
    }

    @Test
    void competingRequestsCreateOneAccountAndRedeemEachTokenOnce(CapturedOutput output) throws Exception {
        int start = output.getAll().length();
        assertThat(race(() -> statusOf(post("/register").with(csrf()).param("email", EMAIL))))
                .containsExactly(302, 302);
        assertThat(users.count()).isEqualTo(1);
        assertThat(mail.messages).hasSize(1);
        String activation = mail.token();
        assertThat(race(() -> statusOf(confirm("/activate", activation, PASSWORD)))).containsExactlyInAnyOrder(200, 302);
        String reset = requestReset();
        assertThat(race(() -> statusOf(confirm("/reset-password", reset, NEW_PASSWORD)))).containsExactlyInAnyOrder(200, 302);
        assertThat(users.findByEmail(EMAIL).orElseThrow().authVersion()).isEqualTo(1);
        assertThat(output.getAll().substring(start)).doesNotContain(EMAIL, activation, reset);
    }

    @Test
    void smtpFailureStaysGenericAllowsRetryAndDoesNotLogSecrets(CapturedOutput output) throws Exception {
        int start = output.getAll().length();
        mail.fail = true;
        submitEmail("/register", EMAIL);
        String failedToken = mail.token();
        assertThat(mail.messages).hasSize(1);
        mail.fail = false;
        submitEmail("/register", EMAIL);
        assertThat(mail.messages).hasSize(1);
        clock.advance(Duration.ofMinutes(1));
        submitEmail("/register", EMAIL);
        assertThat(mail.messages).hasSize(2);
        assertThat(mail.token()).isNotEqualTo(failedToken);
        mvc.perform(confirm("/activate", failedToken, PASSWORD)).andExpect(model().attributeExists("error"));
        mvc.perform(confirm("/activate", mail.token(), PASSWORD)).andExpect(redirectedUrl("/login"));
        mvc.perform(login(EMAIL, PASSWORD)).andExpect(redirectedUrl("/dashboard"));
        assertThat(output.getAll().substring(start)).contains("Authentication email delivery failed")
                .doesNotContain(EMAIL, failedToken, mail.token(), PASSWORD, "SMTP diagnostic");
    }

    @Test
    void ratesLimitNormalizedEmailAndSocketIpAndRecover() throws Exception {
        activate();
        for (int i = 0; i < 5; i++) {
            mvc.perform(atIp(login("MEMBER@example.edu", "wrong"), "192.0.2.30"))
                    .andExpect(redirectedUrl("/login?error"));
        }
        mvc.perform(atIp(login(EMAIL, PASSWORD), "192.0.2.5")).andExpect(redirectedUrl("/login?error"));

        clock.advance(Duration.ofSeconds(1));
        for (int i = 0; i < 20; i++) {
            mvc.perform(login("unknown" + i + "@example.edu", "wrong").header("X-Forwarded-For", "192.0.2." + i))
                    .andExpect(redirectedUrl("/login?error"));
        }
        for (int i = 0; i < 10; i++) {
            RequestBuilder request = atIp(post("/register").with(csrf()).param("email", "invalid")
                    .header("X-Forwarded-For", "192.0.2." + i), "192.0.2.10");
            mvc.perform(request).andExpect(redirectedUrl("/register")).andExpect(flash().attribute("message", ACK));
        }
        var secondRegistration = post("/register").with(csrf()).param("email", "second@example.edu");
        mvc.perform(atIp(secondRegistration, "192.0.2.10")).andExpect(flash().attribute("message", ACK));
        clock.advance(Duration.ofSeconds(59));
        mvc.perform(login(EMAIL, PASSWORD)).andExpect(redirectedUrl("/login?error"));
        mvc.perform(atIp(login(EMAIL, PASSWORD), "192.0.2.5")).andExpect(redirectedUrl("/dashboard"));
        mvc.perform(atIp(secondRegistration, "192.0.2.10")).andExpect(flash().attribute("message", ACK));
        assertThat(users.findByEmail("second@example.edu")).isEmpty();
        clock.advance(Duration.ofSeconds(1));
        mvc.perform(atIp(secondRegistration, "192.0.2.10")).andExpect(flash().attribute("message", ACK));
        assertThat(users.findByEmail("second@example.edu")).isPresent();
    }

    @Test
    void defaultEmailOriginFollowsServerPort() throws Exception {
        var environment = new MockEnvironment();
        environment.getPropertySources().addLast(new ResourcePropertySource("classpath:application.properties"));
        assertThat(new AuthSettings(environment).baseUrl).isEqualTo(URI.create("http://localhost:8081"));
        environment.setProperty("server.port", "8090");
        assertThat(new AuthSettings(environment).baseUrl).isEqualTo(URI.create("http://localhost:8090"));
    }

    @Test
    void limiterIsBoundedAndProdRejectsInsecureOrMissingConfiguration() {
        AuthRateLimit limiter = new AuthRateLimit(clock);
        for (int i = 0; i < 2_000; i++) {
            assertThat(limiter.allow(AuthRateLimit.Scope.LOGIN_EMAIL, "key" + i)).isTrue();
        }
        assertThat(limiter.allow(AuthRateLimit.Scope.LOGIN_EMAIL, "other")).isFalse();
        assertThat(limiter.allow(AuthRateLimit.Scope.MAIL_EMAIL, "other")).isTrue();
        clock.advance(Duration.ofMinutes(1));
        assertThat(limiter.allow(AuthRateLimit.Scope.LOGIN_EMAIL, "other")).isTrue();

        MockEnvironment environment = new MockEnvironment().withProperty("app.base-url", "http://localhost");
        environment.setActiveProfiles("prod");
        assertThatThrownBy(() -> new AuthSettings(environment)).hasMessageContaining("HTTPS");
        environment.setProperty("app.base-url", "https://localhost");
        environment.setProperty("app.mail-from", "localloop@example.test");
        assertThatThrownBy(() -> new AuthSettings(environment)).hasMessageContaining("spring.datasource.url");
    }

    private void submitEmail(String path, String email) throws Exception {
        mvc.perform(post(path).with(csrf()).param("email", email))
                .andExpect(redirectedUrl(path)).andExpect(flash().attribute("message", ACK));
    }

    private String register() throws Exception {
        submitEmail("/register", EMAIL);
        return mail.token();
    }

    private void activate() throws Exception {
        mvc.perform(confirm("/activate", register(), PASSWORD)).andExpect(redirectedUrl("/login"));
    }

    private String requestReset() throws Exception {
        clock.advance(Duration.ofMinutes(1));
        submitEmail("/forgot-password", EMAIL);
        assertThat(mail.link().getPath()).isEqualTo("/reset-password");
        return mail.token();
    }

    private static MockHttpServletRequestBuilder confirm(String path, String token, String password) {
        return post(path).with(csrf()).param("token", token).param("password", password)
                .param("name", "<b>Member</b>").param("role", "ADMIN");
    }

    private static MockHttpServletRequestBuilder login(String email, String password) {
        return post("/login").with(csrf()).param("username", email).param("password", password);
    }

    private static MockHttpServletRequestBuilder atIp(MockHttpServletRequestBuilder request, String ip) {
        return request.with(mock -> {
            mock.setRemoteAddr(ip);
            return mock;
        });
    }

    private MockHttpSession signIn(String password) throws Exception {
        ResultActions result = mvc.perform(login(EMAIL, password)).andExpect(redirectedUrl("/dashboard"));
        return (MockHttpSession) result.andReturn().getRequest().getSession(false);
    }

    private int statusOf(RequestBuilder request) throws Exception {
        return mvc.perform(request).andReturn().getResponse().getStatus();
    }

    private static <T> List<T> race(Callable<T> action) throws Exception {
        var workers = Executors.newFixedThreadPool(2);
        var barrier = new CyclicBarrier(2);
        try {
            Callable<T> competitor = () -> {
                barrier.await(5, TimeUnit.SECONDS);
                return action.call();
            };
            var first = workers.submit(competitor);
            var second = workers.submit(competitor);
            return List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
        } finally {
            workers.shutdownNow();
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Fixtures {
        @Bean @Primary FakeMail fakeMail() { return new FakeMail(); }
        @Bean @Primary TestClock testClock() { return new TestClock(); }
    }

    private static final class TestClock extends Clock {
        private volatile Instant now = Instant.parse("2026-11-22T00:00:00Z");

        void advance(Duration time) { now = now.plus(time); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now, zone); }
        @Override public Instant instant() { return now; }
    }

    private record Message(String recipient, String body) {}

    private static final class FakeMail implements EmailGateway {
        final List<Message> messages = new CopyOnWriteArrayList<>();
        volatile boolean fail;

        @Override
        public void send(String recipient, String subject, String body) {
            messages.add(new Message(recipient, body));
            if (fail) {
                throw new MailSendException("SMTP diagnostic " + body);
            }
        }

        URI link() { return URI.create(messages.getLast().body().lines().skip(2).findFirst().orElseThrow()); }
        String token() { return link().getQuery().substring("token=".length()); }
    }
}
