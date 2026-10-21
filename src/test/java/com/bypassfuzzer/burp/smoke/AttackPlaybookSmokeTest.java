package com.bypassfuzzer.burp.smoke;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.core.urlvalidation.UrlValidationAttackSetting;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationCandidateFinder;
import com.bypassfuzzer.core.urlvalidation.UrlValidationContext;
import com.bypassfuzzer.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationOptions;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationPayloadGenerator;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(90)
class AttackPlaybookSmokeTest {

    private static final String HOST = "127.0.0.1";

    private static Process smokeLab;
    private static String baseUrl;
    private static int port;

    @BeforeAll
    static void startLab() throws Exception {
        port = findFreePort();
        baseUrl = "http://" + HOST + ":" + port;

        smokeLab = new ProcessBuilder("python3", "src/test/vulnerable_lab/app.py", "--host", HOST, "--port", Integer.toString(port))
            .directory(Path.of(".").toFile())
            .redirectErrorStream(true)
            .start();

        waitForLab(baseUrl);
    }

    @AfterAll
    static void stopLab() {
        if (smokeLab != null) {
            smokeLab.destroy();
            try {
                if (!smokeLab.waitFor(3, TimeUnit.SECONDS)) {
                    smokeLab.destroyForcibly();
                    smokeLab.waitFor(3, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                smokeLab.destroyForcibly();
            }
        }
    }

    @Test
    void headerAttackFindsHeaderBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.HEADER,
                "/edge/private/reports/quarterly",
                """
                    GET /edge/private/reports/quarterly HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "trusted X-Forwarded-For"
            )
        );
    }

    @Test
    void pathAttackFindsPathNormalizationBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.PATH,
                "/api/v1/reports/export",
                """
                    GET /api/v1/reports/export HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void verbAttackFindsMethodConfusionBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.VERB,
                "/rest/admin/users/42",
                """
                    GET /rest/admin/users/42 HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "method confusion"
            )
        );
    }

    @Test
    void paramAttackFindsTruthyQueryBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.PARAM,
                "/api/internal/runtime/config?debug=false",
                """
                    GET /api/internal/runtime/config?debug=false HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "truthy query parameter"
            )
        );
    }

    @Test
    void cookieAttackFindsTruthyCookieBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.COOKIE,
                "/portal/account/export",
                """
                    GET /portal/account/export HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user; debug=false\r
                    \r
                    """,
                "truthy cookie parameter"
            )
        );
    }

    @Test
    void trailingDotAttackFindsHostBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.TRAILING_DOT,
                "/edge/admin/console",
                """
                    GET /edge/admin/console HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "trusted trailing-dot Host"
            )
        );
    }

    @Test
    void trailingSlashAttackFindsPathBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.TRAILING_SLASH,
                "/api/v1/reports/export",
                """
                    GET /api/v1/reports/export HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void extensionAttackFindsExtensionBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.EXTENSION,
                "/api/v1/reports/export",
                """
                    GET /api/v1/reports/export HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void contentTypeAttackFindsParserConfusionBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.CONTENT_TYPE,
                "/graphql/internal/preferences?debug=false",
                """
                    GET /graphql/internal/preferences?debug=false HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "content-type parser confusion"
            )
        );
    }

    @Test
    void encodingAttackFindsEncodedBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.ENCODING,
                "/api/v1/reports/export",
                """
                    GET /api/v1/reports/export HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void protocolAttackFindsHttp10Bypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.PROTOCOL,
                "/legacy/admin/audit",
                """
                    GET /legacy/admin/audit HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "http-1.0"
            )
        );
    }

    @Test
    void caseAttackFindsCaseBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.CASE,
                "/api/v1/reports/export",
                """
                    GET /api/v1/reports/export HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void urlValidationFindsAbsoluteUrlBypass() {
        assertUrlValidationSucceeds(
            baseRequest(
                """
                    GET /redirect/next?next={INJECT} HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """.formatted(HOST, port)
            ),
            new UrlValidationOptions("{INJECT}", "trusted.example", "127.0.0.1", false, "http", Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME), Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS, UrlValidationAttackSetting.FAKE_RELATIVE_URLS, UrlValidationAttackSetting.LOOPBACK), Set.of(UrlValidationEncoding.RAW), Set.of()),
            "url-allowlist-bypass"
        );
    }

    @Test
    void urlValidationFindsHostnameBypass() {
        assertUrlValidationSucceeds(
            baseRequest(
                """
                    GET /host/check?host={INJECT} HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """.formatted(HOST, port)
            ),
            new UrlValidationOptions("{INJECT}", "trusted.example", "127.0.0.1", false, "http", Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME), Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS, UrlValidationAttackSetting.FAKE_RELATIVE_URLS, UrlValidationAttackSetting.LOOPBACK), Set.of(UrlValidationEncoding.RAW), Set.of()),
            "hostname-allowlist-bypass"
        );
    }

    @Test
    void urlValidationFindsCorsOriginBypass() {
        assertUrlValidationSucceeds(
            baseRequest(
                """
                    GET /cors/profile HTTP/1.1\r
                    Host: %s:%d\r
                    Origin: {INJECT}\r
                    Cookie: session=lab-user\r
                    \r
                    """.formatted(HOST, port)
            ),
            new UrlValidationOptions("{INJECT}", "trusted.example", "127.0.0.1", false, "http", Set.of(UrlValidationContext.CORS_ORIGIN), Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS, UrlValidationAttackSetting.FAKE_RELATIVE_URLS, UrlValidationAttackSetting.LOOPBACK), Set.of(UrlValidationEncoding.RAW), Set.of()),
            "cors-origin-bypass"
        );
    }

    @Test
    void urlValidationMarkerModeFindsAbsoluteUrlBypass() {
        assertUrlValidationSucceeds(
            baseRequest(
                """
                    GET /redirect/next?next={INJECT} HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """.formatted(HOST, port)
            ),
            new UrlValidationOptions("{INJECT}", "trusted.example", "127.0.0.1", false, "http", Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME), Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS, UrlValidationAttackSetting.FAKE_RELATIVE_URLS, UrlValidationAttackSetting.LOOPBACK), Set.of(UrlValidationEncoding.RAW), Set.of()),
            "url-allowlist-bypass"
        );
    }

    private static Scenario scenario(AttackType type, String pathAndQuery, String rawTemplate, String expectedMarker) {
        String rawRequest = rawTemplate.formatted(HOST, port);
        return new Scenario(type, baseUrl + pathAndQuery, rawRequest, expectedMarker);
    }

    private void assertAttackSucceeds(Scenario scenario) {
        List<AttackResult> results = new ArrayList<>();
        var original = baseRequest(scenario.rawRequest());
        var base = new com.bypassfuzzer.burp.http.CoreRequestAdapter().fromMontoya(original);
        var plans = new com.bypassfuzzer.core.scan.BypassPlanner().plan(base,
            Set.of(com.bypassfuzzer.core.scan.AttackFamily.parse(scenario.type().id())), true, Integer.MAX_VALUE);
        for (var plan : plans) {
            HttpRequest request = MontoyaStubs.request(original.httpService(), plan.request().withSyncedContentLength().toRaw());
            HttpResponse response = new RawSocketRequestSender().send(request);
            results.add(new AttackResult(scenario.type().displayName(), plan.payload(), request, response));
            if (response != null && response.statusCode() == 200 && response.headerValue("X-Smoke-Bypass") != null
                && response.headerValue("X-Smoke-Bypass").contains(scenario.expectedMarker())) break;
        }

        assertFalse(results.isEmpty(), "No requests were executed for " + scenario.type());
        boolean matched = results.stream().anyMatch(result -> {
            HttpResponse response = result.getResponse();
            return response != null
                && response.statusCode() == 200
                && response.headerValue("X-Smoke-Bypass") != null
                && response.headerValue("X-Smoke-Bypass").contains(scenario.expectedMarker());
        });

        String summary = results.stream()
            .limit(8)
            .map(result -> result.getAttackType() + " :: " + result.getPayload() + " -> " + result.getStatusCode())
            .reduce((left, right) -> left + "\n" + right)
            .orElse("<no results>");
        assertTrue(matched, "Expected marker '%s' for %s. First results:%n%s".formatted(
            scenario.expectedMarker(),
            scenario.type(),
            summary
        ));
    }

    private void assertUrlValidationSucceeds(HttpRequest request, UrlValidationOptions options, String expectedMarker) {
        List<AttackResult> results = new ArrayList<>();
        var base = new com.bypassfuzzer.burp.http.CoreRequestAdapter().fromMontoya(request);
        var plans = new com.bypassfuzzer.core.scan.UrlValidationPlanner().plan(base,
            UrlValidationPayloadGenerator.toCoreOptions(options, options.normalizedAttackerHost()), Integer.MAX_VALUE);
        for (var plan : plans) {
            HttpRequest changed = MontoyaStubs.request(request.httpService(), plan.request().withSyncedContentLength().toRaw());
            HttpResponse response = new RawSocketRequestSender().send(changed);
            results.add(new AttackResult("URL Validation", plan.payload(), changed, response));
            if (response != null && response.statusCode() == 200 && response.headerValue("X-Smoke-Bypass") != null
                && response.headerValue("X-Smoke-Bypass").contains(expectedMarker)) break;
        }

        assertFalse(results.isEmpty(), "No URL Validation requests were executed");
        boolean matched = results.stream().anyMatch(result -> {
            HttpResponse response = result.getResponse();
            return response != null
                && response.statusCode() == 200
                && response.headerValue("X-Smoke-Bypass") != null
                && response.headerValue("X-Smoke-Bypass").contains(expectedMarker);
        });

        String summary = results.stream()
            .limit(8)
            .map(result -> result.getAttackType() + " :: " + result.getPayload() + " -> " + result.getStatusCode())
            .reduce((left, right) -> left + "\n" + right)
            .orElse("<no results>");
        assertTrue(matched, "Expected URL Validation marker '%s'. First results:%n%s".formatted(expectedMarker, summary));
    }

    private static HttpRequest baseRequest(String rawRequest) {
        return MontoyaStubs.request(MontoyaStubs.httpService(HOST, port, false), rawRequest);
    }

    private static String buildUrl(burp.api.montoya.http.HttpService service, String path) {
        return "http://" + service.host() + ":" + service.port() + path;
    }

    private static MontoyaApi montoyaApi() {
        Logging logging = (Logging) Proxy.newProxyInstance(
            Logging.class.getClassLoader(),
            new Class<?>[]{Logging.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "output" -> System.out;
                case "error" -> System.err;
                case "toString" -> "SmokeLogging";
                default -> null;
            }
        );

        return (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(),
            new Class<?>[]{MontoyaApi.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "logging" -> logging;
                case "toString" -> "SmokeMontoyaApi";
                default -> null;
            }
        );
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static void waitForLab(String url) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            try {
                if (isLabHealthy()) {
                    return;
                }
            } catch (Exception ignored) {
                // lab not ready yet
            }
            Thread.sleep(100);
        }
        String processOutput = readProcessOutput(smokeLab.getInputStream());
        throw new IllegalStateException("Smoke lab did not become ready at " + url + ". Output: " + processOutput);
    }

    private static boolean isLabHealthy() throws IOException {
        try (Socket socket = new Socket(HOST, port)) {
            socket.setSoTimeout(1000);
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(("GET /health HTTP/1.1\r\nHost: " + HOST + ":" + port + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            socket.shutdownOutput();
            String response = new String(socket.getInputStream().readNBytes(256), StandardCharsets.UTF_8);
            return response.startsWith("HTTP/1.0 200") || response.startsWith("HTTP/1.1 200");
        }
    }

    private static String readProcessOutput(InputStream inputStream) throws IOException {
        byte[] bytes = inputStream.readAllBytes();
        return bytes.length == 0 ? "<no output>" : new String(bytes, StandardCharsets.UTF_8);
    }

    private record Scenario(AttackType type, String targetUrl, String rawRequest, String expectedMarker) {
    }

    private static final class RawSocketRequestSender implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return sendInternal(request, 5, TimeUnit.SECONDS);
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return sendInternal(request, timeout, timeUnit);
        }

        private HttpResponse sendInternal(HttpRequest request, long timeout, TimeUnit timeUnit) {
            try (Socket socket = new Socket(request.httpService().host(), request.httpService().port())) {
                socket.setSoTimeout((int) timeUnit.toMillis(timeout));
                socket.getOutputStream().write(request.toByteArray().getBytes());
                socket.getOutputStream().flush();
                socket.shutdownOutput();

                byte[] bytes = socket.getInputStream().readAllBytes();
                if (bytes.length == 0) {
                    return null;
                }
                return MontoyaStubs.response(bytes);
            } catch (IOException e) {
                return syntheticFailureResponse(e);
            }
        }

        private HttpResponse syntheticFailureResponse(IOException exception) {
            String message = exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
            return MontoyaStubs.syntheticResponse(599, "Smoke Failure", message, List.of());
        }
    }
}
