package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CoverageSweepEngineTest {

    @Test
    void sweepSuffixAndNegotiationProbesNormalizeOriginalTrailingSlash() {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()), new StaticSender(response(403, "text/plain", "blocked")),
            new CoverageSweepProbeGenerator());
        CoverageSweepCandidate candidate = candidate(
            request("/yamplus_api/extreport/", "", "GET", null, ""), 403);

        List<CoverageSweepProbe> probes = engine.buildProbes(candidate, CoverageSweepOptions.defaults());

        assertEquals("/yamplus_api/extreport.json", probePath(probes, "Path suffix .json"));
        assertEquals("/yamplus_api/extreport?.json", probePath(probes, "Query .json"));
        assertEquals("/yamplus_api/extreport/.", probePath(probes, "Append /."));
        assertEquals("/yamplus_api/extreport/?debug=true", probePath(probes, "Append debug=true"));
    }

    private String probePath(List<CoverageSweepProbe> probes, String label) {
        return probes.stream()
            .filter(probe -> label.equals(probe.label()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Missing probe: " + label))
            .request()
            .path();
    }

    @Test
    void allPayloadsUsesTheCompleteBypassCatalogWithoutTheHighSignalCap() {
        HttpRequest original = requestWithHeaders("/admin/users", "id=7", "POST", Map.of(
            "Content-Type", "application/json",
            "Cookie", "session=secret; theme=dark",
            "Host", "example.com"
        ), "{\"id\":7}");
        CoverageSweepCandidate candidate = candidate(original, 403);
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        CoverageSweepOptions options = new CoverageSweepOptions(
            defaults.statuses(), defaults.inScopeOnly(), defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(), defaults.concurrency(), defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(), defaults.mode(), defaults.authSelection(),
            defaults.excludeStaticAssets(), defaults.verifyUnauthenticatedAccess(), List.of(),
            defaults.requestHeaders(), CoverageSweepPayloadSet.ALL_PAYLOADS, com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.RIDE_HARD);
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(403, "text/plain", "blocked")),
            new CoverageSweepProbeGenerator());

        List<CoverageSweepProbe> probes = engine.buildProbes(candidate, options);
        Set<String> families = probes.stream().map(CoverageSweepProbe::family).collect(java.util.stream.Collectors.toSet());

        assertTrue(probes.size() > defaults.maxProbesPerCandidate());
        assertTrue(families.containsAll(Set.of(
            "Control", "Header", "Path", "Verb", "Param", "Cookie", "TrailingDot",
            "TrailingSlash", "Extension", "ContentType", "Encoding", "Protocol", "Case")));
        assertTrue(probes.stream().anyMatch(probe ->
            "Header".equals(probe.family()) && probe.httpMode() == HttpMode.HTTP_1));
    }

    @Test
    void authenticatedAllPayloadsStripsSelectedCredentialsBeforeGeneratingFamilies() {
        HttpRequest original = requestWithHeaders("/account", "", "GET", Map.of(
            "Authorization", "Bearer secret",
            "Cookie", "session=secret; theme=dark",
            "X-Keep", "value"
        ), "");
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        CoverageSweepOptions options = new CoverageSweepOptions(
            Set.of(), defaults.inScopeOnly(), defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(), defaults.concurrency(), defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of("session"), false),
            true, true, List.of(), List.of(), CoverageSweepPayloadSet.ALL_PAYLOADS, com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.RIDE_HARD);
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(200, "text/plain", "ok")),
            new CoverageSweepProbeGenerator());

        CoverageSweepProbe pathProbe = engine.buildProbes(candidate(original, 200), options).stream()
            .filter(probe -> "Path".equals(probe.family()))
            .findFirst().orElseThrow();

        assertFalse(pathProbe.request().hasHeader("Authorization"));
        assertEquals("theme=dark", pathProbe.request().headerValue("Cookie"));
        assertEquals("value", pathProbe.request().headerValue("X-Keep"));
    }

    @Test
    void optionalDoublePortHostProbesUseHttp1AndPreserveTheConnectionService() throws Exception {
        HttpRequest original = requestWithHeaders("/blocked", "", "GET",
            Map.of("Host", "example.com:8443"), "");
        CoverageSweepCandidate candidate = candidate(original, 403);
        ModeTrackingSender sender = new ModeTrackingSender(response(403, "text/plain", "blocked"));
        CoverageSweepOptions options = new CoverageSweepOptions(
            Set.of(403), true, 100, 1, 1, 1, Set.of(),
            CoverageSweepMode.BLOCKED_RESPONSES, CoverageSweepAuthSelection.defaults(),
            true, true, List.of(0)
        );
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()), sender,
            new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(1, sender.automaticRequests.size());
        assertEquals(2, sender.http1Requests.size());
        assertEquals(List.of("example.com:8443:80", "example.com:8443:443"),
            sender.http1Requests.stream().map(request -> request.headerValue("Host")).toList());
        assertTrue(sender.http1Requests.stream().allMatch(request ->
            request.httpService().host().equals("example.com") && request.httpService().port() == 443));
        assertEquals(2, results.stream().filter(result -> "Host Parsing".equals(result.getPayloadFamily())).count());
    }

    @Test
    void doublePortHostProbesAreEnabledByDefault() {
        HttpRequest original = requestWithHeaders("/blocked", "", "GET",
            Map.of("Host", "example.com:8443"), "");
        CoverageSweepCandidate candidate = candidate(original, 403);

        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertEquals(List.of(0), CoverageSweepOptions.defaults().hostPortProbePorts());
        assertEquals(2, probes.stream().filter(probe -> "Host Parsing".equals(probe.family())).count());
    }

    @Test
    void authenticatedDiscoveryIsPassiveAndInventoriesIdentifiers() {
        HttpRequest get = requestWithHeaders("/account", "", "GET", Map.of(
            "Authorization", "Bearer secret",
            "Cookie", "theme=dark; JSESSIONID=secret"
        ), "");
        HttpRequest post = requestWithHeaders("/account", "", "POST", Map.of("X-Api-Key", "secret"), "");
        List<ProxyHttpRequestResponse> history = List.of(history(get, 200, 2), history(post, 204, 1));
        AtomicInteger sends = new AtomicInteger();
        RequestSender sender = new RequestSender() {
            public HttpResponse send(HttpRequest request) { sends.incrementAndGet(); return response(200, "text/plain", "ok"); }
            public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) { return send(request); }
        };
        CoverageSweepOptions options = CoverageSweepOptions.defaults().withAuthenticatedTraffic(
            CoverageSweepAuthSelection.defaults());

        CoverageSweepPreview preview = new CoverageSweepEngine(api(history), sender, new CoverageSweepProbeGenerator())
            .collectPreview(options);

        assertEquals(2, preview.candidates().size());
        assertTrue(preview.discoveredHeaderNames().contains("Authorization"));
        assertTrue(preview.discoveredHeaderNames().contains("X-Api-Key"));
        assertEquals(Set.of("theme", "JSESSIONID"), preview.discoveredCookieNames());
        assertEquals(0, sends.get());
    }

    @Test
    void authenticatedDiscoveryFiltersAHistorySnapshotOutsideBurpsCallback() {
        HttpRequest request = requestWithHeaders("/analytics/chat-messages", "aggregation=month",
            "GET", Map.of("Authorization", "Bearer secret", "Content-Type", "application/json"), "");
        ProxyHttpRequestResponse item = history(request, 200, 1, "application/json");
        when(item.hasResponse()).thenReturn(false);
        MontoyaApi api = api(List.of(item));
        burp.api.montoya.proxy.Proxy proxy = api.proxy();
        org.mockito.Mockito.doReturn(List.of()).when(proxy)
            .history(any(ProxyHistoryFilter.class));
        CoverageSweepEngine engine = new CoverageSweepEngine(api,
            new StaticSender(response(200, "application/json", "ok")),
            new CoverageSweepProbeGenerator());

        CoverageSweepPreview preview = engine.collectPreview(
            CoverageSweepOptions.defaults().withAuthenticatedTraffic(CoverageSweepAuthSelection.defaults()));

        assertEquals(1, preview.inspectedHistoryCount());
        assertEquals(1, preview.successfulResponseCount());
        assertEquals(1, preview.inScopeSuccessfulResponseCount());
        assertEquals(1, preview.candidates().size());
        assertTrue(preview.discoveredHeaderNames().contains("Authorization"));
    }

    @Test
    void authenticatedDiscoveryUsesProxyRequestsNativeScopeResult() {
        HttpRequest request = requestWithHeaders("/analytics/chat-messages", "aggregation=month",
            "GET", Map.of("Authorization", "Bearer secret"), "");
        ProxyHttpRequestResponse item = history(request, 200, 1, "application/json");
        MontoyaApi api = api(List.of(item));
        burp.api.montoya.scope.Scope scope = api.scope();
        org.mockito.Mockito.doReturn(false).when(scope).isInScope(any());

        CoverageSweepPreview preview = new CoverageSweepEngine(api,
            new StaticSender(response(200, "application/json", "ok")),
            new CoverageSweepProbeGenerator()).collectPreview(
                CoverageSweepOptions.defaults().withAuthenticatedTraffic(CoverageSweepAuthSelection.defaults()));

        assertEquals(1, preview.inScopeSuccessfulResponseCount());
        assertEquals(1, preview.candidates().size());
    }

    @Test
    @SuppressWarnings("removal")
    void authenticatedDiscoveryImportsHttp2HistoryWhenProxyUrlIsInScope() {
        String path = "/analytics/chat-messages";
        String query = "aggregation=month&start_date=2026-08-06&end_date=2026-08-13&timezone=America%2FNew_York";
        String url = "https://cdne-backend-2xn7aiksy5trg-c7gnhqd9gqgrgxap.a02.azurefd.net/"
            + "analytics/chat-messages?" + query;
        HttpRequest baseRequest = requestWithHeaders(path, query, "GET", Map.of(
            "Authorization", "Bearer test-token",
            "Cookie", "msal.cache.encryption=test-value",
            "Content-Type", "application/json",
            "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150"
        ), "");
        HttpRequest request = mock(HttpRequest.class, delegatesTo(baseRequest));
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("cdne-backend-2xn7aiksy5trg-c7gnhqd9gqgrgxap.a02.azurefd.net");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(request.httpService()).thenReturn(service);
        when(request.url()).thenReturn(url);
        when(request.httpVersion()).thenReturn("HTTP/2");
        when(request.isInScope()).thenReturn(false);

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpResponse successfulResponse = response(200, "application/json", "{}");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.url()).thenReturn(url);
        when(item.response()).thenReturn(successfulResponse);
        when(item.time()).thenReturn(ZonedDateTime.now());

        MontoyaApi api = api(List.of(item));
        burp.api.montoya.scope.Scope scope = api.scope();
        org.mockito.Mockito.doAnswer(invocation -> url.equals(invocation.getArgument(0, String.class)))
            .when(scope).isInScope(any());

        CoverageSweepPreview preview = new CoverageSweepEngine(api,
            new StaticSender(response(200, "application/json", "{}")),
            new CoverageSweepProbeGenerator()).collectPreview(
                CoverageSweepOptions.defaults().withAuthenticatedTraffic(CoverageSweepAuthSelection.defaults()));

        assertEquals(1, preview.inspectedHistoryCount());
        assertEquals(1, preview.successfulResponseCount());
        assertEquals(1, preview.inScopeSuccessfulResponseCount());
        assertEquals(1, preview.candidates().size());
        assertTrue(preview.discoveredHeaderNames().contains("Authorization"));
        assertTrue(preview.discoveredCookieNames().contains("msal.cache.encryption"));
    }

    @Test
    void authenticatedDiscoveryExcludesStaticAssetsByDefaultAndCanIncludeThem() {
        HttpRequest account = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest script = requestWithHeaders("/assets/app.js?v=1", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest image = requestWithHeaders("/avatar", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest stylesheet = requestWithHeaders("/assets/site.css?v=1", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest font = requestWithHeaders("/assets/inter.woff2", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        List<ProxyHttpRequestResponse> history = List.of(
            history(account, 200, 5, "application/json"),
            history(script, 200, 4, "text/plain"),
            history(image, 200, 3, "image/png"),
            history(stylesheet, 200, 2, "text/plain"),
            history(font, 200, 1, "application/octet-stream")
        );
        CoverageSweepEngine engine = new CoverageSweepEngine(api(history),
            new StaticSender(response(200, "text/plain", "ok")), new CoverageSweepProbeGenerator());
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults().withAuthenticatedTraffic(
            CoverageSweepAuthSelection.defaults());

        CoverageSweepPreview filtered = engine.collectPreview(defaults);

        assertEquals(List.of("/account"), filtered.candidates().stream()
            .map(CoverageSweepCandidate::path).toList());

        CoverageSweepOptions includingStatic = new CoverageSweepOptions(
            defaults.statuses(),
            defaults.inScopeOnly(),
            defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(),
            defaults.concurrency(),
            defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(),
            defaults.mode(),
            defaults.authSelection(),
            false,
            false
        );

        assertEquals(5, engine.collectPreview(includingStatic).candidates().size());
    }

    @Test
    void selectedCookieIdentifiesCandidateButAttacksRemoveSelectedCredentialsOnly() {
        HttpRequest original = requestWithHeaders("/account", "", "GET", Map.of(
            "Cookie", "theme=dark; JSESSIONID=secret",
            "Authorization", "Bearer secret",
            "Proxy-Authorization", "Basic secret",
            "X-Api-Key", "secret",
            "X-Keep", "value"
        ), "");
        CoverageSweepAuthSelection selection = new CoverageSweepAuthSelection(
            Set.of("Authorization", "X-Api-Key"), Set.of("JSESSIONID"), false);
        CoverageSweepOptions options = CoverageSweepOptions.defaults().withAuthenticatedTraffic(selection);
        CoverageSweepCandidate candidate = candidate(original, 200);
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(200, "text/plain", "ok")), new CoverageSweepProbeGenerator());

        assertTrue(engine.matchesAuthSelection(candidate, selection));
        List<CoverageSweepProbe> probes = engine.buildProbes(candidate, options);

        assertTrue(probes.size() > 100 && probes.size() <= options.maxProbesPerCandidate());
        assertTrue(probes.stream().noneMatch(probe -> "Control".equals(probe.family())));
        HttpRequest first = probes.get(0).request();
        assertEquals("theme=dark", first.headerValue("Cookie"));
        assertFalse(first.hasHeader("Authorization"));
        assertFalse(first.hasHeader("Proxy-Authorization"));
        assertFalse(first.hasHeader("X-Api-Key"));
        assertEquals("value", first.headerValue("X-Keep"));
        assertEquals("theme=dark; JSESSIONID=secret", original.headerValue("Cookie"));
    }

    @Test
    void configuredHeadersArePresentAndAttackedValuesAreAppendedAsDuplicates() {
        HttpRequest original = com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.request(
            Map.entry("Authorization", "Bearer captured"),
            Map.entry("Cookie", "JSESSIONID=captured; theme=dark"),
            Map.entry("X-Forwarded-For", "captured"));
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        CoverageSweepOptions options = new CoverageSweepOptions(
            defaults.statuses(), defaults.inScopeOnly(), defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(), defaults.concurrency(), defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of("JSESSIONID"), false),
            true, true, List.of(), List.of(
                new ConfiguredHeader("Authorization", "Bearer stable"),
                new ConfiguredHeader("Cookie", "JSESSIONID=stable; theme=light"),
                new ConfiguredHeader("X-Forwarded-For", "10.0.0.1")
            ), CoverageSweepPayloadSet.HIGH_SIGNAL, com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.RIDE_HARD);
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(200, "text/plain", "ok")), new CoverageSweepProbeGenerator());

        List<CoverageSweepProbe> probes = engine.buildProbes(candidate(original, 200), options);
        CoverageSweepProbe forwarded = probes.stream()
            .filter(probe -> probe.label().equals("X-Forwarded-For localhost"))
            .findFirst().orElseThrow();
        CoverageSweepProbe authorization = probes.stream()
            .filter(probe -> probe.label().equals("Authorization bearer placeholder"))
            .findFirst().orElseThrow();

        assertEquals(List.of("10.0.0.1", "127.0.0.1"),
            com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.values(
                forwarded.request(), "X-Forwarded-For"));
        assertEquals(List.of("Bearer stable", "Bearer A"),
            com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.values(
                authorization.request(), "Authorization"));
    }

    @Test
    void authenticatedExecutionLeavesSignalBlankAndCarriesHistoryResponse() throws Exception {
        HttpResponse originalResponse = response(200, "application/json", "authenticated");
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest, originalResponse, "key",
            originalRequest.url(), "GET", "example.com", "/account", 200, 13,
            "application/json", ZonedDateTime.now());
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 2, 1, 0,
            Set.of(429), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false));
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(200, "application/json", "probe")), new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(result -> result.getPayloadEncoding().isBlank()));
        assertTrue(results.stream().allMatch(result -> result.getOriginalRequest() == originalRequest));
        assertTrue(results.stream().allMatch(result -> result.getOriginalResponse() == originalResponse));
        assertTrue(results.stream().noneMatch(result -> "Control".equals(result.getPayloadFamily())));
    }

    @Test
    void authenticatedExecutionVerifiesAnonymousControlAndLabelsLikelyPublic() throws Exception {
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpResponse originalResponse = response(200, "application/json", "authenticated");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest, originalResponse, "key",
            originalRequest.url(), "GET", "example.com", "/account", 200, 13,
            "application/json", ZonedDateTime.now());
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 1, 1, 0,
            Set.of(429), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false), true, true);
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new SequenceSender(List.of(
                response(200, "application/json", "public"),
                response(403, "application/json", "blocked")
            )), new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertEquals("Unauthenticated Control", results.get(0).getPayloadFamily());
        assertEquals("LIKELY PUBLIC: authenticated 200 -> unauthenticated 200",
            results.get(0).getPayloadEncoding());
        assertFalse(results.get(0).getRequest().hasHeader("Authorization"));
        assertEquals("", results.get(1).getPayloadEncoding());
    }

    @Test
    void anonymousVerificationExcludesConfiguredCredentialsButKeepsOtherConfiguredHeaders() throws Exception {
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET", Map.of(
            "Authorization", "Bearer captured",
            "Cookie", "session=captured; theme=dark"
        ), "");
        HttpResponse originalResponse = response(200, "application/json", "authenticated");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest, originalResponse, "key",
            originalRequest.url(), "GET", "example.com", "/account", 200, 13,
            "application/json", ZonedDateTime.now());
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 1, 1, 1,
            defaults.throttleStatusCodes(), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of("session"), false),
            true, true, List.of(), List.of(
                new ConfiguredHeader("Authorization", "Bearer stable"),
                new ConfiguredHeader("Cookie", "session=stable; theme=configured"),
                new ConfiguredHeader("X-Tenant", "blue")
            ), CoverageSweepPayloadSet.HIGH_SIGNAL, com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.RIDE_HARD);
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(403, "application/json", "blocked")),
            new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        HttpRequest anonymous = results.get(0).getRequest();
        assertFalse(anonymous.hasHeader("Authorization"));
        assertEquals("theme=configured", anonymous.headerValue("Cookie"));
        assertEquals("blue", anonymous.headerValue("X-Tenant"));
    }

    @Test
    void authenticatedMutationUsesAnonymousControlAsBypassBaseline() throws Exception {
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest,
            response(200, "application/json", "authenticated"), "key", originalRequest.url(), "GET",
            "example.com", "/account", 200, 13, "application/json", ZonedDateTime.now());
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 1, 1, 0,
            Set.of(429), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false), true, true);
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new SequenceSender(List.of(
                response(403, "application/json", "blocked"),
                response(200, "application/json", "secret")
            )), new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertEquals("", results.get(0).getPayloadEncoding());
        assertEquals("BYPASS?: authenticated 200 -> anonymous 403 -> probe 200", results.get(1).getPayloadEncoding());
    }

    @Test
    void classifiesThreeResponseAuthenticatedBypassWithWeakBoundaryMarker() {
        CoverageSweepCandidate candidate = candidate(request("/account", "", "GET", null, ""), 200);

        assertEquals("BYPASS?: authenticated 200 -> anonymous 302 -> probe 200",
            CoverageSweepClassifier.authenticatedBypassSignal(
                candidate,
                response(302, "text/html", "login"),
                response(200, "application/json", "secret")));
        assertEquals("BYPASS? (weak): authenticated 200 -> anonymous 404 -> probe 200",
            CoverageSweepClassifier.authenticatedBypassSignal(
                candidate,
                response(404, "application/json", "missing"),
                response(200, "application/json", "secret")));
        assertEquals("", CoverageSweepClassifier.authenticatedBypassSignal(
            candidate,
            response(403, "application/json", "blocked"),
            response(302, "text/html", "redirect")));
        assertEquals("", CoverageSweepClassifier.unauthenticatedMutationSignal(
            response(403, "application/json", "blocked"),
            response(302, "text/html", "redirect")));
    }

    @Test
    void importedExecutionCarriesOriginalRequestAndLiveControlResponse() throws Exception {
        HttpRequest originalRequest = request("/imported", "", "GET", null, "");
        HttpResponse controlResponse = response(403, "text/plain", "blocked");
        CoverageSweepCandidate importedCandidate = new CoverageSweepCandidate(
            originalRequest,
            null,
            "imported-key",
            originalRequest.url(),
            originalRequest.method(),
            "example.com",
            originalRequest.path(),
            0,
            0,
            "",
            ZonedDateTime.now()
        );
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(List.of(
                controlResponse,
                response(200, "application/json", "probe")
            )),
            new CoverageSweepProbeGenerator()
        );
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            2,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );
        List<AttackResult> results = new ArrayList<>();

        assertTrue(engine.start(List.of(importedCandidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(result -> result.getOriginalRequest() == originalRequest));
        assertTrue(results.stream().allMatch(result -> result.getOriginalResponse() == controlResponse));
    }

    @Test
    void collectsOnlyInScopeBlockedProxyHistoryWithResponses() {
        MontoyaApi api = api(
            List.of(
                history("/blocked", 403, true, 3),
                history("/unauth", 401, true, 2),
                history("/ok", 200, true, 1),
                history("/out", 403, false, 4),
                historyWithoutResponse("/empty", true, 5)
            )
        );

        CoverageSweepPreview preview = new CoverageSweepEngine(api, new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .collectPreview(CoverageSweepOptions.defaults());

        assertEquals(2, preview.blockedHistoryCount());
        assertEquals(2, preview.dedupedEndpointCount());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/blocked")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/unauth")));
    }

    @Test
    void collectsConfiguredRedirectAndClientErrorStatuses() {
        MontoyaApi api = api(List.of(
            history("/redirect", 302, true, 1),
            history("/blocked", 403, true, 2),
            history("/missing", 404, true, 3),
            history("/ok", 200, true, 4)
        ));
        CoverageSweepOptions options = new CoverageSweepOptions(
            java.util.Set.of(302, 401, 403, 404),
            true,
            100,
            25,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        CoverageSweepPreview preview = new CoverageSweepEngine(api, new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .collectPreview(options);

        assertEquals(3, preview.blockedHistoryCount());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/redirect")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/missing")));
    }

    @Test
    void dedupesEndpointShapesPreferringMostRecentAndCapsPreview() {
        List<ProxyHttpRequestResponse> history = new ArrayList<>();
        history.add(history("/users/1?id=1&debug=true", 403, true, 1));
        history.add(history("/users/2?debug=false&id=2", 401, true, 300));
        history.add(history("/reports/1", 403, true, 2));

        for (int i = 0; i < 130; i++) {
            history.add(history("/cap/item-" + i, 403, true, 10 + i));
        }

        CoverageSweepPreview preview = new CoverageSweepEngine(api(history), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .collectPreview(CoverageSweepOptions.defaults());

        assertEquals(132, preview.dedupedEndpointCount());
        assertEquals(100, preview.candidates().size());
        assertTrue(preview.candidates().stream().noneMatch(candidate -> candidate.path().equals("/users/1?id=1&debug=true")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/users/2?debug=false&id=2")));
    }

    @Test
    void importsTargetUrlsFromLinesAndDedupesEndpointShapes() {
        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromUrls(List.of(
                "https://victim.example/admin/users/1?debug=true&id=1",
                "https://victim.example/admin/users/2?id=2&debug=false",
                "https://victim.example/admin/info",
                "# comment",
                "not-a-url"
            ), CoverageSweepOptions.defaults());

        assertEquals(3, preview.blockedHistoryCount());
        assertEquals(2, preview.dedupedEndpointCount());
        assertEquals(2, preview.candidates().size());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.displayUrl().equals("https://victim.example/admin/info")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().startsWith("/admin/users/")));
        assertTrue(preview.candidates().stream().allMatch(candidate -> "GET".equals(candidate.method())));
    }

    @Test
    void importedTargetPreviewKeepsAllExplicitTargets() {
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < 150; i++) {
            urls.add("https://victim.example/endpoint-" + i);
        }

        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromUrls(urls, CoverageSweepOptions.defaults());

        assertEquals(150, preview.blockedHistoryCount());
        assertEquals(150, preview.dedupedEndpointCount());
        assertEquals(150, preview.candidates().size());
    }

    @Test
    void importedTargetUrlsRemainSeparateWhenDedupeIsDisabled() {
        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromUrls(List.of(
                "https://victim.example/admin/users/1?debug=true&id=1",
                "https://victim.example/admin/users/2?id=2&debug=false",
                "https://victim.example/admin/info"
            ), CoverageSweepOptions.defaults(), false);

        assertEquals(3, preview.blockedHistoryCount());
        assertEquals(2, preview.dedupedEndpointCount());
        assertEquals(3, preview.candidates().size());
    }

    @Test
    void openApiOperationsRemainSeparateWhenDedupeIsDisabled() {
        String spec = """
            openapi: 3.0.0
            servers: [{url: https://api.example.test}]
            paths:
              /users/{id}:
                get:
                  parameters: [{name: id, in: path, example: 1}]
              /users/{userId}:
                get:
                  parameters: [{name: userId, in: path, example: 2}]
            """;

        CoverageSweepPreview preview = importedEngine().collectPreviewFromOpenApi(
            spec, "openapi.yaml", "", "", CoverageSweepOptions.defaults(), false);

        assertEquals(2, preview.blockedHistoryCount());
        assertEquals(1, preview.dedupedEndpointCount());
        assertEquals(2, preview.candidates().size());
        assertEquals(List.of("/users/1", "/users/2"),
            preview.candidates().stream().map(CoverageSweepCandidate::path).sorted().toList());
    }

    @Test
    void importsOpenApiOperationsAsMethodAwareCandidates() {
        String spec = """
            openapi: 3.0.0
            servers:
              - url: https://api.example.test
            paths:
              /admin/{id}:
                get:
                  parameters:
                    - name: id
                      in: path
                      required: true
                      example: 7
                delete:
                  parameters:
                    - name: id
                      in: path
                      required: true
                      example: 7
            """;

        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromOpenApi(spec, "openapi.yaml", CoverageSweepOptions.defaults());

        assertEquals(2, preview.blockedHistoryCount());
        assertEquals(2, preview.candidates().size());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.method().equals("GET")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.method().equals("DELETE")));
        assertTrue(preview.candidates().stream().allMatch(candidate -> candidate.path().equals("/admin/7")));
    }

    @Test
    void generatesBoundedHighSignalProbes() {
        CoverageSweepCandidate candidate = candidate(request("/admin/users", "", "GET", null, ""), 403);
        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertEquals(164, probes.size());
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;.json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;.html")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;.xml")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users%3b")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users%3b.json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users%3b.html")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users.json;")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?role=admin")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?.json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?format=json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?_format=json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?api-version=1")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("//admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("///admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin//users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin///users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users/..")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/%2e/admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/./admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/%2fadmin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/ADMIN/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/USERS")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/Admin/Users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/AdMiN/uSeRs")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/%61dmin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/adm%69n/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/%2561dmin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/admin%2fusers")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/%61%64%6d%69%6e/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users/")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?debug=true")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?admin=true")));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().path().contains("jsessionid")));
        assertTrue(probes.stream().allMatch(probe -> "GET".equals(probe.request().method())));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().hasHeader("X-Original-URL")));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().hasHeader("X-Rewrite-URL")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Content-Type")
            && "application/json".equals(probe.request().headerValue("Content-Type"))));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Content-Type")
            && "application/x-www-form-urlencoded".equals(probe.request().headerValue("Content-Type"))));
        assertTrue(probes.stream().anyMatch(probe -> "Bearer A".equals(probe.request().headerValue("Authorization"))));
        assertTrue(probes.stream().anyMatch(probe -> "Basic A".equals(probe.request().headerValue("Authorization"))));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().hasHeader("X-Custom-IP-Authorization")));
    }

    @Test
    void sweepIteratesStandaloneSemicolonSegmentsAcrossPathBoundaries() {
        CoverageSweepCandidate candidate = candidate(request("/api/v2/admin/users/profile", "mode=full", "GET", null, ""), 403);
        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/;/v2/;/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/v2/;/admin/;/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/v2/admin/;/users/;/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/;/api/;/v2/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/v2/admin/users/;/profile/;?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%3b/v2/%3b/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/./v2/./admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%2e/v2/%2e/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%252e/v2/%252e/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%u002e/v2/%u002e/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%253b/v2/%253b/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%u003b/v2/%u003b/admin/users/profile?mode=full")));
    }

    @Test
    void appendsDebugParamsAfterExistingQueryString() {
        CoverageSweepCandidate candidate = candidate(request("/admin/users", "page=1", "GET", null, ""), 403);
        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?page=1&debug=true")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?page=1&admin=true")));
    }

    @Test
    void classifiesBypassAndUnchangedBlockedResponse() {
        CoverageSweepCandidate candidate = candidate(request("/something", "", "GET", null, ""), 403);

        assertTrue(CoverageSweepClassifier.isInteresting(
            candidate,
            response(403, "text/plain", "blocked"),
            response(200, "application/json", "secret data")
        ));
        assertEquals("403 -> 200", CoverageSweepClassifier.signal(
            candidate,
            response(403, "text/plain", "blocked"),
            response(200, "application/json", "secret data")
        ));

        assertFalse(CoverageSweepClassifier.isInteresting(
            candidate,
            response(403, "text/plain", "blocked"),
            response(403, "text/plain", "blocked")
        ));
        assertEquals("", CoverageSweepClassifier.signal(
            candidate,
            response(403, "text/plain", "blocked"),
            response(403, "text/plain", "blocked")
        ));
    }

    @Test
    void doesNotSignalClientErrorResponsesEvenWithLargeBodyDelta() {
        CoverageSweepCandidate candidate = candidate(request("/redirect", "", "GET", null, ""), 302);

        assertFalse(CoverageSweepClassifier.isInteresting(
            candidate,
            response(302, "text/html", ""),
            response(404, "text/html", "x".repeat(500))
        ));
        assertEquals("", CoverageSweepClassifier.signal(
            candidate,
            response(302, "text/html", ""),
            response(404, "text/html", "x".repeat(500))
        ));
    }

    @Test
    void executionLabelsLikelyBypassResults() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(List.of(
                response(403, "text/plain", "blocked"),
                response(200, "application/json", "secret")
            )),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            2,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/something", "", "GET", null, ""), 403)), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) {
            Thread.sleep(20);
        }

        assertEquals(2, results.size());
        assertEquals("403 -> 200", results.get(1).getPayloadEncoding());
    }

    @Test
    void executionLabelsMissingTransportResponsesExplicitly() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new StaticSender(null),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            1,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/something", "", "GET", null, ""), 403)),
            options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(1, results.size());
        assertEquals("No response", results.get(0).getPayloadEncoding());
        assertEquals(0, results.get(0).getStatusCode());
        assertEquals(1, engine.deferredRetryCount());
        assertEquals("No response", engine.deferredRetrySnapshot().get(0).getSignal());
    }

    @Test
    void automaticallyRetriesNoResponsePayloadAfterHealthyControlCanary() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(java.util.Arrays.asList(
                null,                                      // main mutation has no response
                response(403, "text/plain", "blocked"),  // retry control canary is healthy
                response(200, "text/plain", "retried")   // mutation retry succeeds
            )),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = Collections.synchronizedList(new ArrayList<>());
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(), true, 100, 1, 1, 0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/unstable", "", "POST", null, ""), 403)),
            options, results::add, () -> { }));
        for (int i = 0; i < 100 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertEquals("No response", results.get(0).getSignal());
        assertEquals(1, results.get(1).getThrottleRetryAttempt());
        assertEquals(200, results.get(1).getStatusCode());
        assertEquals(0, engine.deferredRetryCount());
        assertEquals(2, engine.automaticRetryRequestCount());
    }

    @Test
    void reportsExactMainProgressAndQuarantinesPatternThrottledRetryGroup() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(List.of(
                response(403, "text/plain", "blocked"), // main control
                response(429, "text/plain", "limited"), // main mutation
                response(403, "text/plain", "blocked"), // retry control canary
                response(429, "text/plain", "limited")  // sampled mutation
            )),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = Collections.synchronizedList(new ArrayList<>());
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(), true, 100, 2, 1, 1,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/limited", "", "GET", null, ""), 403)),
            options, results::add, () -> { }));
        for (int i = 0; i < 100 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(CoverageSweepEngine.SweepPhase.COMPLETE, engine.phase());
        assertEquals(2, engine.plannedMainRequestCount());
        assertEquals(2, engine.completedMainRequestCount());
        assertEquals(4, engine.sentRequestCount());
        assertEquals(2, engine.automaticRetryRequestCount());
        assertEquals(1, engine.quarantinedRetryRequestCount());
        assertEquals(1, engine.deferredRetryCount());
        assertEquals(3, results.size());
        assertEquals(1, results.get(2).getThrottleRetryAttempt());
    }

    @Test
    void doesNotReplayMutationWhenRetryControlCanaryIsAlsoThrottled() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(List.of(
                response(403, "text/plain", "blocked"),
                response(429, "text/plain", "limited"),
                response(429, "text/plain", "host limited")
            )),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = Collections.synchronizedList(new ArrayList<>());
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(), true, 100, 2, 1, 1,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/limited", "", "GET", null, ""), 403)),
            options, results::add, () -> { }));
        for (int i = 0; i < 100 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(3, engine.sentRequestCount());
        assertEquals(1, engine.automaticRetryRequestCount());
        assertEquals(0, engine.quarantinedRetryRequestCount());
        assertEquals(1, engine.deferredRetryCount());
        assertEquals(2, results.size());
    }

    @Test
    void executesCandidatesConcurrentlyWhenConfigured() throws Exception {
        ConcurrentTrackingSender sender = new ConcurrentTrackingSender(response(403, "text/plain", "blocked"), 120);
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            sender,
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = Collections.synchronizedList(new ArrayList<>());
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            1,
            2,
            2,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(
            candidate(request("/one", "", "GET", null, ""), 403),
            candidate(request("/two", "", "GET", null, ""), 403)
        ), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) {
            Thread.sleep(20);
        }

        assertEquals(2, results.size());
        assertTrue(sender.maxActive.get() > 1);
    }

    private MontoyaApi api(List<ProxyHttpRequestResponse> history) {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(any())).thenAnswer(invocation -> !invocation.getArgument(0, String.class).contains("/out"));
        when(api.proxy().history()).thenReturn(history);
        when(api.proxy().history(any())).thenAnswer(invocation -> {
            ProxyHistoryFilter filter = invocation.getArgument(0);
            return history.stream().filter(filter::matches).toList();
        });
        return api;
    }

    private CoverageSweepEngine importedEngine() {
        return new CoverageSweepEngine(
            api(List.of()),
            new StaticSender(response(403, "text/plain", "blocked")),
            new CoverageSweepProbeGenerator(),
            uri -> request(
                uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath(),
                uri.getRawQuery() == null ? "" : uri.getRawQuery(),
                "GET",
                null,
                ""
            )
        );
    }

    private ProxyHttpRequestResponse history(String path, int status, boolean inScope, int minutes) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpRequest request = withScope(request(path, "", "GET", null, ""), inScope);
        return history(item, request, status, minutes);
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status, int minutes) {
        return history(mock(ProxyHttpRequestResponse.class), withScope(request, true), status, minutes);
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status, int minutes, String contentType) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        request = withScope(request, true);
        HttpResponse response = response(status, contentType, "body");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.time()).thenReturn(ZonedDateTime.now().plusMinutes(minutes));
        return item;
    }

    private HttpRequest withScope(HttpRequest request, boolean inScope) {
        HttpRequest scoped = mock(HttpRequest.class, delegatesTo(request));
        when(scoped.isInScope()).thenReturn(inScope);
        return scoped;
    }

    private ProxyHttpRequestResponse history(ProxyHttpRequestResponse item, HttpRequest request, int status, int minutes) {
        HttpResponse response = response(status, "text/plain", "blocked");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.time()).thenReturn(ZonedDateTime.now().plusMinutes(minutes));
        return item;
    }

    private ProxyHttpRequestResponse historyWithoutResponse(String path, boolean inScope, int minutes) {
        ProxyHttpRequestResponse item = history(path, 403, inScope, minutes);
        when(item.hasResponse()).thenReturn(false);
        when(item.response()).thenReturn(null);
        return item;
    }

    private CoverageSweepCandidate candidate(HttpRequest request, int status) {
        HttpResponse response = response(status, "text/plain", "blocked");
        return new CoverageSweepCandidate(
            request,
            response,
            "key",
            request.url(),
            request.method(),
            "example.com",
            request.path(),
            status,
            response.body().length(),
            "text/plain",
            ZonedDateTime.now()
        );
    }

    private HttpResponse response(int status, String contentType, String body) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray bodyBytes = byteArray(body == null ? 0 : body.length());
        List<HttpHeader> headers = List.of(header("Content-Type", contentType));
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(bodyBytes);
        when(response.headers()).thenReturn(headers);
        return response;
    }

    private HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                default -> null;
            }
        );
    }

    private ByteArray byteArray(int length) {
        ByteArray byteArray = mock(ByteArray.class);
        when(byteArray.length()).thenReturn(length);
        return byteArray;
    }

    private record StaticSender(HttpResponse response) implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return response;
        }
    }

    private static final class SequenceSender implements RequestSender {
        private final List<HttpResponse> responses;
        private int index = 0;

        private SequenceSender(List<HttpResponse> responses) {
            this.responses = responses;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            HttpResponse response = responses.get(Math.min(index, responses.size() - 1));
            index++;
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }

    private static final class ConcurrentTrackingSender implements RequestSender {
        private final HttpResponse response;
        private final long delayMs;
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger maxActive = new AtomicInteger();

        private ConcurrentTrackingSender(HttpResponse response, long delayMs) {
            this.response = response;
            this.delayMs = delayMs;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            int current = active.incrementAndGet();
            maxActive.accumulateAndGet(current, Math::max);
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                active.decrementAndGet();
            }
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }

    private static final class ModeTrackingSender implements RequestSender {
        private final HttpResponse response;
        private final List<HttpRequest> automaticRequests = new ArrayList<>();
        private final List<HttpRequest> http1Requests = new ArrayList<>();

        private ModeTrackingSender(HttpResponse response) {
            this.response = response;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            automaticRequests.add(request);
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, HttpMode httpMode) {
            if (httpMode == HttpMode.HTTP_1) {
                http1Requests.add(request);
            }
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }
}
