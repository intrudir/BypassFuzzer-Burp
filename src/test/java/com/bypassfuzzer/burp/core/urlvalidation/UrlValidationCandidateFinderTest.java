package com.bypassfuzzer.burp.core.urlvalidation;
import com.bypassfuzzer.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.core.urlvalidation.UrlValidationContext;
import com.bypassfuzzer.core.urlvalidation.UrlValidationAttackSetting;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlValidationCandidateFinderTest {

    @Test
    void markerModeTargetsInjectedRequestMarker() {
        var service = (burp.api.montoya.http.HttpService) Proxy.newProxyInstance(
            getClass().getClassLoader(),
            new Class<?>[]{burp.api.montoya.http.HttpService.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "host", "ipAddress" -> "example.com";
                case "port" -> 80;
                case "secure" -> false;
                case "toString" -> "http://example.com:80";
                case "hashCode" -> Objects.hash("example.com", 80, false);
                case "equals" -> proxy == args[0];
                default -> null;
            }
        );
        UrlValidationCandidateFinder finder = new UrlValidationCandidateFinder((httpService, rawRequest) -> requestProxy(httpService, rawRequest));
        HttpRequest request = requestProxy(
            service,
            """
                GET /redirect/next?next={INJECT} HTTP/1.1\r
                Host: example.com\r
                Cookie: session=lab-user\r
                \r
                """
        );

        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "http",
            Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK
            ),
            Set.of(UrlValidationEncoding.RAW),
            Set.of()
        );

        assertEquals(1, finder.countMarkerOccurrences(request, "{INJECT}"));

        List<UrlValidationCandidate> candidates = finder.find(request, options);
        assertEquals(1, candidates.size());
        assertEquals("marker", candidates.get(0).locationLabel());

        HttpRequest mutated = candidates.get(0).mutator().mutate(request, "http://trusted.example@127.0.0.1/");
        assertTrue(mutated.toString().contains("next=http://trusted.example@127.0.0.1/"));
    }

    @Test
    void markerCandidateReplacesAllMarkersInRequest() {
        var service = (burp.api.montoya.http.HttpService) Proxy.newProxyInstance(
            getClass().getClassLoader(),
            new Class<?>[]{burp.api.montoya.http.HttpService.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "host", "ipAddress" -> "example.com";
                case "port" -> 80;
                case "secure" -> false;
                case "toString" -> "http://example.com:80";
                case "hashCode" -> Objects.hash("example.com", 80, false);
                case "equals" -> proxy == args[0];
                default -> null;
            }
        );
        UrlValidationCandidateFinder finder = new UrlValidationCandidateFinder((httpService, rawRequest) -> requestProxy(httpService, rawRequest));
        HttpRequest request = requestProxy(
            service,
            """
                GET /redirect/next?next={INJECT} HTTP/1.1\r
                Host: example.com\r
                Origin: {INJECT}\r
                Cookie: session=lab-user\r
                \r
                """
        );

        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "http",
            Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME, UrlValidationContext.CORS_ORIGIN),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK
            ),
            Set.of(UrlValidationEncoding.RAW),
            Set.of()
        );

        List<UrlValidationCandidate> candidates = finder.find(request, options);
        assertEquals(1, candidates.size());

        HttpRequest mutated = candidates.get(0).mutator().mutate(request, "null");
        assertTrue(mutated.toString().contains("next=null"));
        assertTrue(mutated.toString().contains("Origin: null"));
    }

    @Test
    void markerCandidateResyncsContentLengthAfterBodyReplacement() {
        var service = (burp.api.montoya.http.HttpService) Proxy.newProxyInstance(
            getClass().getClassLoader(),
            new Class<?>[]{burp.api.montoya.http.HttpService.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "host", "ipAddress" -> "example.com";
                case "port" -> 443;
                case "secure" -> true;
                case "toString" -> "https://example.com:443";
                case "hashCode" -> Objects.hash("example.com", 443, true);
                case "equals" -> proxy == args[0];
                default -> null;
            }
        );
        AtomicReference<String> rebuiltRaw = new AtomicReference<>();
        UrlValidationCandidateFinder finder = new UrlValidationCandidateFinder((httpService, rawRequest) -> {
            rebuiltRaw.set(rawRequest);
            return requestProxy(httpService, rawRequest);
        });
        HttpRequest request = requestProxy(
            service,
            """
                POST /redirect HTTP/1.1\r
                Host: example.com\r
                Content-Type: application/x-www-form-urlencoded\r
                Content-Length: 13\r
                \r
                next={INJECT}"""
        );

        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL),
            Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS),
            Set.of(UrlValidationEncoding.RAW),
            Set.of()
        );

        List<UrlValidationCandidate> candidates = finder.find(request, options);
        String payload = "https://trusted.example@127.0.0.1/";
        String expectedBody = "next=" + payload;
        int expectedLength = expectedBody.getBytes(StandardCharsets.UTF_8).length;

        candidates.get(0).mutator().mutate(request, payload);

        assertTrue(rebuiltRaw.get().contains("Content-Length: " + expectedLength + "\r\n"));
        assertTrue(rebuiltRaw.get().endsWith("\r\n\r\n" + expectedBody));
    }

    private HttpRequest requestProxy(burp.api.montoya.http.HttpService service, String rawRequest) {
        return (HttpRequest) Proxy.newProxyInstance(
            getClass().getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "httpService" -> service;
                case "toString" -> rawRequest;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> null;
            }
        );
    }
}
