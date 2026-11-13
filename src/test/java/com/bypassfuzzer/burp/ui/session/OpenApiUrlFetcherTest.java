package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.core.http.ConfiguredHeader;
import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OpenApiUrlFetcherTest {
    @Test
    void redirectAndDiscoveryScopeCustomHeadersToTheCurrentOrigin() throws Exception {
        for (boolean discovery : List.of(false, true)) {
            for (String destination : List.of("https://origin.test:443/spec", "https://ORIGIN.test/spec",
                "https://other.test/spec", "https://origin.test:8443/spec", "http://origin.test/spec")) {
                MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
                var first = exchange(discovery ? 200 : 302,
                    discovery ? "<html><script>SwaggerUIBundle({url: '" + destination + "'})</script></html>" : "",
                    discovery ? "text/html" : "", destination);
                var second = exchange(200, "{\"openapi\":\"3.0.0\",\"paths\":{}}", "application/json", null);
                when(api.http().sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1))).thenReturn(first, second);
                var raw = new java.util.ArrayList<String>();
                OpenApiUrlFetcher.burp(api, (target, request) -> { raw.add(request); return mock(HttpRequest.class); })
                    .fetch("https://origin.test/start", HttpMode.HTTP_1, List.of(
                        new com.bypassfuzzer.core.http.ConfiguredHeader("Authorization", "Bearer fixture"),
                        new com.bypassfuzzer.core.http.ConfiguredHeader("Cookie", "session=fixture"),
                        new com.bypassfuzzer.core.http.ConfiguredHeader("X-Custom-Secret", "fixture")));
                boolean sameOrigin = destination.equals("https://origin.test:443/spec") || destination.equals("https://ORIGIN.test/spec");
                assertEquals(2, raw.size());
                org.junit.jupiter.api.Assertions.assertTrue(raw.get(0).contains("Authorization: Bearer fixture"));
                assertEquals(sameOrigin, raw.get(1).contains("Authorization: Bearer fixture"), destination);
                assertEquals(sameOrigin, raw.get(1).contains("Cookie: session=fixture"), destination);
                assertEquals(sameOrigin, raw.get(1).contains("X-Custom-Secret: fixture"), destination);
                org.junit.jupiter.api.Assertions.assertTrue(raw.get(1).contains("User-Agent: "));
            }
        }
    }

    @Test
    void leavingAndReturningToOriginDoesNotRestoreCredentials() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        var leave = exchange(302, "", "", "https://other.test/next");
        var back = exchange(302, "", "", "https://origin.test/spec");
        var document = exchange(200, "{}", "application/json", null);
        when(api.http().sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1))).thenReturn(leave, back, document);
        var raw = new java.util.ArrayList<String>();
        OpenApiUrlFetcher.burp(api, (target, request) -> { raw.add(request); return mock(HttpRequest.class); })
            .fetch("https://origin.test/start", HttpMode.HTTP_1,
                List.of(new com.bypassfuzzer.core.http.ConfiguredHeader("Authorization", "Bearer fixture")));
        assertEquals(3, raw.size());
        org.junit.jupiter.api.Assertions.assertFalse(raw.get(1).contains("Bearer fixture"));
        org.junit.jupiter.api.Assertions.assertFalse(raw.get(2).contains("Bearer fixture"));
    }

    private static HttpRequestResponse exchange(int status, String text, String type, String location) {
        HttpRequestResponse result = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(result.response()).thenReturn(response); when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(body); when(body.length()).thenReturn(text.length());
        when(response.bodyToString()).thenReturn(text); when(response.headerValue("Content-Type")).thenReturn(type);
        when(response.headerValue("Location")).thenReturn(location);
        return result;
    }


    @Test
    void parserPreservesLiteralBackslashInRequestTarget() {
        String rawUrl = "https://iquery.finance.yahoo.com/ws/user-analytics/\\docs/handcrafted/swagger/openapi.json";

        OpenApiUrlFetcher.ParsedUrl parsed = OpenApiUrlFetcher.parse(rawUrl);

        assertEquals("iquery.finance.yahoo.com", parsed.host());
        assertEquals(443, parsed.port());
        assertEquals("/ws/user-analytics/\\docs/handcrafted/swagger/openapi.json", parsed.requestTarget());
        assertEquals(rawUrl, parsed.rawUrl());
    }

    @Test
    void discoversRelativeDocumentWithoutNormalizingRepeatedSlashes() {
        OpenApiUrlFetcher.ParsedUrl page = OpenApiUrlFetcher.parse(
            "https://finance.mobile.yahoo.com/docs//index.html");
        String html = "<script>SwaggerUIBundle({url: \"newsfeedservice.yaml\"})</script>";

        assertEquals("newsfeedservice.yaml",
            OpenApiUrlFetcher.discoverDocumentReference(html, "text/html"));
        assertEquals("https://finance.mobile.yahoo.com/docs//newsfeedservice.yaml",
            OpenApiUrlFetcher.resolveReference(page, "newsfeedservice.yaml"));
        assertEquals("https://cdn.example.test/openapi.yaml",
            OpenApiUrlFetcher.resolveReference(page, "//cdn.example.test/openapi.yaml"));
        assertEquals(null, OpenApiUrlFetcher.discoverDocumentReference(
            "openapi: 3.0.0\nservers: [{url: /api}]", "application/yaml"));
    }

    @Test
    void burpFetcherSendsLiteralBackslashOverHttp1() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        HttpRequest outboundRequest = mock(HttpRequest.class);
        AtomicReference<String> rawRequest = new AtomicReference<>();
        when(api.http().sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1))).thenReturn(exchange);
        when(exchange.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(37);
        when(response.bodyToString()).thenReturn("{\"openapi\":\"3.0.0\",\"paths\":{}}");
        String rawUrl = "https://iquery.finance.yahoo.com/ws/user-analytics/\\docs/handcrafted/swagger/openapi.json";

        String source = OpenApiUrlFetcher.burp(api, (target, raw) -> {
            rawRequest.set(raw);
            return outboundRequest;
        }).fetch(rawUrl, HttpMode.HTTP_1);

        assertEquals("{\"openapi\":\"3.0.0\",\"paths\":{}}", source);
        verify(api.http()).sendRequest(outboundRequest, HttpMode.HTTP_1);
        assertEquals(
            "GET /ws/user-analytics/\\docs/handcrafted/swagger/openapi.json HTTP/1.1\r\n"
                + "Host: iquery.finance.yahoo.com\r\n"
                + "User-Agent: " + OpenApiUrlFetcher.BROWSER_USER_AGENT + "\r\n"
                + "Accept: application/json, application/yaml, text/yaml, */*;q=0.1\r\n"
                + "Connection: close\r\n\r\n",
            rawRequest.get()
        );
    }

    @Test
    void burpFetcherUsesSelectedHttp2Mode() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        HttpRequest outboundRequest = mock(HttpRequest.class);
        when(api.http().sendRequest(outboundRequest, HttpMode.HTTP_2)).thenReturn(exchange);
        when(exchange.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(2);
        when(response.bodyToString()).thenReturn("{}");

        String source = OpenApiUrlFetcher.burp(api, (target, raw) -> outboundRequest)
            .fetch("https://specs.example.test/openapi.json", HttpMode.HTTP_2);

        assertEquals("{}", source);
        verify(api.http()).sendRequest(outboundRequest, HttpMode.HTTP_2);
    }

    @Test
    void configuredHeadersReplaceDefaultsAndPreserveDuplicatesOnSpecDownload() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        HttpRequest outboundRequest = mock(HttpRequest.class);
        AtomicReference<String> rawRequest = new AtomicReference<>();
        when(api.http().sendRequest(outboundRequest, HttpMode.HTTP_1)).thenReturn(exchange);
        when(exchange.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(2);
        when(response.bodyToString()).thenReturn("{}");

        OpenApiUrlFetcher.burp(api, (target, raw) -> {
            rawRequest.set(raw);
            return outboundRequest;
        }).fetch("https://specs.example.test/openapi.json", HttpMode.HTTP_1, List.of(
            new ConfiguredHeader("User-Agent", "Custom Agent"),
            new ConfiguredHeader("Authorization", "Bearer one"),
            new ConfiguredHeader("authorization", "Bearer two")
        ));

        assertEquals(
            "GET /openapi.json HTTP/1.1\r\n"
                + "Host: specs.example.test\r\n"
                + "Accept: application/json, application/yaml, text/yaml, */*;q=0.1\r\n"
                + "Connection: close\r\n"
                + "User-Agent: Custom Agent\r\n"
                + "Authorization: Bearer one\r\n"
                + "authorization: Bearer two\r\n\r\n",
            rawRequest.get()
        );
    }
}
