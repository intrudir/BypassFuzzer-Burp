package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.core.http.ConfiguredHeader;

import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@FunctionalInterface
interface OpenApiUrlFetcher {

    int MAX_SOURCE_BYTES = 10 * 1024 * 1024;
    int MAX_REDIRECTS = 5;
    int MAX_DOCUMENT_DISCOVERY_STEPS = 3;
    Pattern DOCUMENT_URL = Pattern.compile("(?is)\\b(?:configUrl|url)\\s*:\\s*(['\"])(.*?)\\1");
    Pattern INITIALIZER_SCRIPT = Pattern.compile(
        "(?is)<script[^>]+src\\s*=\\s*(['\"])([^'\"]*(?:initializer|swagger-ui-init)[^'\"]*)\\1");
    String BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    AtomicInteger FETCH_THREAD_COUNTER = new AtomicInteger(1);
    ExecutorService FETCH_EXECUTOR = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable,
            "bypassfuzzer-openapi-fetch-" + FETCH_THREAD_COUNTER.getAndIncrement());
        thread.setDaemon(true);
        return thread;
    });

    String fetch(String rawUrl, HttpMode httpMode) throws Exception;

    default String fetch(String rawUrl, HttpMode httpMode, java.util.List<ConfiguredHeader> headers) throws Exception {
        return fetch(rawUrl, httpMode);
    }

    default FetchedDocument fetchDocument(String rawUrl, HttpMode httpMode,
                                           java.util.List<ConfiguredHeader> headers) throws Exception {
        return new FetchedDocument(fetch(rawUrl, httpMode, headers), rawUrl);
    }

    static OpenApiUrlFetcher burp(MontoyaApi api) {
        return burp(api, (target, rawRequest) -> {
            HttpService service = HttpService.httpService(target.host(), target.port(), target.secure());
            return HttpRequest.httpRequest(service, ByteArray.byteArray(rawRequest));
        });
    }

    static OpenApiUrlFetcher burp(MontoyaApi api, RawRequestFactory requestFactory) {
        return new OpenApiUrlFetcher() {
            @Override
            public String fetch(String rawUrl, HttpMode httpMode) throws Exception {
                return fetch(rawUrl, httpMode, java.util.List.of());
            }

            @Override
            public String fetch(String rawUrl, HttpMode httpMode,
                                java.util.List<ConfiguredHeader> headers) throws Exception {
                return fetchDocument(rawUrl, httpMode, headers).source();
            }

            @Override
            public FetchedDocument fetchDocument(String rawUrl, HttpMode httpMode,
                                                  java.util.List<ConfiguredHeader> headers) throws Exception {
                return fetchWithBurp(api, requestFactory, rawUrl,
                    httpMode == null ? HttpMode.HTTP_1 : httpMode, headers, 0, 0);
            }
        };
    }

    private static FetchedDocument fetchWithBurp(MontoyaApi api, RawRequestFactory requestFactory,
                                                 String rawUrl, HttpMode httpMode,
                                                 java.util.List<ConfiguredHeader> configuredHeaders,
                                                 int redirectCount,
                                                 int discoveryCount) throws Exception {
        ParsedUrl target = parse(rawUrl);
        String rawRequest = buildRawRequest(target, configuredHeaders);
        HttpRequest request = requestFactory.create(target, rawRequest);
        HttpRequestResponse exchange = sendWithTimeout(api, request, httpMode);
        HttpResponse response = exchange == null ? null : exchange.response();
        if (response == null) {
            throw new IOException("OpenAPI URL returned no response");
        }

        int status = response.statusCode();
        if (status >= 300 && status < 400) {
            String location = response.headerValue("Location");
            if (location == null || location.isBlank()) {
                throw new IOException("OpenAPI URL returned HTTP " + status + " without a Location header");
            }
            if (redirectCount >= MAX_REDIRECTS) {
                throw new IOException("OpenAPI URL exceeded " + MAX_REDIRECTS + " redirects");
            }
            return fetchWithBurp(api, requestFactory, resolveReference(target, location.trim()),
                httpMode, configuredHeaders, redirectCount + 1, discoveryCount);
        }
        if (status < 200 || status >= 300) {
            throw new IOException("OpenAPI URL returned HTTP " + status);
        }
        if (response.body() != null && response.body().length() > MAX_SOURCE_BYTES) {
            throw new IOException("OpenAPI document exceeds the 10 MB import limit");
        }
        String source = response.bodyToString();
        String reference = discoverDocumentReference(source, response.headerValue("Content-Type"));
        if (reference != null) {
            if (discoveryCount >= MAX_DOCUMENT_DISCOVERY_STEPS) {
                throw new IOException("OpenAPI URL exceeded " + MAX_DOCUMENT_DISCOVERY_STEPS
                    + " document discovery steps");
            }
            return fetchWithBurp(api, requestFactory, resolveReference(target, reference),
                httpMode, configuredHeaders, 0, discoveryCount + 1);
        }
        if (looksLikeHtml(source, response.headerValue("Content-Type"))) {
            throw new IOException("URL returned HTML without a discoverable API document reference");
        }
        return new FetchedDocument(source, target.rawUrl());
    }

    private static String buildRawRequest(ParsedUrl target, java.util.List<ConfiguredHeader> configuredHeaders) {
        java.util.List<ConfiguredHeader> defaults = java.util.List.of(
            new ConfiguredHeader("Host", target.hostHeader()),
            new ConfiguredHeader("User-Agent", BROWSER_USER_AGENT),
            new ConfiguredHeader("Accept", "application/json, application/yaml, text/yaml, */*;q=0.1"),
            new ConfiguredHeader("Connection", "close")
        );
        java.util.List<ConfiguredHeader> configured = configuredHeaders == null
            ? java.util.List.of() : java.util.List.copyOf(configuredHeaders);
        java.util.Set<String> configuredNames = configured.stream()
            .map(header -> header.name().toLowerCase(Locale.ROOT))
            .collect(java.util.stream.Collectors.toSet());
        StringBuilder request = new StringBuilder("GET ")
            .append(target.requestTarget()).append(" HTTP/1.1\r\n");
        defaults.stream()
            .filter(header -> !configuredNames.contains(header.name().toLowerCase(Locale.ROOT)))
            .forEach(header -> request.append(header.name()).append(": ").append(header.value()).append("\r\n"));
        configured.forEach(header -> request.append(header.name()).append(": ")
            .append(header.value()).append("\r\n"));
        return request.append("\r\n").toString();
    }

    private static HttpRequestResponse sendWithTimeout(MontoyaApi api, HttpRequest request,
                                                       HttpMode httpMode) throws Exception {
        Future<HttpRequestResponse> future = FETCH_EXECUTOR.submit(
            () -> api.http().sendRequest(request, httpMode));
        try {
            return future.get(30, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new IOException("OpenAPI URL timed out after 30 seconds");
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw e;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IOException("Unable to fetch OpenAPI URL", cause);
        }
    }

    static ParsedUrl parse(String rawUrl) {
        String value = rawUrl == null ? "" : rawUrl.trim();
        if (value.chars().anyMatch(character -> Character.isWhitespace(character) || character == 0)) {
            throw invalidUrl();
        }

        int schemeEnd = value.indexOf("://");
        if (schemeEnd <= 0) {
            throw invalidUrl();
        }
        String scheme = value.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException("Enter an absolute HTTP or HTTPS OpenAPI URL.");
        }

        int authorityStart = schemeEnd + 3;
        int authorityEnd = firstDelimiter(value, authorityStart);
        String authority = value.substring(authorityStart, authorityEnd);
        if (authority.isBlank() || authority.indexOf('@') >= 0 || authority.chars().anyMatch(Character::isWhitespace)) {
            throw invalidUrl();
        }

        HostPort hostPort = parseAuthority(authority, "https".equals(scheme));
        String requestTarget = authorityEnd == value.length() ? "/" : value.substring(authorityEnd);
        int fragment = requestTarget.indexOf('#');
        if (fragment >= 0) {
            requestTarget = requestTarget.substring(0, fragment);
        }
        if (requestTarget.isEmpty()) {
            requestTarget = "/";
        } else if (requestTarget.startsWith("?")) {
            requestTarget = "/" + requestTarget;
        }
        if (!requestTarget.startsWith("/") && !requestTarget.startsWith("\\")) {
            throw invalidUrl();
        }

        return new ParsedUrl(value, scheme, hostPort.host(), hostPort.port(),
            "https".equals(scheme), authority, requestTarget);
    }

    private static int firstDelimiter(String value, int start) {
        int end = value.length();
        for (char delimiter : new char[]{'/', '\\', '?', '#'}) {
            int index = value.indexOf(delimiter, start);
            if (index >= 0 && index < end) {
                end = index;
            }
        }
        return end;
    }

    private static HostPort parseAuthority(String authority, boolean secure) {
        String host;
        int port = secure ? 443 : 80;
        if (authority.startsWith("[")) {
            int closing = authority.indexOf(']');
            if (closing <= 1) {
                throw invalidUrl();
            }
            host = authority.substring(1, closing);
            String suffix = authority.substring(closing + 1);
            if (!suffix.isEmpty()) {
                if (!suffix.startsWith(":")) {
                    throw invalidUrl();
                }
                port = parsePort(suffix.substring(1));
            }
        } else {
            int colon = authority.lastIndexOf(':');
            if (colon >= 0) {
                if (authority.indexOf(':') != colon) {
                    throw invalidUrl();
                }
                host = authority.substring(0, colon);
                port = parsePort(authority.substring(colon + 1));
            } else {
                host = authority;
            }
        }
        if (host.isBlank()) {
            throw invalidUrl();
        }
        return new HostPort(host, port);
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) {
                throw invalidUrl();
            }
            return port;
        } catch (NumberFormatException e) {
            throw invalidUrl();
        }
    }

    static String resolveReference(ParsedUrl current, String location) {
        if (location.regionMatches(true, 0, "http://", 0, 7)
            || location.regionMatches(true, 0, "https://", 0, 8)) {
            return location;
        }
        if (location.startsWith("//")) return current.scheme() + ":" + location;
        String origin = current.scheme() + "://" + current.hostHeader();
        if (location.startsWith("/") || location.startsWith("\\")) {
            return origin + location;
        }
        String target = current.requestTarget();
        int query = target.indexOf('?');
        if (query >= 0) {
            target = target.substring(0, query);
        }
        int slash = Math.max(target.lastIndexOf('/'), target.lastIndexOf('\\'));
        String directory = slash >= 0 ? target.substring(0, slash + 1) : "/";
        return origin + directory + location;
    }

    static String discoverDocumentReference(String source, String contentType) {
        if (source == null || source.isBlank()) return null;
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        String leading = source.stripLeading();
        boolean htmlOrScript = type.contains("javascript") || type.contains("ecmascript")
            || leading.startsWith("<");
        if (!htmlOrScript) return null;
        Matcher configuredUrl = DOCUMENT_URL.matcher(source);
        if (configuredUrl.find()) return configuredUrl.group(2);
        Matcher initializer = INITIALIZER_SCRIPT.matcher(source);
        return initializer.find() ? initializer.group(2) : null;
    }

    private static boolean looksLikeHtml(String source, String contentType) {
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        String leading = source == null ? "" : source.stripLeading().toLowerCase(Locale.ROOT);
        return leading.startsWith("<") && (type.contains("html")
            || leading.startsWith("<!doctype html") || leading.startsWith("<html")
            || leading.startsWith("<!--"));
    }

    private static IllegalArgumentException invalidUrl() {
        return new IllegalArgumentException("Enter a valid absolute HTTP or HTTPS OpenAPI URL.");
    }

    record ParsedUrl(String rawUrl, String scheme, String host, int port, boolean secure,
                     String hostHeader, String requestTarget) {
    }

    record HostPort(String host, int port) {
    }

    record FetchedDocument(String source, String effectiveUrl) {
    }

    @FunctionalInterface
    interface RawRequestFactory {
        HttpRequest create(ParsedUrl target, String rawRequest);
    }
}
