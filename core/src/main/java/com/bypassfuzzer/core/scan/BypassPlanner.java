package com.bypassfuzzer.core.scan;
import com.bypassfuzzer.core.http.CookieHeaderUtils;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.RequestParameterSupport;
import com.bypassfuzzer.core.http.RequestBodyFormat;
import com.bypassfuzzer.core.http.QueryStringUtils;
import com.bypassfuzzer.core.payloads.PayloadRepository;
import com.bypassfuzzer.core.payloads.UrlPayloadProcessor;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/** Complete transport-neutral Bypass family registry used by Burp and the CLI. */
public final class BypassPlanner {
    private static final List<String> METHODS = List.of("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH");
    private static final List<String> OVERRIDE_HEADERS = List.of("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override");
    private static final List<String> FUZZ_VALUES = List.of("true", "1", "yes", "on", "admin", "root", "false", "0", "no", "off");
    private final Supplier<String> outOfBandDomain;

    public BypassPlanner() {
        this(() -> "");
    }

    public BypassPlanner(Supplier<String> outOfBandDomain) {
        this.outOfBandDomain = outOfBandDomain == null ? () -> "" : outOfBandDomain;
    }

    public List<PlannedRequest> plan(HttpRequestData request, Set<AttackFamily> selectedFamilies,
                                     boolean fuzzExistingCookies, int maximum) {
        return plan(request, selectedFamilies, fuzzExistingCookies, maximum, PlaybookOptions.defaults());
    }

    public List<PlannedRequest> plan(HttpRequestData request, Set<AttackFamily> selectedFamilies,
                                    boolean fuzzExistingCookies, int maximum, PlaybookOptions options) {
        Set<String> families = selectedFamilies == null || selectedFamilies.isEmpty() ? null
            : selectedFamilies.stream().map(AttackFamily::id).collect(java.util.stream.Collectors.toSet());
        Set<String> selected = BypassPlaybooks.resolve(BypassPlaybooks.Inventory.BYPASS, families, options);
        List<List<PlannedRequest>> groups = new ArrayList<>();
        for (var descriptor : BypassPlaybooks.available(BypassPlaybooks.Inventory.BYPASS)) {
            if (!selected.contains(descriptor.id())) continue;
            if (descriptor.added()) groups.add(BypassPlaybooks.added(descriptor, request, options, BypassPlaybooks.Inventory.BYPASS));
            else {
                AttackFamily family = descriptor.family();
                List<PlannedRequest> values = switch (family) {
                case HEADER -> headers(request);
                case PATH -> paths(request);
                case VERB -> verbs(request);
                case PARAM -> params(request);
                case COOKIE -> cookies(request, fuzzExistingCookies);
                case TRAILING_DOT -> trailingDot(request);
                case TRAILING_SLASH -> trailingSlash(request);
                case EXTENSION -> extensions(request);
                case CONTENT_TYPE -> contentTypes(request);
                case ENCODING -> encodings(request);
                case PROTOCOL -> protocols(request);
                case CASE -> cases(request);
                };
                groups.add(values.stream().map(p -> p.withPlaybook(descriptor.id())).toList());
            }
        }
        return BypassPlaybooks.fair(groups, Math.max(1, maximum));
    }

    private List<PlannedRequest> headers(HttpRequestData request) {
        List<PlannedRequest> output = new ArrayList<>();
        String targetUrl = request.origin() + request.rawTarget();
        String path = request.path();
        List<String> ips = ResourcePayloads.load("ip_payloads.txt");
        for (String template : ResourcePayloads.load("header_payload_templates.txt")) {
            List<String> rendered;
            if (template.contains("{OOB PAYLOAD}") || template.contains("{OOB DOMAIN PAYLOAD}")) {
                String domain = outOfBandDomain.get();
                if (domain == null || domain.isBlank()) continue;
                rendered = template.contains("{OOB PAYLOAD}")
                    ? List.of(template.replace("{OOB PAYLOAD}", "http://" + domain), template.replace("{OOB PAYLOAD}", "https://" + domain))
                    : List.of(template.replace("{OOB DOMAIN PAYLOAD}", domain));
            } else rendered = template.contains("{IP PAYLOAD}")
                ? ips.stream().map(ip -> template.replace("{IP PAYLOAD}", ip)).toList()
                : List.of(template.replace("{WHITESPACE PAYLOAD}", " ")
                    .replace("{URL PAYLOAD}", targetUrl).replace("{PATH PAYLOAD}", path)
                    .replace("{PATH SWAP}", path + " [PATH_SWAP]"));
            for (String value : rendered) {
                int colon = value.indexOf(':');
                if (colon <= 0) continue;
                String name = value.substring(0, colon).trim();
                String headerValue = value.substring(colon + 1).trim();
                HttpRequestData mutation = request;
                if (headerValue.endsWith(" [PATH_SWAP]")) {
                    headerValue = headerValue.substring(0, headerValue.length() - " [PATH_SWAP]".length());
                    mutation = mutation.withRawTarget(replacePath(request.rawTarget(), "/"));
                }
                output.add(planned(AttackFamily.HEADER, name + ": " + headerValue, mutation.upsertHeader(name, headerValue)));
            }
        }
        String host = request.firstHeader("Host").orElse(request.origin().authority());
        String plain = host.startsWith("[") ? host : host.split(":", 2)[0];
        for (String value : List.of(plain + ":80:443", plain + ":443:80")) {
            output.add(planned(AttackFamily.HEADER, "Host: " + value + " (double-port)",
                request.upsertHeader("Host", value).withProtocol(HttpProtocol.HTTP_1)));
        }
        return output;
    }

    private List<PlannedRequest> paths(HttpRequestData request) {
        try {
            UrlPayloadProcessor processor = new UrlPayloadProcessor(request.origin() + request.rawTarget());
            return processor.generateUrlPayloads(ResourcePayloads.load("url_payloads.txt")).stream()
                .map(url -> planned(AttackFamily.PATH, url, request.withRawTarget(rawTarget(url)))).toList();
        } catch (Exception exception) {
            return List.of();
        }
    }

    private List<PlannedRequest> verbs(HttpRequestData request) {
        List<PlannedRequest> output = new ArrayList<>();
        for (String method : METHODS) {
            String bodyParams = RequestParameterSupport.extractUrlEncodedBody(request);
            HttpRequestData mutation = RequestParameterSupport.supportsBody(request.method()) && Set.of("GET", "HEAD", "DELETE").contains(method)
                && bodyParams != null && !bodyParams.isEmpty()
                ? RequestParameterSupport.moveBodyToQuery(request, method, bodyParams) : request.withMethod(method);
            output.add(planned(AttackFamily.VERB, "Method: " + method, mutation));
        }
        for (String header : OVERRIDE_HEADERS) for (String method : METHODS) {
            output.add(planned(AttackFamily.VERB, header + ": " + method, request.upsertHeader(header, method)));
        }
        for (String method : List.of("POST", "PUT")) for (String header : OVERRIDE_HEADERS)
            for (String override : List.of("GET", "DELETE", "PATCH"))
                output.add(planned(AttackFamily.VERB, method + " + " + header + ": " + override,
                    request.withMethod(method).upsertHeader(header, override)));
        String query = request.query();
        String body = RequestParameterSupport.extractUrlEncodedBody(request);
        for (String method : List.of("POST", "PUT", "PATCH")) {
            if (!query.isEmpty()) output.add(planned(AttackFamily.VERB, method + " (params query→body)",
                RequestParameterSupport.moveQueryToBody(request, method)));
            if (body != null && !body.isEmpty()) output.add(planned(AttackFamily.VERB, method + " (params body→query)",
                RequestParameterSupport.moveBodyToQuery(request, method, body)));
            String parameters = query.isEmpty() ? body : query;
            if (parameters != null && !parameters.isEmpty()) output.add(planned(AttackFamily.VERB, method + " (params in query+body)",
                RequestParameterSupport.putParamsInBoth(request, method, parameters)));
        }
        return output;
    }

    private List<PlannedRequest> params(HttpRequestData request) {
        List<PlannedRequest> output = new ArrayList<>();
        Map<String, String> existing = parsePairs(request.query(), "&");
        for (String name : existing.keySet()) for (String value : FUZZ_VALUES) {
            output.add(planned(AttackFamily.PARAM, name + "=" + value,
                request.withRawTarget(QueryStringUtils.replaceValue(request.rawTarget(), name, value))));
        }
        for (String payload : new PayloadRepository().loadParamPayloads()) {
            output.add(planned(AttackFamily.PARAM, payload, request.withRawTarget(appendQuery(request.rawTarget(), payload))));
        }
        return output;
    }

    private List<PlannedRequest> cookies(HttpRequestData request, boolean fuzzExisting) {
        List<PlannedRequest> output = new ArrayList<>();
        String original = request.firstHeader("Cookie").orElse("");
        if (fuzzExisting) for (String name : parsePairs(original, ";").keySet()) for (String value : FUZZ_VALUES) {
            output.add(planned(AttackFamily.COOKIE, name + "=" + value,
                request.upsertHeader("Cookie", com.bypassfuzzer.core.http.CookieHeaderUtils.replaceValue(original, name, value))));
        }
        for (String payload : new PayloadRepository().loadParamPayloads()) {
            String value = original.isBlank() ? payload : original + "; " + payload;
            output.add(planned(AttackFamily.COOKIE, payload, request.upsertHeader("Cookie", value)));
        }
        return output;
    }

    private List<PlannedRequest> trailingDot(HttpRequestData request) {
        String host = request.firstHeader("Host").orElse(request.origin().authority());
        return List.of(planned(AttackFamily.TRAILING_DOT, "Host: " + host + ".", request.upsertHeader("Host", host + ".")));
    }

    private List<PlannedRequest> trailingSlash(HttpRequestData request) {
        if (request.path().equals("/")) return List.of();
        String path = request.path();
        String query = request.query().isEmpty() ? "" : "?" + request.query();
        List<String> targets = path.endsWith("/") ? List.of(path.substring(0, path.length() - 1) + query, path + "." + query)
            : List.of(path + "/" + query, path + "/." + query);
        return targets.stream().map(target -> planned(AttackFamily.TRAILING_SLASH, target, request.withRawTarget(target))).toList();
    }

    private List<PlannedRequest> extensions(HttpRequestData request) {
        if (request.path().equals("/")) return List.of();
        String base = stripTrailing(request.path());
        String query = request.query().isEmpty() ? "" : "?" + request.query();
        return ResourcePayloads.load("extension_payloads.txt").stream().map(extension ->
            planned(AttackFamily.EXTENSION, base + extension, request.withRawTarget(base + extension + query))).toList();
    }

    private List<PlannedRequest> contentTypes(HttpRequestData request) {
        var output = new ArrayList<PlannedRequest>();
        var parameters = RequestParameterSupport.extractLocatedParameters(request);
        var prepared = !parameters.isEmpty() && !RequestParameterSupport.supportsBody(request.method())
            ? RequestParameterSupport.prepareForBodyFormat(request, "POST") : request;
        String current = prepared.firstHeader("Content-Type").orElse("");
        if (!parameters.isEmpty()) for (var format : RequestBodyFormat.values()) {
            String type = switch (format) {
                case URL_ENCODED -> "application/x-www-form-urlencoded";
                case JSON -> "application/json";
                case XML -> "application/xml";
                case MULTIPART -> "multipart/form-data";
            };
            if (current.contains(type) || format == RequestBodyFormat.XML && current.contains("text/xml")) continue;
            output.add(planned(AttackFamily.CONTENT_TYPE, "Content-Type conversion: " + format,
                RequestParameterSupport.applyBodyFormat(prepared, parameters, format)));
        }
        for (String type : List.of("application/x-www-form-urlencoded", "application/json", "application/xml", "text/xml",
            "multipart/form-data", "*/*", "application/*", "text/*", "application/json;", "application/json;charset="))
            output.add(planned(AttackFamily.CONTENT_TYPE, "Content-Type: " + type, prepared.upsertHeader("Content-Type", type)));
        return output;
    }

    private List<PlannedRequest> encodings(HttpRequestData request) {
        List<PlannedRequest> output = new ArrayList<>();
        String path = request.path();
        String query = request.query().isEmpty() ? "" : "?" + request.query();
        for (String kind : List.of("url", "double-url", "triple-url", "unicode", "unicode-long", "unicode-overflow")) {
            for (int ordinal = 1; ordinal <= 5; ordinal++) {
                String encoded = encodeOrdinal(path, ordinal, kind);
                if (!encoded.equals(path)) output.add(planned(AttackFamily.ENCODING,
                    "Path " + kind + " #" + ordinal + ": " + encoded, request.withRawTarget(encoded + query)));
            }
        }
        for (var parameter : RequestParameterSupport.extractLocatedParameters(request)) {
            if (parameter.name().length() > 100 || parameter.value().length() > 100) continue;
            for (String kind : List.of("url", "double-url", "triple-url", "unicode", "unicode-long", "unicode-overflow")) {
                String name = encodeOrdinal(parameter.name(), 1, kind);
                String value = encodeOrdinal(parameter.value(), 1, kind);
                if (!name.equals(parameter.name())) output.add(planned(AttackFamily.ENCODING,
                    "Param name " + kind + " (" + parameter.location() + "): " + parameter.name() + " → " + name,
                    RequestParameterSupport.replaceParameterName(request, parameter, name)));
                if (!value.equals(parameter.value())) output.add(planned(AttackFamily.ENCODING,
                    "Param value " + kind + " (" + parameter.location() + "): " + parameter.name() + "=" + value,
                    RequestParameterSupport.replaceParameterValue(request, parameter, value)));
            }
        }
        return output;
    }

    private List<PlannedRequest> protocols(HttpRequestData request) {
        return List.of(
            planned(AttackFamily.PROTOCOL, "Protocol: HTTP/2", request.withProtocol(HttpProtocol.HTTP_2)),
            planned(AttackFamily.PROTOCOL, "Protocol: HTTP/1.1", request.withProtocol(HttpProtocol.HTTP_1)),
            planned(AttackFamily.PROTOCOL, "Protocol: HTTP/1.0", request.withProtocol(HttpProtocol.HTTP_1_0).upsertHeader("Connection", "close")),
            planned(AttackFamily.PROTOCOL, "Protocol: HTTP/0.9", request.withProtocol(HttpProtocol.HTTP_0_9))
        );
    }

    private List<PlannedRequest> cases(HttpRequestData request) {
        var values = new LinkedHashSet<String>();
        String path = request.path(), query = request.query();
        List<String> paths = List.of(path, path.toUpperCase(Locale.ROOT), path.toLowerCase(Locale.ROOT), title(path), alternating(path));
        List<String> queries = List.of(query, query.toUpperCase(Locale.ROOT), query.toLowerCase(Locale.ROOT), title(query), alternating(query));
        for (String p : paths) for (String q : queries) values.add(p + (q.isEmpty() ? "" : "?" + q));
        values.remove(request.rawTarget());
        return values.stream().map(value -> planned(AttackFamily.CASE, value, request.withRawTarget(value))).toList();
    }

    private PlannedRequest planned(AttackFamily family, String payload, HttpRequestData request) {
        return new PlannedRequest(family.displayName(), payload, "", request, false);
    }

    private String rawTarget(String url) { int scheme = url.indexOf("://"); if (scheme < 0) return url; int slash = url.indexOf('/', scheme + 3); return slash < 0 ? "/" : url.substring(slash); }
    private String replacePath(String target, String path) { int query = target.indexOf('?'); return path + (query < 0 ? "" : target.substring(query)); }
    private String appendQuery(String target, String pair) { return target + (target.contains("?") ? "&" : "?") + pair; }
    private String stripTrailing(String path) { int end = path.length(); while (end > 1 && path.charAt(end - 1) == '/') end--; return path.substring(0, end); }
    private String title(String input) { StringBuilder result = new StringBuilder(); boolean upper = true; for (char current : input.toCharArray()) { if ("/?&=_-".indexOf(current) >= 0) { result.append(current); upper = true; } else { result.append(upper ? Character.toUpperCase(current) : Character.toLowerCase(current)); upper = false; }} return result.toString(); }
    private String alternating(String input) { StringBuilder result = new StringBuilder(); int index = 0; for (char current : input.toCharArray()) result.append(Character.isLetter(current) ? ((index++ & 1) == 0 ? Character.toUpperCase(current) : Character.toLowerCase(current)) : current); return result.toString(); }
    private String encodeOrdinal(String input, int ordinal, String kind) { int seen = 0; for (int i = 0; i < input.length(); i++) { char current = input.charAt(i); if (!Character.isLetterOrDigit(current)) continue; if (++seen != ordinal) continue; String encoded = switch (kind) { case "url" -> String.format("%%%02X", (int) current); case "double-url" -> String.format("%%25%02X", (int) current); case "triple-url" -> String.format("%%2525%02X", (int) current); case "unicode" -> String.format("%%u%04x", (int) current); case "unicode-long" -> String.format("\\u%04x", (int) current); default -> String.format("%%u%04x", (int) current + (0x4e * 0x100)); }; return input.substring(0, i) + encoded + input.substring(i + 1); } return input; }
    private Map<String, String> parsePairs(String text, String separator) { Map<String, String> values = new LinkedHashMap<>(); if (text == null || text.isBlank()) return values; for (String part : text.split(java.util.regex.Pattern.quote(separator))) { int equal = part.indexOf('='); String name = (equal < 0 ? part : part.substring(0, equal)).trim(); if (!name.isEmpty()) values.put(name, equal < 0 ? "" : part.substring(equal + 1).trim()); } return values; }

}
