package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.payloads.PayloadRepository;
import com.bypassfuzzer.core.payloads.UrlPayloadProcessor;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
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
        Set<AttackFamily> selected = selectedFamilies == null || selectedFamilies.isEmpty()
            ? new LinkedHashSet<>(Arrays.asList(AttackFamily.values())) : new LinkedHashSet<>(selectedFamilies);
        Map<AttackFamily, List<PlannedRequest>> byFamily = new EnumMap<>(AttackFamily.class);
        for (AttackFamily family : AttackFamily.values()) {
            if (!selected.contains(family)) continue;
            byFamily.put(family, switch (family) {
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
            });
        }
        return roundRobin(byFamily, Math.max(1, maximum));
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
        for (String method : METHODS) output.add(planned(AttackFamily.VERB, "Method: " + method, request.withMethod(method)));
        String original = request.method();
        for (String method : List.of(original.toLowerCase(Locale.ROOT), title(original), alternating(original), "X" + original, original + "X")) {
            output.add(planned(AttackFamily.VERB, "Method: " + method, request.withMethod(method)));
        }
        for (String header : OVERRIDE_HEADERS) for (String method : METHODS) {
            output.add(planned(AttackFamily.VERB, header + ": " + method, request.upsertHeader(header, method)));
        }
        return output;
    }

    private List<PlannedRequest> params(HttpRequestData request) {
        List<PlannedRequest> output = new ArrayList<>();
        Map<String, String> existing = parsePairs(request.query(), "&");
        for (String name : existing.keySet()) for (String value : FUZZ_VALUES) {
            output.add(planned(AttackFamily.PARAM, name + "=" + value,
                request.withRawTarget(replaceQueryValue(request.rawTarget(), name, value))));
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
                request.upsertHeader("Cookie", replaceDelimitedValue(original, name, value, "; "))));
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
        return List.of("application/x-www-form-urlencoded", "application/json", "application/xml", "text/xml",
            "multipart/form-data", "*/*", "application/*", "text/*", "application/json;", "application/json;charset=")
            .stream().map(value -> planned(AttackFamily.CONTENT_TYPE, "Content-Type: " + value,
                request.upsertHeader("Content-Type", value))).toList();
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
        String target = request.rawTarget();
        LinkedHashSet<String> values = new LinkedHashSet<>(List.of(target.toUpperCase(Locale.ROOT),
            target.toLowerCase(Locale.ROOT), title(target), alternating(target)));
        values.remove(target);
        return values.stream().map(value -> planned(AttackFamily.CASE, value, request.withRawTarget(value))).toList();
    }

    private PlannedRequest planned(AttackFamily family, String payload, HttpRequestData request) {
        return new PlannedRequest(family.displayName(), payload, "", request, false);
    }

    private List<PlannedRequest> roundRobin(Map<AttackFamily, List<PlannedRequest>> families, int maximum) {
        List<PlannedRequest> output = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        int index = 0;
        boolean added;
        do {
            added = false;
            for (AttackFamily family : AttackFamily.values()) {
                List<PlannedRequest> values = families.getOrDefault(family, List.of());
                if (index >= values.size()) continue;
                PlannedRequest value = values.get(index);
                String key = family.id() + "\n" + value.request().method() + "\n" + value.request().rawTarget() + "\n"
                    + value.request().headers() + "\n" + Arrays.hashCode(value.request().body());
                if (seen.add(key)) output.add(value);
                added = true;
                if (output.size() >= maximum) return List.copyOf(output);
            }
            index++;
        } while (added);
        return List.copyOf(output);
    }

    private String rawTarget(String url) { int scheme = url.indexOf("://"); if (scheme < 0) return url; int slash = url.indexOf('/', scheme + 3); return slash < 0 ? "/" : url.substring(slash); }
    private String replacePath(String target, String path) { int query = target.indexOf('?'); return path + (query < 0 ? "" : target.substring(query)); }
    private String appendQuery(String target, String pair) { return target + (target.contains("?") ? "&" : "?") + pair; }
    private String stripTrailing(String path) { int end = path.length(); while (end > 1 && path.charAt(end - 1) == '/') end--; return path.substring(0, end); }
    private String title(String input) { StringBuilder result = new StringBuilder(); boolean upper = true; for (char current : input.toCharArray()) { if ("/?&=_-".indexOf(current) >= 0) { result.append(current); upper = true; } else { result.append(upper ? Character.toUpperCase(current) : Character.toLowerCase(current)); upper = false; }} return result.toString(); }
    private String alternating(String input) { StringBuilder result = new StringBuilder(); int index = 0; for (char current : input.toCharArray()) result.append(Character.isLetter(current) ? ((index++ & 1) == 0 ? Character.toUpperCase(current) : Character.toLowerCase(current)) : current); return result.toString(); }
    private String encodeOrdinal(String input, int ordinal, String kind) { int seen = 0; for (int i = 0; i < input.length(); i++) { char current = input.charAt(i); if (!Character.isLetterOrDigit(current)) continue; if (++seen != ordinal) continue; String encoded = switch (kind) { case "url" -> String.format("%%%02X", (int) current); case "double-url" -> String.format("%%25%02X", (int) current); case "triple-url" -> String.format("%%2525%02X", (int) current); case "unicode" -> String.format("%%u%04x", (int) current); case "unicode-long" -> String.format("\\u%04x", (int) current); default -> String.format("%%u%04x", (int) current + (0x4e * 0x100)); }; return input.substring(0, i) + encoded + input.substring(i + 1); } return input; }
    private Map<String, String> parsePairs(String text, String separator) { Map<String, String> values = new LinkedHashMap<>(); if (text == null || text.isBlank()) return values; for (String part : text.split(java.util.regex.Pattern.quote(separator))) { int equal = part.indexOf('='); String name = (equal < 0 ? part : part.substring(0, equal)).trim(); if (!name.isEmpty()) values.put(name, equal < 0 ? "" : part.substring(equal + 1).trim()); } return values; }
    private String replaceQueryValue(String target, String name, String value) { int question = target.indexOf('?'); if (question < 0) return appendQuery(target, name + "=" + value); String path = target.substring(0, question); Map<String, String> pairs = parsePairs(target.substring(question + 1), "&"); pairs.put(name, value); return path + "?" + pairs.entrySet().stream().map(entry -> entry.getKey() + "=" + entry.getValue()).collect(java.util.stream.Collectors.joining("&")); }
    private String replaceDelimitedValue(String text, String name, String value, String separator) { Map<String, String> pairs = parsePairs(text, ";"); pairs.put(name, value); return pairs.entrySet().stream().map(entry -> entry.getKey() + "=" + entry.getValue()).collect(java.util.stream.Collectors.joining(separator)); }
}
