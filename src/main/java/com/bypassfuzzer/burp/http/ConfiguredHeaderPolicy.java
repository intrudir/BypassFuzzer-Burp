package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Applies always-send headers and preserves them when a payload attacks the same header. */
public final class ConfiguredHeaderPolicy {

    private final List<ConfiguredHeader> headers;
    private final Map<String, List<ConfiguredHeader>> byName;
    private final UserAgentMode userAgentMode;
    private final long userAgentSeed;

    public ConfiguredHeaderPolicy(List<ConfiguredHeader> headers) {
        this(headers, UserAgentMode.DISABLED, 0L);
    }

    public ConfiguredHeaderPolicy(List<ConfiguredHeader> headers, UserAgentMode userAgentMode,
                                  long userAgentSeed) {
        this.headers = headers == null ? List.of() : List.copyOf(headers);
        this.userAgentMode = userAgentMode == null ? UserAgentMode.DISABLED : userAgentMode;
        this.userAgentSeed = this.userAgentMode == UserAgentMode.DISABLED ? 0L : userAgentSeed;
        Map<String, List<ConfiguredHeader>> grouped = new LinkedHashMap<>();
        for (ConfiguredHeader header : this.headers) {
            grouped.computeIfAbsent(normalize(header.name()), ignored -> new ArrayList<>()).add(header);
        }
        Map<String, List<ConfiguredHeader>> immutable = new LinkedHashMap<>();
        grouped.forEach((name, values) -> immutable.put(name, List.copyOf(values)));
        this.byName = java.util.Collections.unmodifiableMap(immutable);
    }

    public List<ConfiguredHeader> headers() {
        return headers;
    }

    /** Replaces captured values for configured names and retains configured duplicate order. */
    public HttpRequest applyToBase(HttpRequest request) {
        if (request == null || headers.isEmpty()) {
            return request;
        }
        HttpRequest updated = request;
        for (List<ConfiguredHeader> sameName : byName.values()) {
            updated = updated.withRemovedHeader(sameName.get(0).name());
        }
        for (ConfiguredHeader header : headers) {
            updated = updated.withAddedHeader(header.name(), header.value());
        }
        return updated;
    }

    /** Applies configured values to an unmutated request. */
    public HttpRequest reconcileMutation(HttpRequest request) {
        return reconcileMutation(request, request);
    }

    /** Reconciles a generated request by comparing it with the pre-mutation source request. */
    public HttpRequest reconcileMutation(HttpRequest baseline, HttpRequest request) {
        if (request == null) {
            return request;
        }
        if (headers.isEmpty()) {
            return UserAgentRandomizer.reconcile(baseline, request, userAgentMode, userAgentSeed);
        }
        Map<String, List<String>> payloads = new LinkedHashMap<>();
        for (List<ConfiguredHeader> sameName : byName.values()) {
            String name = sameName.get(0).name();
            List<String> baselineValues = values(baseline, name);
            List<String> actual = values(request, name);
            boolean attacked = !actual.equals(baselineValues);
            payloads.put(normalize(name), attacked
                ? payloadDelta(name, baselineValues, actual)
                : List.of());
        }

        HttpRequest updated = applyToBase(request);
        for (List<ConfiguredHeader> sameName : byName.values()) {
            String name = sameName.get(0).name();
            for (String payloadValue : payloads.get(normalize(name))) {
                updated = updated.withAddedHeader(name, payloadValue);
            }
        }
        return UserAgentRandomizer.reconcile(
            applyToBase(baseline), updated, userAgentMode, userAgentSeed);
    }

    public ConfiguredHeaderPolicy withoutAuthentication(java.util.Set<String> authHeaderNames,
                                                        java.util.Set<String> authCookieNames) {
        java.util.Set<String> excluded = new java.util.HashSet<>();
        excluded.add("authorization");
        excluded.add("proxy-authorization");
        if (authHeaderNames != null) {
            authHeaderNames.stream().filter(java.util.Objects::nonNull)
                .map(ConfiguredHeaderPolicy::normalize).forEach(excluded::add);
        }
        List<ConfiguredHeader> retained = new ArrayList<>();
        for (ConfiguredHeader header : headers) {
            String normalized = normalize(header.name());
            if (excluded.contains(normalized)) {
                continue;
            }
            if ("cookie".equals(normalized)) {
                String value = CookieHeaderUtils.removeCookies(header.value(), authCookieNames);
                if (value != null && !value.isBlank()) {
                    retained.add(new ConfiguredHeader(header.name(), value));
                }
            } else {
                retained.add(header);
            }
        }
        return new ConfiguredHeaderPolicy(retained, userAgentMode, userAgentSeed);
    }

    private List<String> values(HttpRequest request, String name) {
        List<String> result = new ArrayList<>();
        try {
            for (HttpHeader header : request.headers()) {
                if (header.name().equalsIgnoreCase(name)) {
                    result.add(header.value());
                }
            }
        } catch (Exception ignored) {
            String value = request.headerValue(name);
            if (value != null) {
                result.add(value);
            }
        }
        return List.copyOf(result);
    }

    private List<String> payloadDelta(String name, List<String> baseline, List<String> actual) {
        if ("cookie".equals(normalize(name)) && baseline.size() == 1 && actual.size() == 1) {
            String prefix = baseline.get(0) + "; ";
            if (actual.get(0).startsWith(prefix)) {
                return List.of(actual.get(0).substring(prefix.length()));
            }
        }
        List<String> remaining = new ArrayList<>(actual);
        for (String originalValue : baseline) {
            remaining.remove(originalValue);
        }
        return List.copyOf(remaining);
    }

    private static String normalize(String name) {
        return name.toLowerCase(Locale.ROOT);
    }
}
