package com.bypassfuzzer.core.http;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Burp's always-send and payload-delta semantics, shared with the standalone CLI. */
public final class RequestHeaderPolicy<R> {
    private final RequestAccess<R> access;
    private final List<ConfiguredHeader> headers;
    private final Map<String, List<ConfiguredHeader>> byName = new LinkedHashMap<>();
    private final UserAgentMode mode;
    private final long seed;

    public RequestHeaderPolicy(RequestAccess<R> access, List<ConfiguredHeader> headers, UserAgentMode mode, long seed) {
        this.access = access;
        this.headers = headers == null ? List.of() : List.copyOf(headers);
        this.mode = mode == null ? UserAgentMode.DISABLED : mode;
        this.seed = this.mode == UserAgentMode.DISABLED ? 0 : seed;
        for (var header : this.headers)
            byName.computeIfAbsent(normalize(header.name()), ignored -> new ArrayList<>()).add(header);
    }

    public List<ConfiguredHeader> headers() { return headers; }

    public R applyToBase(R request) {
        if (request == null || headers.isEmpty() || !access.supportsHeaders(request)) return request;
        R updated = request;
        for (var entries : byName.values()) updated = access.removeHeader(updated, entries.get(0).name());
        for (var header : headers) updated = access.addHeader(updated, header.name(), header.value());
        return updated;
    }

    public R reconcileMutation(R baseline, R request) {
        if (request == null) return null;
        // A headerless protocol mutation must retain its wire shape, even with a fixed or randomized UA.
        if (!access.supportsHeaders(request)) return request;
        var payloads = new LinkedHashMap<String, List<String>>();
        for (var entries : byName.values()) {
            String name = entries.get(0).name();
            var before = values(baseline, name);
            var actual = values(request, name);
            payloads.put(normalize(name), before.equals(actual) ? List.of() : delta(name, before, actual));
        }
        R updated = applyToBase(request);
        for (var entries : byName.values()) {
            String name = entries.get(0).name();
            for (String value : payloads.get(normalize(name))) updated = access.addHeader(updated, name, value);
        }
        if (mode == UserAgentMode.DISABLED) return updated;
        var attacks = new ArrayList<>(values(updated, "User-Agent"));
        for (String value : values(applyToBase(baseline), "User-Agent")) attacks.remove(value);
        String ua = UserAgentVariants.valueFor(mode, seed, access.method(updated), access.url(updated),
            access.headers(updated), access.body(updated));
        updated = access.addHeader(access.removeHeader(updated, "User-Agent"), "User-Agent", ua);
        for (String value : attacks) updated = access.addHeader(updated, "User-Agent", value);
        return updated;
    }

    public RequestHeaderPolicy<R> withoutAuthentication(Set<String> headerNames, Set<String> cookieNames) {
        var excluded = new java.util.HashSet<>(Set.of("authorization", "proxy-authorization"));
        if (headerNames != null) headerNames.stream().filter(java.util.Objects::nonNull)
            .map(RequestHeaderPolicy::normalize).forEach(excluded::add);
        var retained = new ArrayList<ConfiguredHeader>();
        for (var header : headers) {
            if (excluded.contains(normalize(header.name()))) continue;
            String value = header.name().equalsIgnoreCase("Cookie")
                ? CookieHeaderUtils.removeCookies(header.value(), cookieNames) : header.value();
            if (!header.name().equalsIgnoreCase("Cookie") || value != null && !value.isBlank())
                retained.add(new ConfiguredHeader(header.name(), value));
        }
        return new RequestHeaderPolicy<>(access, retained, mode, seed);
    }

    private List<String> values(R request, String name) {
        if (request == null) return List.of();
        return access.headers(request).stream().filter(h -> h.name().equalsIgnoreCase(name)).map(HttpHeader::value).toList();
    }

    private List<String> delta(String name, List<String> before, List<String> actual) {
        if (name.equalsIgnoreCase("Cookie") && before.size() == 1 && actual.size() == 1) {
            String prefix = before.get(0) + "; ";
            if (actual.get(0).startsWith(prefix)) return List.of(actual.get(0).substring(prefix.length()));
        }
        var remaining = new ArrayList<>(actual);
        before.forEach(remaining::remove);
        return List.copyOf(remaining);
    }

    private static String normalize(String value) { return value.toLowerCase(Locale.ROOT); }
}
