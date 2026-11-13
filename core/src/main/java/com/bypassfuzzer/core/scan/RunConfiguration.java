package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import java.util.*;

/** The editable part of a run. Socket destinations and mode-specific seeds remain fixed. */
public record RunConfiguration(Set<String> excludedHosts, int concurrency, int perHostConcurrency,
                               double requestsPerSecond, Set<String> playbooks,
                               List<ConfiguredHeader> headers, Set<String> removeHeaders,
                               UserAgentMode userAgentMode, long userAgentSeed) {
    public RunConfiguration {
        if (concurrency < 1 || perHostConcurrency < 1 || perHostConcurrency > concurrency)
            throw new IllegalArgumentException("Concurrency must be positive; per-host concurrency cannot exceed total concurrency");
        if (!Double.isFinite(requestsPerSecond) || requestsPerSecond <= 0)
            throw new IllegalArgumentException("Requests/second must be finite and greater than zero");
        var hosts = new TreeSet<String>();
        for (String host : excludedHosts == null ? Set.<String>of() : excludedHosts) {
            String normalized = normalizeHost(host);
            if (normalized.isEmpty() || normalized.contains("/") || normalized.chars().anyMatch(Character::isWhitespace)
                || normalized.contains("*") || normalized.contains("?") || normalized.chars().filter(c -> c==':').count()==1)
                throw new IllegalArgumentException("Exclusions must be exact hostnames or IP addresses, without scheme, port or path");
            hosts.add(normalized);
        }
        excludedHosts = Set.copyOf(hosts);
        playbooks = playbooks == null ? null : Set.copyOf(playbooks);
        headers = headers == null ? List.of() : List.copyOf(headers);
        for (var header : headers) {
            validateName(header.name());
            if (header.value() == null || header.value().indexOf('\r') >= 0 || header.value().indexOf('\n') >= 0 || header.value().indexOf('\0') >= 0)
                throw new IllegalArgumentException("Header values cannot contain CR, LF or NUL");
        }
        var removed = new TreeSet<String>();
        for (String name : removeHeaders == null ? Set.<String>of() : removeHeaders) {
            validateName(name); removed.add(name.toLowerCase(Locale.ROOT));
        }
        for (var header : headers) if (removed.contains(header.name().toLowerCase(Locale.ROOT)))
            throw new IllegalArgumentException("A header cannot be both set and removed: " + header.name());
        removeHeaders = Set.copyOf(removed);
        userAgentMode = userAgentMode == null ? UserAgentMode.DISABLED : userAgentMode;
    }
    private static void validateName(String name) {
        if (name == null || !name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
            throw new IllegalArgumentException("Invalid header name");
    }
    public static String normalizeHost(String host) {
        String value = host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("[") && value.endsWith("]")) value = value.substring(1,value.length()-1);
        return value.replaceFirst("\\.$", "");
    }
    public boolean excludes(String host) { return excludedHosts.contains(normalizeHost(host)); }
    public boolean sameHeaders(RunConfiguration other) {
        return headers.equals(other.headers) && removeHeaders.equals(other.removeHeaders)
            && userAgentMode == other.userAgentMode && userAgentSeed == other.userAgentSeed;
    }
    public <Q> Q prepare(Q request, RequestAccess<Q> access) {
        for (String name : removeHeaders) request = access.removeHeader(request, name);
        return policy(access).applyToBase(request);
    }
    public <Q> RequestHeaderPolicy<Q> policy(RequestAccess<Q> access) {
        return new RequestHeaderPolicy<>(access, headers, userAgentMode, userAgentSeed);
    }
}
