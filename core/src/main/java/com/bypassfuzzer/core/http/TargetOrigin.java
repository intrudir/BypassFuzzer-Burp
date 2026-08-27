package com.bypassfuzzer.core.http;

import java.net.URI;
import java.util.Locale;

/** Network destination kept separate from fuzzable Host/authority request data. */
public record TargetOrigin(String scheme, String host, int port) {
    public TargetOrigin {
        scheme = scheme == null ? "" : scheme.toLowerCase(Locale.ROOT);
        host = host == null ? "" : host.trim();
        if (!(scheme.equals("http") || scheme.equals("https"))) {
            throw new IllegalArgumentException("Target origin scheme must be http or https");
        }
        if (host.isBlank()) {
            throw new IllegalArgumentException("Target origin host is required");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Target origin port must be between 1 and 65535");
        }
    }

    public static TargetOrigin parse(String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("Invalid target origin: " + value, exception);
        }
        if (uri.getScheme() == null || uri.getHost() == null || uri.getRawUserInfo() != null
            || (uri.getRawPath() != null && !uri.getRawPath().isEmpty() && !uri.getRawPath().equals("/"))
            || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Target origin must contain only scheme, host, and optional port: " + value);
        }
        int port = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
        return new TargetOrigin(uri.getScheme(), uri.getHost(), port);
    }

    public boolean secure() {
        return scheme.equals("https");
    }

    public String authority() {
        int defaultPort = secure() ? 443 : 80;
        String renderedHost = host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
        return port == defaultPort ? renderedHost : renderedHost + ":" + port;
    }

    @Override
    public String toString() {
        return scheme + "://" + authority();
    }
}
