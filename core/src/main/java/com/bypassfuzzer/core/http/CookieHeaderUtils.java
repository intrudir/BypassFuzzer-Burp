package com.bypassfuzzer.core.http;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Set;

/**
 * Cookie-header parsing and rewrite helpers that preserve cookie order.
 */
public final class CookieHeaderUtils {

    private CookieHeaderUtils() {
    }

    public static Map<String, String> parse(String cookieHeader) {
        Map<String, String> cookies = new LinkedHashMap<>();
        for (CookiePart cookie : parseCookieParts(cookieHeader)) {
            String name = cookie.name();
            String value = cookie.value();
            cookies.put(name, value);
        }

        return cookies;
    }

    public static String toHeaderValue(Map<String, String> cookies) {
        StringBuilder header = new StringBuilder();
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            if (header.length() > 0) {
                header.append("; ");
            }
            header.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return header.toString();
    }

    public static String replaceValue(String cookieHeader, String cookieName, String value) {
        List<CookiePart> cookies = parseCookieParts(cookieHeader);
        boolean replaced = false;
        for (int i = 0; i < cookies.size(); i++) {
            CookiePart cookie = cookies.get(i);
            if (cookie.name().equals(cookieName)) {
                cookies.set(i, cookie.withValue(value));
                replaced = true;
            }
        }

        if (!replaced) {
            return cookieHeader;
        }

        return toHeaderValue(cookies);
    }

    public static String appendCookie(String cookieHeader, String cookie) {
        if (cookie == null || cookie.isEmpty()) {
            return cookieHeader;
        }
        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return cookie;
        }
        return cookieHeader + "; " + cookie;
    }

    public static String upsertCookie(String cookieHeader, String cookie) {
        if (cookie == null || cookie.isEmpty()) {
            return cookieHeader;
        }

        CookiePart target = parseCookieParts(cookie).stream().findFirst().orElse(null);
        if (target == null) {
            return appendCookie(cookieHeader, cookie);
        }

        List<CookiePart> cookies = parseCookieParts(cookieHeader);
        boolean replaced = false;
        for (int i = 0; i < cookies.size(); i++) {
            CookiePart existing = cookies.get(i);
            if (existing.name().equals(target.name())) {
                cookies.set(i, target);
                replaced = true;
            }
        }

        if (replaced) {
            return toHeaderValue(cookies);
        }

        return appendCookie(cookieHeader, cookie);
    }

    public static String removeCookies(String cookieHeader, Set<String> cookieNames) {
        if (cookieHeader == null || cookieNames == null || cookieNames.isEmpty()) {
            return cookieHeader;
        }
        List<CookiePart> retained = parseCookieParts(cookieHeader).stream()
            .filter(cookie -> cookieNames.stream().noneMatch(name -> name.equalsIgnoreCase(cookie.name())))
            .toList();
        return toHeaderValue(retained);
    }

    private static String toHeaderValue(List<CookiePart> cookies) {
        return cookies.stream()
            .map(cookie -> cookie.name() + "=" + cookie.value())
            .collect(Collectors.joining("; "));
    }

    private static List<CookiePart> parseCookieParts(String cookieHeader) {
        List<CookiePart> cookies = new ArrayList<>();
        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return cookies;
        }

        String[] pairs = cookieHeader.split(";");
        for (String pair : pairs) {
            String trimmed = pair.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            int eqIdx = trimmed.indexOf('=');
            if (eqIdx <= 0) {
                continue;
            }

            String name = trimmed.substring(0, eqIdx).trim();
            String value = eqIdx < trimmed.length() - 1 ? trimmed.substring(eqIdx + 1).trim() : "";
            cookies.add(new CookiePart(name, value));
        }

        return cookies;
    }

    private record CookiePart(String name, String value) {
        private CookiePart withValue(String newValue) {
            return new CookiePart(name, newValue);
        }
    }
}
