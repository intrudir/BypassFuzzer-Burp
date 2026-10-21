package com.bypassfuzzer.core.scan;
import java.util.*;
import java.util.regex.Pattern;
import com.bypassfuzzer.core.http.HttpRequestData;

/** The Burp master's static-asset and endpoint-shape rules. */
public final class SweepCandidateRules {
    private static final Pattern IMAGE_PATH_PATTERN = Pattern.compile(
        ".*\\.(?:apng|avif|bmp|gif|ico|jpe?g|png|svg|tiff?|webp)$");
    private static final Pattern JAVASCRIPT_PATH_PATTERN = Pattern.compile(
        ".*\\.(?:cjs|js|mjs|js\\.map)$");
    private static final Pattern STYLESHEET_OR_FONT_PATH_PATTERN = Pattern.compile(
        ".*\\.(?:css|woff2?)$");
    public static boolean staticAsset(String pathWithQuery, String contentType) {
        String responseContentType = safe(contentType)
            .toLowerCase(Locale.ROOT)
            .split(";", 2)[0]
            .trim();
        if (responseContentType.startsWith("image/")
            || responseContentType.equals("text/css")
            || responseContentType.equals("text/javascript")
            || responseContentType.equals("application/javascript")
            || responseContentType.equals("application/x-javascript")
            || responseContentType.equals("text/ecmascript")
            || responseContentType.equals("application/ecmascript")
            || responseContentType.equals("font/woff")
            || responseContentType.equals("font/woff2")
            || responseContentType.equals("application/font-woff")
            || responseContentType.equals("application/x-font-woff")) {
            return true;
        }

        String path = pathOnly(safe(pathWithQuery))
            .toLowerCase(Locale.ROOT);
        return IMAGE_PATH_PATTERN.matcher(path).matches()
            || JAVASCRIPT_PATH_PATTERN.matcher(path).matches()
            || STYLESHEET_OR_FONT_PATH_PATTERN.matcher(path).matches();
    }

    public static String normalizedPathShape(String pathWithQuery) {
        String path = pathOnly(pathWithQuery);
        String[] parts = path.split("/");
        List<String> normalized = new ArrayList<>();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            String lower = part.toLowerCase(Locale.ROOT);
            if (lower.matches("\\d+")) {
                normalized.add("{num}");
            } else if (lower.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
                normalized.add("{uuid}");
            } else {
                normalized.add(lower);
            }
        }
        return "/" + String.join("/", normalized);
    }

    private static String safe(String value) { return value == null ? "" : value; }
    private static String pathOnly(String value) { return safe(value).split("\\?", 2)[0]; }
    public static List<HttpRequestData> select(List<HttpRequestData> inputs, int max, boolean dedupe) {
        var values = new LinkedHashMap<String, HttpRequestData>();
        int index = 0;
        for (var request : inputs) {
            String key = dedupe ? request.origin() + "|" + request.method().toUpperCase(Locale.ROOT) + "|"
                + normalizedPathShape(request.rawTarget()) : Integer.toString(index++);
            values.putIfAbsent(key, request);
        }
        return values.values().stream().limit(max).toList();
    }
}
