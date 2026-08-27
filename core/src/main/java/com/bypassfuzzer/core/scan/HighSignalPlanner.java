package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Renders the same bundled curated Sweep inventory without a Burp dependency. */
public final class HighSignalPlanner {
    public static final Set<String> FAMILIES = Set.of("Matrix / Extension", "Extension / Negotiation",
        "Path Normalization", "Encoding", "Debug Params", "Content-Type", "Header", "Host Parsing");

    public List<PlannedRequest> plan(HttpRequestData request, Set<String> enabledFamilies, int maximum) {
        Set<String> selected = enabledFamilies == null || enabledFamilies.isEmpty() ? FAMILIES : enabledFamilies;
        List<PlannedRequest> output = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String line : ResourcePayloads.load("sweep_probes.txt")) {
            if (output.size() >= maximum) break;
            String[] parts = line.split("\\|", 4);
            if (parts.length != 4 || !selected.contains(parts[1].trim())) continue;
            String kind = parts[0].trim();
            String family = parts[1].trim();
            String label = parts[2].trim();
            String value = render(parts[3].trim(), request.rawTarget());
            HttpRequestData mutation = switch (kind) {
                case "PATH" -> request.withRawTarget(value);
                case "HEADER" -> headerMutation(request, value);
                default -> null;
            };
            add(output, seen, maximum, family, label, mutation);
        }
        if (selected.contains("Path Normalization")) addBackslashes(request, output, seen, maximum);
        if (selected.contains("Host Parsing")) addHostParsing(request, output, seen, maximum);
        return List.copyOf(output);
    }

    private HttpRequestData headerMutation(HttpRequestData request, String rendered) {
        String value = rendered;
        String path = null;
        if (value.startsWith("path=")) {
            int marker = value.indexOf("; header=");
            if (marker < 0) return null;
            path = value.substring(5, marker).trim();
            value = value.substring(marker + 9).trim();
        }
        int colon = value.indexOf(':');
        if (colon <= 0) return null;
        HttpRequestData target = path == null ? request : request.withRawTarget(path);
        return target.upsertHeader(value.substring(0, colon).trim(), value.substring(colon + 1).trim());
    }

    private void addBackslashes(HttpRequestData request, List<PlannedRequest> output, Set<String> seen, int maximum) {
        String path = pathOnly(request.rawTarget());
        String query = querySuffix(request.rawTarget());
        List<int[]> segments = segments(path);
        for (String marker : List.of("\\", "%5c", "%5C")) {
            for (int index = 0; index < segments.size() && output.size() < maximum; index++) {
                int start = segments.get(index)[0];
                int end = segments.get(index)[1];
                add(output, seen, maximum, "Path Normalization", "Backslash prefix segment " + (index + 1),
                    request.withRawTarget(path.substring(0, start) + marker + path.substring(start) + query));
                add(output, seen, maximum, "Path Normalization", "Backslash suffix segment " + (index + 1),
                    request.withRawTarget(path.substring(0, end) + marker + path.substring(end) + query));
                add(output, seen, maximum, "Path Normalization", "Backslash sandwich segment " + (index + 1),
                    request.withRawTarget(path.substring(0, start) + marker + path.substring(start, end) + marker
                        + path.substring(end) + query));
            }
        }
    }

    private void addHostParsing(HttpRequestData request, List<PlannedRequest> output, Set<String> seen, int maximum) {
        String host = request.firstHeader("Host").orElse(request.origin().authority());
        String hostname = host.startsWith("[") ? host : host.split(":", 2)[0];
        for (String value : List.of(hostname + ":80:443", hostname + ":443:80")) {
            add(output, seen, maximum, "Host Parsing", "Host double-port " + value,
                request.upsertHeader("Host", value).withProtocol(HttpProtocol.HTTP_1));
        }
    }

    private void add(List<PlannedRequest> output, Set<String> seen, int maximum, String family,
                     String label, HttpRequestData request) {
        if (request == null || output.size() >= maximum) return;
        String key = request.method() + "\n" + request.rawTarget() + "\n" + request.headers() + "\n"
            + java.util.Arrays.hashCode(request.body());
        if (seen.add(key)) output.add(new PlannedRequest(family, label, "", request, false));
    }

    private String render(String template, String rawTarget) {
        String path = pathOnly(rawTarget);
        String stripped = stripTrailing(path);
        String query = querySuffix(rawTarget);
        String queryValue = query.startsWith("?") ? query.substring(1) : query;
        String firstUpper = uppercaseSegment(path, true);
        String lastUpper = uppercaseSegment(path, false);
        return template
            .replace("{PATH_ORIGINAL}", path)
            .replace("{PATH_NO_LEADING_SLASH}", path.replaceFirst("^/+", ""))
            .replace("{PATH_TRAILING_SLASH_TOGGLE}", toggleSlash(path))
            .replace("{PATH_DUPLICATE_SLASH_ONCE}", duplicateSlash(path, 1) + query)
            .replace("{PATH_DUPLICATE_SLASH_TWICE}", duplicateSlash(path, 2) + query)
            .replace("{PATH_FIRST_SEGMENT_UPPERCASE}", firstUpper + query)
            .replace("{PATH_LAST_SEGMENT_UPPERCASE}", lastUpper + query)
            .replace("{PATH_CAPITALIZED}", capitalizeSegments(path) + query)
            .replace("{PATH_MIXED_CASE_1}", mixedCase(path, true) + query)
            .replace("{PATH_MIXED_CASE_2}", mixedCase(path, false) + query)
            .replace("{PATH_URL_ENCODE_CHAR_1}", encodeOrdinal(path, 1, false) + query)
            .replace("{PATH_URL_ENCODE_CHAR_2}", encodeOrdinal(path, 2, false) + query)
            .replace("{PATH_URL_ENCODE_CHAR_3}", encodeOrdinal(path, 3, false) + query)
            .replace("{PATH_URL_ENCODE_CHAR_4}", encodeOrdinal(path, 4, false) + query)
            .replace("{PATH_URL_ENCODE_CHAR_5}", encodeOrdinal(path, 5, false) + query)
            .replace("{PATH_DOUBLE_URL_ENCODE_CHAR_1}", encodeOrdinal(path, 1, true) + query)
            .replace("{PATH_DOUBLE_URL_ENCODE_CHAR_2}", encodeOrdinal(path, 2, true) + query)
            .replace("{PATH_DOUBLE_URL_ENCODE_CHAR_3}", encodeOrdinal(path, 3, true) + query)
            .replace("{PATH_ENCODE_FIRST_SEPARATOR}", encodeFirstSeparator(path, false) + query)
            .replace("{PATH_DOUBLE_ENCODE_FIRST_SEPARATOR}", encodeFirstSeparator(path, true) + query)
            .replace("{PATH_FIRST_SEGMENT_FULLY_URL_ENCODED}", fullyEncodeSegment(path, true, false) + query)
            .replace("{PATH_FIRST_SEGMENT_FULLY_DOUBLE_URL_ENCODED}", fullyEncodeSegment(path, true, true) + query)
            .replace("{PATH_LAST_SEGMENT_FULLY_URL_ENCODED}", fullyEncodeSegment(path, false, false) + query)
            .replace("{QUERY_APPEND_SEPARATOR}", queryValue.isEmpty() ? "?" : "&")
            .replace("{QUERY}", query)
            .replace("{PATH}", stripped);
    }

    private String pathOnly(String target) { int index = target.indexOf('?'); return index < 0 ? target : target.substring(0, index); }
    private String querySuffix(String target) { int index = target.indexOf('?'); return index < 0 ? "" : target.substring(index); }
    private String stripTrailing(String path) { int end = path.length(); while (end > 1 && path.charAt(end - 1) == '/') end--; return path.substring(0, end); }
    private String toggleSlash(String path) { return path.equals("/") ? path : path.endsWith("/") ? path.substring(0, path.length() - 1) : path + "/"; }
    private String duplicateSlash(String path, int count) { int at = path.indexOf('/', 1); return at < 0 ? "/".repeat(count + 1) + path.substring(1) : path.substring(0, at) + "/".repeat(count) + path.substring(at); }
    private String uppercaseSegment(String path, boolean first) { String[] values = path.split("/", -1); int at = first ? 0 : values.length - 1; while (at >= 0 && at < values.length && values[at].isEmpty()) at += first ? 1 : -1; if (at >= 0 && at < values.length) values[at] = values[at].toUpperCase(Locale.ROOT); return String.join("/", values); }
    private String capitalizeSegments(String path) { String[] values = path.split("/", -1); for (int i = 0; i < values.length; i++) if (!values[i].isEmpty()) values[i] = Character.toUpperCase(values[i].charAt(0)) + values[i].substring(1).toLowerCase(Locale.ROOT); return String.join("/", values); }
    private String mixedCase(String path, boolean upperFirst) { StringBuilder out = new StringBuilder(); int letters = 0; for (char current : path.toCharArray()) { if (!Character.isLetter(current)) out.append(current); else { boolean upper = (letters++ % 2 == 0) == upperFirst; out.append(upper ? Character.toUpperCase(current) : Character.toLowerCase(current)); }} return out.toString(); }
    private String encodeOrdinal(String path, int ordinal, boolean twice) { int seen = 0; for (int i = 0; i < path.length(); i++) { char current = path.charAt(i); if (Character.isLetterOrDigit(current) && ++seen == ordinal) return path.substring(0, i) + String.format(twice ? "%%25%02x" : "%%%02x", (int) current) + path.substring(i + 1); } return path; }
    private String encodeFirstSeparator(String path, boolean twice) { int at = path.indexOf('/', 1); return at < 0 ? path : path.substring(0, at) + (twice ? "%252f" : "%2f") + path.substring(at + 1); }
    private String fullyEncodeSegment(String path, boolean first, boolean twice) { String[] values = path.split("/", -1); int at = first ? 0 : values.length - 1; while (at >= 0 && at < values.length && values[at].isEmpty()) at += first ? 1 : -1; if (at < 0 || at >= values.length) return path; StringBuilder encoded = new StringBuilder(); for (char current : values[at].toCharArray()) encoded.append(Character.isLetterOrDigit(current) ? String.format(twice ? "%%25%02x" : "%%%02x", (int) current) : current); values[at] = encoded.toString(); return String.join("/", values); }
    private List<int[]> segments(String path) { List<int[]> result = new ArrayList<>(); int index = 0; while (index < path.length()) { while (index < path.length() && path.charAt(index) == '/') index++; if (index >= path.length()) break; int start = index; while (index < path.length() && path.charAt(index) != '/') index++; result.add(new int[]{start, index}); } return result; }
}
