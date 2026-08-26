package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.payloads.HostPortBypassPayloadGenerator;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;
import com.bypassfuzzer.burp.core.payloads.StandalonePathMarkerVariants;
import com.bypassfuzzer.burp.http.RequestHeaderUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class CoverageSweepProbeGenerator {

    private static final String SWEEP_PROBES_FILE = "sweep_probes.txt";
    private static final List<BackslashVariant> BACKSLASH_VARIANTS = List.of(
        new BackslashVariant("raw", "\\"),
        new BackslashVariant("encoded lowercase", "%5c"),
        new BackslashVariant("encoded uppercase", "%5C")
    );
    private final List<CoverageSweepProbeTemplate> templates;
    private final HostPortBypassPayloadGenerator hostPortPayloadGenerator = new HostPortBypassPayloadGenerator();

    public CoverageSweepProbeGenerator() {
        this(loadTemplates());
    }

    CoverageSweepProbeGenerator(List<CoverageSweepProbeTemplate> templates) {
        this.templates = List.copyOf(templates);
    }

    public List<CoverageSweepProbe> buildProbes(HttpRequest request, CoverageSweepOptions options) {
        return buildProbes(request, options, true);
    }

    public List<CoverageSweepProbe> buildProbes(HttpRequest request, CoverageSweepOptions options, boolean includeControl) {
        if (request == null) {
            return List.of();
        }

        int limit = Math.max(1, options.maxProbesPerCandidate())
            + hostPortProbeCount(options);
        List<CoverageSweepProbe> probes = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        if (includeControl) {
            add(probes, seen, limit, new CoverageSweepProbe("Control: original blocked request", "Control", request));
        }
        if (options.hostPortProbesEnabled() && familyEnabled(options, "Host Parsing")) {
            for (HostPortBypassPayloadGenerator.HostPortPayload payload
                : hostPortPayloadGenerator.generateLightweight(request, options.hostPortProbePorts())) {
                add(probes, seen, limit, new CoverageSweepProbe(
                    "Host: " + payload.value() + " (double-port)",
                    "Host Parsing",
                    RequestHeaderUtils.upsertHeader(request, "Host", payload.value()),
                    HttpMode.HTTP_1
                ));
            }
        }

        String path = safePath(request.path());
        if (familyEnabled(options, "Path Normalization")) {
            addBackslashPathProbes(probes, seen, limit, request, path);
        }
        for (CoverageSweepProbeTemplate template : templates) {
            if (!familyEnabled(options, template.family())) {
                continue;
            }
            add(probes, seen, limit, buildProbe(template, request, path));
        }
        if (familyEnabled(options, "Path Normalization")) {
            addStandaloneNormalizationMarkerProbes(probes, seen, limit, request, path);
        }

        return probes;
    }

    /** Promotes the full Bypass catalog's backslash primitive into bounded High Signal coverage. */
    private void addBackslashPathProbes(List<CoverageSweepProbe> probes,
                                        Set<String> seen,
                                        int limit,
                                        HttpRequest request,
                                        String pathWithQuery) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        List<int[]> segments = pathSegments(path);
        for (BackslashVariant variant : BACKSLASH_VARIANTS) {
            for (int index = 0; index < segments.size(); index++) {
                int start = segments.get(index)[0];
                int end = segments.get(index)[1];
                int segmentNumber = index + 1;
                add(probes, seen, limit, backslashProbe(request, query,
                    "Backslash " + variant.label() + " prefix on segment " + segmentNumber,
                    path.substring(0, start) + variant.marker() + path.substring(start)));
                add(probes, seen, limit, backslashProbe(request, query,
                    "Backslash " + variant.label() + " suffix on segment " + segmentNumber,
                    path.substring(0, end) + variant.marker() + path.substring(end)));
                add(probes, seen, limit, backslashProbe(request, query,
                    "Backslash " + variant.label() + " sandwich on segment " + segmentNumber,
                    path.substring(0, start) + variant.marker() + path.substring(start, end)
                        + variant.marker() + path.substring(end)));
            }
        }
    }

    private CoverageSweepProbe backslashProbe(HttpRequest request, String query,
                                               String label, String path) {
        return new CoverageSweepProbe(label, "Path Normalization",
            request.withPath(RequestPathUtils.replaceQuery(path, query)));
    }

    private void addStandaloneNormalizationMarkerProbes(List<CoverageSweepProbe> probes,
                                                         Set<String> seen,
                                                         int limit,
                                                         HttpRequest request,
                                                         String pathWithQuery) {
        for (String marker : StandalonePathMarkerVariants.all()) {
            List<String> variants = standaloneMarkerBoundaryPaths(pathWithQuery, marker);
            for (int index = 0; index < variants.size(); index++) {
                String position = index == variants.size() - 1 ? "all boundaries" : "boundary " + (index + 1);
                add(probes, seen, limit, new CoverageSweepProbe(
                    "Standalone " + marker + " segment at " + position,
                    "Path Normalization",
                    request.withPath(variants.get(index))
                ));
            }

            List<String> surroundedSegments = standaloneMarkerSegmentSurroundPaths(pathWithQuery, marker);
            for (int index = 0; index < surroundedSegments.size(); index++) {
                add(probes, seen, limit, new CoverageSweepProbe(
                    "Surround path segment " + (index + 1) + " with standalone " + marker + " segments",
                    "Path Normalization",
                    request.withPath(surroundedSegments.get(index))
                ));
            }
        }
    }

    private List<String> standaloneMarkerBoundaryPaths(String pathWithQuery, String marker) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        List<Integer> boundaries = new ArrayList<>();
        for (int index = 1; index < path.length() - 1; index++) {
            if (path.charAt(index) == '/' && path.charAt(index - 1) != '/' && path.charAt(index + 1) != '/') {
                boundaries.add(index);
            }
        }
        if (boundaries.isEmpty()) {
            return List.of();
        }

        List<String> variants = new ArrayList<>();
        for (int boundary : boundaries) {
            String variant = path.substring(0, boundary) + "/" + marker + "/" + path.substring(boundary + 1);
            variants.add(RequestPathUtils.replaceQuery(variant, query));
        }

        StringBuilder cumulative = new StringBuilder(path.length() + boundaries.size() * (marker.length() + 1));
        for (int index = 0; index < path.length(); index++) {
            if (boundaries.contains(index)) {
                cumulative.append('/').append(marker).append('/');
            } else {
                cumulative.append(path.charAt(index));
            }
        }
        variants.add(RequestPathUtils.replaceQuery(cumulative.toString(), query));
        return variants;
    }

    private List<String> standaloneMarkerSegmentSurroundPaths(String pathWithQuery, String marker) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        List<int[]> segments = pathSegments(path);

        List<String> variants = new ArrayList<>();
        for (int[] segment : segments) {
            int start = segment[0];
            int end = segment[1];
            String surrounded = path.substring(0, start)
                + marker + "/" + path.substring(start, end) + "/" + marker
                + path.substring(end);
            variants.add(RequestPathUtils.replaceQuery(surrounded, query));
        }
        return variants;
    }

    private List<int[]> pathSegments(String path) {
        List<int[]> segments = new ArrayList<>();
        int index = 0;
        while (index < path.length()) {
            while (index < path.length() && path.charAt(index) == '/') {
                index++;
            }
            if (index >= path.length()) {
                break;
            }
            int start = index;
            while (index < path.length() && path.charAt(index) != '/') {
                index++;
            }
            segments.add(new int[]{start, index});
        }
        return segments;
    }

    private CoverageSweepProbe buildProbe(CoverageSweepProbeTemplate template, HttpRequest request, String path) {
        return switch (template.kind()) {
            case "PATH" -> new CoverageSweepProbe(template.label(), template.family(), request.withPath(renderTemplate(template.value(), path)));
            case "HEADER" -> headerProbe(template, request);
            default -> null;
        };
    }

    private CoverageSweepProbe headerProbe(CoverageSweepProbeTemplate template, HttpRequest request) {
        String requestPath = null;
        String headerTemplate = template.value();
        if (headerTemplate.startsWith("path=")) {
            int headerMarker = headerTemplate.indexOf("; header=");
            if (headerMarker <= 5) {
                return null;
            }
            requestPath = headerTemplate.substring("path=".length(), headerMarker).trim();
            headerTemplate = headerTemplate.substring(headerMarker + "; header=".length()).trim();
        }

        int separator = headerTemplate.indexOf(':');
        if (separator <= 0) {
            return null;
        }
        String name = headerTemplate.substring(0, separator).trim();
        String value = headerTemplate.substring(separator + 1).trim();
        if (name.isBlank()) {
            return null;
        }

        String originalPath = safePath(request.path());
        HttpRequest targetRequest = requestPath == null ? request : request.withPath(renderTemplate(requestPath, originalPath));
        return new CoverageSweepProbe(template.label(), template.family(), RequestHeaderUtils.upsertHeader(targetRequest, name, renderTemplate(value, originalPath)));
    }

    private static int hostPortProbeCount(CoverageSweepOptions options) {
        if (!options.hostPortProbesEnabled() || !familyEnabled(options, "Host Parsing")) {
            return 0;
        }
        int customCount = (int) options.hostPortProbePorts().stream()
            .filter(port -> port >= 1 && port <= 65535)
            .count();
        return customCount * 3 + 2;
    }

    private static boolean familyEnabled(CoverageSweepOptions options, String family) {
        return options.familySelection().highSignalEnabled(family);
    }

    private void add(List<CoverageSweepProbe> probes, Set<String> seen, int limit, CoverageSweepProbe probe) {
        if (probes.size() >= limit || probe == null || probe.request() == null) {
            return;
        }
        if (seen.add(effectiveRequestKey(probe.request()))) {
            probes.add(probe);
        }
    }

    private String effectiveRequestKey(HttpRequest request) {
        StringBuilder key = new StringBuilder();
        key.append(request.method()).append(' ').append(request.path()).append(' ');
        try {
            for (HttpHeader header : request.headers()) {
                key.append(header.name().toLowerCase(java.util.Locale.ROOT)).append(':').append(header.value()).append('|');
            }
        } catch (Exception e) {
            key.append(request.toString());
        }
        key.append(' ').append(request.bodyToString());
        return key.toString();
    }

    private String duplicateSlash(String pathWithQuery, int extraSlashCount) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        if (path.length() <= 1) {
            return pathWithQuery;
        }
        int nextSlash = path.indexOf('/', 1);
        if (nextSlash >= 0) {
            return RequestPathUtils.replaceQuery(path.substring(0, nextSlash) + "/".repeat(extraSlashCount) + path.substring(nextSlash), query);
        }
        return RequestPathUtils.replaceQuery("/".repeat(extraSlashCount + 1) + path.substring(1), query);
    }

    private String capitalizeSegments(String pathWithQuery) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        StringBuilder builder = new StringBuilder(path.length());
        boolean startOfSegment = true;
        for (int index = 0; index < path.length(); index++) {
            char c = path.charAt(index);
            if (c == '/') {
                builder.append(c);
                startOfSegment = true;
            } else if (startOfSegment && Character.isLetter(c)) {
                builder.append(Character.toUpperCase(c));
                startOfSegment = false;
            } else {
                builder.append(Character.toLowerCase(c));
                startOfSegment = false;
            }
        }
        return RequestPathUtils.replaceQuery(builder.toString(), query);
    }

    private String uppercaseSegment(String pathWithQuery, boolean firstSegment) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        String[] parts = path.split("/", -1);
        int target = firstSegment ? firstNonEmptySegment(parts) : lastNonEmptySegment(parts);
        if (target < 0) {
            return pathWithQuery;
        }
        parts[target] = parts[target].toUpperCase(java.util.Locale.ROOT);
        return RequestPathUtils.replaceQuery(String.join("/", parts), query);
    }

    private int firstNonEmptySegment(String[] parts) {
        for (int index = 0; index < parts.length; index++) {
            if (!parts[index].isBlank()) {
                return index;
            }
        }
        return -1;
    }

    private int lastNonEmptySegment(String[] parts) {
        for (int index = parts.length - 1; index >= 0; index--) {
            if (!parts[index].isBlank()) {
                return index;
            }
        }
        return -1;
    }

    private String mixedCase(String pathWithQuery, boolean uppercaseFirst) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        StringBuilder builder = new StringBuilder(path.length());
        int letterIndex = 0;
        for (int index = 0; index < path.length(); index++) {
            char c = path.charAt(index);
            if (!Character.isLetter(c)) {
                builder.append(c);
                continue;
            }
            boolean uppercase = (letterIndex % 2 == 0) == uppercaseFirst;
            builder.append(uppercase ? Character.toUpperCase(c) : Character.toLowerCase(c));
            letterIndex++;
        }
        return RequestPathUtils.replaceQuery(builder.toString(), query);
    }

    private String encodePathCharacterWithQuery(String pathWithQuery, int ordinal) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        return RequestPathUtils.replaceQuery(encodePathCharacter(path, ordinal), query);
    }

    private String encodePathCharacter(String path, int ordinal) {
        int seen = 0;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (isEncodable(c)) {
                seen++;
                if (seen == ordinal) {
                    return path.substring(0, i) + String.format("%%%02x", (int) c) + path.substring(i + 1);
                }
            }
        }
        return path;
    }

    private boolean isEncodable(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    private String safePath(String path) {
        return path == null || path.isBlank() ? "/" : path;
    }

    private String renderTemplate(String template, String pathWithQuery) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String pathWithoutTrailingSlash = stripTrailingSlashes(path);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        String queryWithPrefix = query.isEmpty() ? "" : "?" + query;
        String queryAppendSeparator = query.isEmpty() ? "?" : "&";

        return template
            .replace("{PATH_ORIGINAL}", path)
            .replace("{PATH_NO_LEADING_SLASH}", path.replaceFirst("^/+", ""))
            .replace("{PATH_TRAILING_SLASH_TOGGLE}", toggleTrailingSlash(path))
            .replace("{PATH_DUPLICATE_SLASH_ONCE}", duplicateSlash(pathWithQuery, 1))
            .replace("{PATH_DUPLICATE_SLASH_TWICE}", duplicateSlash(pathWithQuery, 2))
            .replace("{PATH_FIRST_SEGMENT_UPPERCASE}", uppercaseSegment(pathWithQuery, true))
            .replace("{PATH_LAST_SEGMENT_UPPERCASE}", uppercaseSegment(pathWithQuery, false))
            .replace("{PATH_CAPITALIZED}", capitalizeSegments(pathWithQuery))
            .replace("{PATH_MIXED_CASE_1}", mixedCase(pathWithQuery, true))
            .replace("{PATH_MIXED_CASE_2}", mixedCase(pathWithQuery, false))
            .replace("{PATH_URL_ENCODE_CHAR_1}", encodePathCharacterWithQuery(pathWithQuery, 1))
            .replace("{PATH_URL_ENCODE_CHAR_2}", encodePathCharacterWithQuery(pathWithQuery, 2))
            .replace("{PATH_URL_ENCODE_CHAR_3}", encodePathCharacterWithQuery(pathWithQuery, 3))
            .replace("{PATH_URL_ENCODE_CHAR_4}", encodePathCharacterWithQuery(pathWithQuery, 4))
            .replace("{PATH_URL_ENCODE_CHAR_5}", encodePathCharacterWithQuery(pathWithQuery, 5))
            .replace("{PATH_DOUBLE_URL_ENCODE_CHAR_1}", doubleEncodePathCharacterWithQuery(pathWithQuery, 1))
            .replace("{PATH_DOUBLE_URL_ENCODE_CHAR_2}", doubleEncodePathCharacterWithQuery(pathWithQuery, 2))
            .replace("{PATH_DOUBLE_URL_ENCODE_CHAR_3}", doubleEncodePathCharacterWithQuery(pathWithQuery, 3))
            .replace("{PATH_ENCODE_FIRST_SEPARATOR}", encodeFirstSeparator(pathWithQuery, false))
            .replace("{PATH_DOUBLE_ENCODE_FIRST_SEPARATOR}", encodeFirstSeparator(pathWithQuery, true))
            .replace("{PATH_FIRST_SEGMENT_FULLY_URL_ENCODED}", fullyEncodeSegment(pathWithQuery, true, false))
            .replace("{PATH_FIRST_SEGMENT_FULLY_DOUBLE_URL_ENCODED}", fullyEncodeSegment(pathWithQuery, true, true))
            .replace("{PATH_LAST_SEGMENT_FULLY_URL_ENCODED}", fullyEncodeSegment(pathWithQuery, false, false))
            .replace("{QUERY_APPEND_SEPARATOR}", queryAppendSeparator)
            .replace("{QUERY}", queryWithPrefix)
            .replace("{PATH}", pathWithoutTrailingSlash);
    }

    private String stripTrailingSlashes(String path) {
        if (path == null || path.length() <= 1) {
            return path;
        }
        int end = path.length();
        while (end > 1 && path.charAt(end - 1) == '/') {
            end--;
        }
        return path.substring(0, end);
    }

    private String doubleEncodePathCharacterWithQuery(String pathWithQuery, int ordinal) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        return RequestPathUtils.replaceQuery(encodePathCharacter(path, ordinal, true), query);
    }

    private String encodePathCharacter(String path, int ordinal, boolean doubleEncode) {
        int seen = 0;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (isEncodable(c)) {
                seen++;
                if (seen == ordinal) {
                    return path.substring(0, i) + encodedChar(c, doubleEncode) + path.substring(i + 1);
                }
            }
        }
        return path;
    }

    private String encodeFirstSeparator(String pathWithQuery, boolean doubleEncode) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        int separator = path.indexOf('/', 1);
        if (separator < 0) {
            return pathWithQuery;
        }
        String encodedSlash = doubleEncode ? "%252f" : "%2f";
        return RequestPathUtils.replaceQuery(path.substring(0, separator) + encodedSlash + path.substring(separator + 1), query);
    }

    private String fullyEncodeSegment(String pathWithQuery, boolean firstSegment, boolean doubleEncode) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        String[] parts = path.split("/", -1);
        int target = firstSegment ? firstNonEmptySegment(parts) : lastNonEmptySegment(parts);
        if (target < 0) {
            return pathWithQuery;
        }
        parts[target] = fullyEncode(parts[target], doubleEncode);
        return RequestPathUtils.replaceQuery(String.join("/", parts), query);
    }

    private String fullyEncode(String segment, boolean doubleEncode) {
        StringBuilder encoded = new StringBuilder(segment.length() * 3);
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            encoded.append(isEncodable(c) ? encodedChar(c, doubleEncode) : c);
        }
        return encoded.toString();
    }

    private String encodedChar(char c, boolean doubleEncode) {
        return String.format(doubleEncode ? "%%25%02x" : "%%%02x", (int) c);
    }

    private String toggleTrailingSlash(String path) {
        if (path.length() > 1 && path.endsWith("/")) {
            return path.substring(0, path.length() - 1);
        }
        if ("/".equals(path)) {
            return path;
        }
        return path + "/";
    }

    private static List<CoverageSweepProbeTemplate> loadTemplates() {
        List<String> lines = PayloadLoader.loadPayloads(SWEEP_PROBES_FILE);
        List<CoverageSweepProbeTemplate> loaded = new ArrayList<>();
        for (String line : lines) {
            loaded.add(parseTemplate(line));
        }
        return loaded;
    }

    private record BackslashVariant(String label, String marker) {
    }

    private static CoverageSweepProbeTemplate parseTemplate(String line) {
        String[] parts = line.split("\\|", 4);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid sweep probe template: " + line);
        }
        return new CoverageSweepProbeTemplate(
            parts[0].trim(),
            parts[1].trim(),
            parts[2].trim(),
            parts[3].trim()
        );
    }
}
