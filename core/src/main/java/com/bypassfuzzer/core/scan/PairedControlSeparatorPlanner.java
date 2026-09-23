package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Two user-supplied identifiers separated by controls, encoded for the selected request slot. */
public final class PairedControlSeparatorPlanner {
    public static final String FAMILY = "idor.hybrid.paired_control_separators";
    public record Candidate(String replacement, String label, String encoding, boolean priority) {
        public HttpRequestData apply(HttpRequestData request, IdentifierLocation location) {
            return location.replace(request, replacement);
        }
    }
    public record Inventory(List<Candidate> candidates, List<String> notes) {
        public Inventory {
            candidates = List.copyOf(candidates);
            notes = List.copyOf(notes);
        }
    }
    private record Separator(String value, String name, boolean priority) { }

    private static final List<Separator> SEPARATORS = separators();

    public Inventory inventory(HttpRequestData request, IdentifierLocation location,
                               String authorized, String target) {
        List<Candidate> candidates = new ArrayList<>();
        Set<String> notes = new LinkedHashSet<>();
        for (Separator separator : SEPARATORS) {
            String encoding = encoding(request, location, separator.value());
            if (encoding == null) {
                notes.add(skipReason(request, location));
                continue;
            }
            for (boolean authorizedFirst : List.of(true, false)) {
                String first = authorizedFirst ? authorized : target;
                String second = authorizedFirst ? target : authorized;
                String joined = switch (location.kind()) {
                    case PATH -> first + percentEncode(separator.value()) + second;
                    default -> first + separator.value() + second;
                };
                String direction = authorizedFirst ? "id1 → id2" : "id2 → id1";
                candidates.add(new Candidate(joined, separator.name() + " | " + direction,
                    encoding, separator.priority()));
            }
        }
        if (location.kind() == IdentifierLocation.Kind.COOKIE)
            notes.add("Cookie controls skipped: ordinary cookie values cannot carry control characters safely.");
        return new Inventory(candidates, List.copyOf(notes));
    }

    private static String encoding(HttpRequestData request, IdentifierLocation location, String separator) {
        return switch (location.kind()) {
            case PATH, QUERY -> "percent-encoded UTF-8";
            case FORM -> "form-encoded UTF-8";
            case JSON -> "JSON string escape";
            case TEXT, MULTIPART -> location.canEncode(request, separator) ? "body charset" : null;
            case XML_TEXT, XML_ATTRIBUTE -> location.canEncode(request, separator)
                && validXml(separator, request) ? "XML character reference" : null;
            case HEADER -> separator.equals("\t")
                && (request.protocol() == HttpProtocol.HTTP_1
                    || request.protocol() == HttpProtocol.HTTP_1_0)
                ? "inline HTTP/1 tab" : null;
            case COOKIE -> null;
        };
    }

    private static String skipReason(HttpRequestData request, IdentifierLocation location) {
        return switch (location.kind()) {
            case HEADER -> request.protocol() == HttpProtocol.AUTO
                || request.protocol() == HttpProtocol.BOTH
                ? "Header controls skipped while the protocol may negotiate HTTP/2; select HTTP/1 for inline-tab probes."
                : request.protocol() == HttpProtocol.HTTP_2
                ? "HTTP/2 header controls skipped; ordinary header fields cannot carry them safely."
                : "Header controls except inline tab skipped; raw CR/LF header framing is not generated.";
            case COOKIE -> "Cookie controls skipped; ordinary cookie values cannot carry them safely.";
            case XML_TEXT, XML_ATTRIBUTE -> "XML controls forbidden by the document version or charset were skipped.";
            case TEXT, MULTIPART -> "Characters unsupported by the declared body charset were skipped.";
            default -> "Unsupported separator skipped.";
        };
    }

    private static boolean validXml(String value, HttpRequestData request) {
        boolean xml11 = new String(request.body(), StandardCharsets.ISO_8859_1)
            .matches("(?s)^\\s*<\\?xml[^?]*version\\s*=\\s*['\"]1\\.1['\"].*");
        return value.codePoints().allMatch(codepoint -> codepoint != 0 && (xml11
            ? codepoint >= 1 && codepoint <= 0x10FFFF
            : codepoint == 9 || codepoint == 10 || codepoint == 13
                || codepoint >= 0x20 && codepoint <= 0xD7FF
                || codepoint >= 0xE000 && codepoint <= 0xFFFD
                || codepoint >= 0x10000 && codepoint <= 0x10FFFF));
    }

    private static List<Separator> separators() {
        List<Separator> values = new ArrayList<>();
        values.add(new Separator("\n", "LF U+000A", true));
        values.add(new Separator("\r\n", "CRLF U+000D U+000A", true));
        values.add(new Separator("\r", "CR U+000D", true));
        values.add(new Separator("\0", "NUL U+0000", true));
        values.add(new Separator("\t", "TAB U+0009", true));
        Set<Integer> priority = Set.of(0, 9, 10, 13);
        for (int cp = 0; cp <= 0x1F; cp++) add(values, cp, priority);
        for (int cp = 0x7F; cp <= 0x9F; cp++) add(values, cp, priority);
        for (int cp : new int[]{0x00AD, 0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
            0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060,
            0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF}) add(values, cp, Set.of());
        return List.copyOf(values);
    }

    private static void add(List<Separator> values, int codepoint, Set<Integer> excluded) {
        if (!excluded.contains(codepoint))
            values.add(new Separator(new String(Character.toChars(codepoint)),
                "U+" + String.format("%04X", codepoint), false));
    }

    private static String percentEncode(String value) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8))
            encoded.append('%').append(String.format("%02X", b & 0xff));
        return encoded.toString();
    }
}
