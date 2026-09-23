package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Character offsets in {@link HttpRequestData#toRaw()} for one exact identifier slot. */
public record IdentifierLocationSpan(int start, int end) {
    public static Optional<IdentifierLocationSpan> find(HttpRequestData request, IdentifierLocation location) {
        int targetStart = request.method().length() + 1;
        String raw = request.toRaw();
        int bodyStart = raw.length() - request.body().length;
        if (location.byteOffset() >= 0) {
            int start = switch (location.kind()) {
                case HEADER, COOKIE -> location.byteOffset();
                default -> bodyStart + location.byteOffset();
            };
            return start < 0 || start + location.byteLength() > raw.length() ? Optional.empty()
                : Optional.of(new IdentifierLocationSpan(start, start + location.byteLength()));
        }
        return switch (location.kind()) {
            case PATH -> path(request.path(), location.index(), targetStart);
            case QUERY -> pairs(request.query(), location.index(),
                targetStart + request.path().length() + 1);
            case FORM -> pairs(new String(request.body(), StandardCharsets.ISO_8859_1),
                location.index(), bodyStart);
            case JSON -> json(request, location.path(), bodyStart);
            case HEADER, COOKIE, TEXT, XML_TEXT, XML_ATTRIBUTE, MULTIPART -> Optional.empty();
        };
    }

    private static Optional<IdentifierLocationSpan> path(String path, int index, int start) {
        String[] segments = path.split("/", -1);
        if (index < 0 || index >= segments.length || segments[index].isEmpty()) return Optional.empty();
        int offset = start;
        for (int i = 0; i < index; i++) offset += segments[i].length() + 1;
        return Optional.of(new IdentifierLocationSpan(offset, offset + segments[index].length()));
    }

    private static Optional<IdentifierLocationSpan> pairs(String raw, int index, int start) {
        String[] pairs = raw.split("&", -1);
        if (index < 0 || index >= pairs.length) return Optional.empty();
        int offset = start;
        for (int i = 0; i < index; i++) offset += pairs[i].length() + 1;
        int equal = pairs[index].indexOf('=');
        if (equal < 0 || equal == pairs[index].length() - 1) return Optional.empty();
        return Optional.of(new IdentifierLocationSpan(offset + equal + 1, offset + pairs[index].length()));
    }

    private static Optional<IdentifierLocationSpan> json(HttpRequestData request, String pointer, int bodyStart) {
        String body = new String(request.body(), StandardCharsets.UTF_8);
        try {
            IdentifierLocationSpan local = new JsonSpans(body, pointer).find();
            if (local == null) return Optional.empty();
            int start = body.substring(0, local.start()).getBytes(StandardCharsets.UTF_8).length;
            int end = body.substring(0, local.end()).getBytes(StandardCharsets.UTF_8).length;
            return Optional.of(new IdentifierLocationSpan(bodyStart + start, bodyStart + end));
        } catch (RuntimeException invalidJson) {
            return Optional.empty();
        }
    }

    /** Walks JSON source tokens so a pointer resolves to the original bytes, including escapes. */
    private static final class JsonSpans {
        private final String source;
        private final String wanted;
        private int offset;
        private IdentifierLocationSpan result;

        private JsonSpans(String source, String wanted) {
            this.source = source;
            this.wanted = wanted;
        }

        private IdentifierLocationSpan find() {
            value("");
            whitespace();
            if (offset != source.length()) throw new IllegalArgumentException("Trailing JSON content");
            return result;
        }

        private void value(String pointer) {
            whitespace();
            char token = current();
            if (token == '{') {
                offset++;
                whitespace();
                if (consume('}')) return;
                do {
                    whitespace();
                    String name = string();
                    whitespace();
                    require(':');
                    value(pointer + "/" + name.replace("~", "~0").replace("/", "~1"));
                    whitespace();
                    if (consume('}')) return;
                    require(',');
                } while (true);
            }
            if (token == '[') {
                offset++;
                whitespace();
                if (consume(']')) return;
                int index = 0;
                do {
                    value(pointer + "/" + index++);
                    whitespace();
                    if (consume(']')) return;
                    require(',');
                } while (true);
            }
            int start = offset;
            if (token == '"') {
                string();
                start++;
                if (pointer.equals(wanted)) result = new IdentifierLocationSpan(start, offset - 1);
            } else {
                while (offset < source.length() && ",}] \t\r\n".indexOf(source.charAt(offset)) < 0) offset++;
                if (start == offset) throw new IllegalArgumentException("Missing JSON value");
                if (pointer.equals(wanted)) result = new IdentifierLocationSpan(start, offset);
            }
        }

        private String string() {
            int start = offset;
            require('"');
            while (true) {
                char ch = current();
                offset++;
                if (ch == '"') break;
                if (ch == '\\') offset++;
            }
            return JsonParser.parseString(source.substring(start, offset)).getAsString();
        }

        private char current() {
            if (offset >= source.length()) throw new IllegalArgumentException("Incomplete JSON");
            return source.charAt(offset);
        }

        private void whitespace() {
            while (offset < source.length() && " \t\r\n".indexOf(source.charAt(offset)) >= 0) offset++;
        }

        private boolean consume(char expected) {
            if (offset < source.length() && source.charAt(offset) == expected) {
                offset++;
                return true;
            }
            return false;
        }

        private void require(char expected) {
            if (!consume(expected)) throw new IllegalArgumentException("Unexpected JSON token");
        }
    }
}
