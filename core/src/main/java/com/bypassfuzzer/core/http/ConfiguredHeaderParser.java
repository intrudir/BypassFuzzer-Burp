package com.bypassfuzzer.core.http;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Parses the multiline request-header editor format. */
public final class ConfiguredHeaderParser {

    private static final Pattern TOKEN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

    private ConfiguredHeaderParser() {
    }

    public static List<ConfiguredHeader> parse(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        String[] lines = text.split("\\R", -1);
        List<ConfiguredHeader> headers = new ArrayList<>();
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index];
            if (line.isBlank()) {
                continue;
            }
            int separator = line.indexOf(':');
            if (separator <= 0) {
                throw invalid(index, "expected Name: value");
            }
            String name = line.substring(0, separator).trim();
            String value = line.substring(separator + 1);
            if (value.startsWith(" ")) {
                value = value.substring(1);
            }
            if (!TOKEN.matcher(name).matches()) {
                throw invalid(index, "invalid HTTP header name");
            }
            if (containsInvalidValueCharacter(value)) {
                throw invalid(index, "header value contains a forbidden control character");
            }
            headers.add(new ConfiguredHeader(name, value));
        }
        return List.copyOf(headers);
    }

    public static String format(List<ConfiguredHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return "";
        }
        return headers.stream()
            .map(header -> header.name() + ": " + header.value())
            .collect(java.util.stream.Collectors.joining(System.lineSeparator()));
    }

    private static boolean containsInvalidValueCharacter(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == 0 || character == '\r' || character == '\n'
                || (character < 0x20 && character != '\t') || character == 0x7f) {
                return true;
            }
        }
        return false;
    }

    private static IllegalArgumentException invalid(int zeroBasedLine, String reason) {
        return new IllegalArgumentException("Header line " + (zeroBasedLine + 1) + ": " + reason + ".");
    }
}
