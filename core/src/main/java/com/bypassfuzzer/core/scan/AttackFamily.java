package com.bypassfuzzer.core.scan;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

public enum AttackFamily {
    HEADER("header", "Header"), PATH("path", "Path"), VERB("verb", "Verb"),
    PARAM("param", "Param"), COOKIE("cookie", "Cookie"),
    TRAILING_DOT("trailingdot", "TrailingDot"), TRAILING_SLASH("trailingslash", "TrailingSlash"),
    EXTENSION("extension", "Extension"), CONTENT_TYPE("contenttype", "ContentType"),
    ENCODING("encoding", "Encoding"), PROTOCOL("protocol", "Protocol"), CASE("case", "Case");

    private final String id;
    private final String displayName;

    AttackFamily(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    public String id() { return id; }
    public String displayName() { return displayName; }

    public static AttackFamily parse(String value) {
        return Arrays.stream(values()).filter(family -> family.id.equalsIgnoreCase(value)
            || family.name().equalsIgnoreCase(value)).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown attack family: " + value));
    }

    public static Set<AttackFamily> parseCsv(String value) {
        if (value == null || value.isBlank()) return new LinkedHashSet<>(Arrays.asList(values()));
        Set<AttackFamily> selected = new LinkedHashSet<>();
        for (String token : value.split(",")) selected.add(parse(token.trim()));
        return selected;
    }
}
