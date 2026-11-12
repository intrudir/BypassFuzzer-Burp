package com.bypassfuzzer.core.scan;

import java.util.List;
import java.util.Set;

/** Immutable selection and run controls shared by both hosts. Null selection means catalog defaults. */
public record PlaybookOptions(Set<String> selected, List<String> apiPrefixes,
                              boolean wildcardCalibration, boolean includeStateChanging) {
    public PlaybookOptions {
        selected = selected == null ? null : Set.copyOf(selected);
        apiPrefixes = apiPrefixes == null ? List.of() : List.copyOf(apiPrefixes);
        for (String prefix : apiPrefixes)
            if (prefix == null || !prefix.startsWith("/") || prefix.startsWith("//")
                || prefix.contains("?") || prefix.contains("#") || prefix.chars().anyMatch(Character::isWhitespace))
                throw new IllegalArgumentException("API prefixes must be absolute paths without query, fragment or whitespace");
    }
    public static PlaybookOptions defaults() { return new PlaybookOptions(null, List.of(), true, false); }
    public PlaybookOptions withSelection(Set<String> value) { return new PlaybookOptions(value, apiPrefixes, wildcardCalibration, includeStateChanging); }
}
