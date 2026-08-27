package com.bypassfuzzer.core.payloads;

import java.util.List;

/** Standalone path-segment markers used for parser-normalization probes. */
public final class StandalonePathMarkerVariants {

    private static final List<String> ALL = List.of(
        ".",
        "%2e",
        "%2E",
        "%252e",
        "%252E",
        "%u002e",
        "%U002E",
        ";",
        "%3b",
        "%3B",
        "%253b",
        "%253B",
        "%u003b",
        "%U003B"
    );

    private StandalonePathMarkerVariants() {
    }

    public static List<String> all() {
        return ALL;
    }
}
