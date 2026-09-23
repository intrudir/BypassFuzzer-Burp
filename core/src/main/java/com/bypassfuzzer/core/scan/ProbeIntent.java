package com.bypassfuzzer.core.scan;

/** The authorization question a planned request asks. */
public enum ProbeIntent {
    STANDARD,
    MASS_ASSIGNMENT,
    PATH_BODY_CONFLICT
}
