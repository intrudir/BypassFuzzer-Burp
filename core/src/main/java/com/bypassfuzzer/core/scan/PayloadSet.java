package com.bypassfuzzer.core.scan;

public enum PayloadSet {
    HIGH_SIGNAL,
    ALL;

    public static PayloadSet parse(String value) {
        return value != null && (value.equalsIgnoreCase("all") || value.equalsIgnoreCase("all-payloads"))
            ? ALL : HIGH_SIGNAL;
    }
}
