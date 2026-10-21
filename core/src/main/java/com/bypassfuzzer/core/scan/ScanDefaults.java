package com.bypassfuzzer.core.scan;

/** Operational defaults from the Burp extension, shared by every entrypoint. */
public final class ScanDefaults {
    private ScanDefaults() { }
    public static final int CONCURRENCY = 1;
    public static final int SWEEP_CANDIDATES = 100;
    public static final int SWEEP_PROBES = 350;
    public static final int BYPASS_RETRIES = 3;
    public static final int SWEEP_RETRIES = 3;
    public static final int IDOR_RETRIES = 1;
    public static final int URL_VALIDATION_RETRIES = 0;
    public static int retries(String mode) {
        return switch (mode) {
            case "bypass" -> BYPASS_RETRIES;
            case "sweep" -> SWEEP_RETRIES;
            case "idor" -> IDOR_RETRIES;
            case "url-validation" -> URL_VALIDATION_RETRIES;
            default -> throw new IllegalArgumentException("Unknown mode: " + mode);
        };
    }
}
