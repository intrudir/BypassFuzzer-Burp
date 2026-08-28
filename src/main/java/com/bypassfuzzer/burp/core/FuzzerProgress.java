package com.bypassfuzzer.burp.core;

/** Immutable Bypass run telemetry shown in the session and Dashboard. */
public record FuzzerProgress(
    int plannedPayloads,
    long httpRequestsSent,
    long resultsRecorded,
    int automaticRetriesPending,
    long automaticRetriesRejected
) {
    public static FuzzerProgress empty() {
        return new FuzzerProgress(0, 0, 0, 0, 0);
    }
}
