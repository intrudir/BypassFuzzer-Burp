package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;

/** One physical attempt, including an optional reference to its separate fallback control. */
public record ScanEvent(String mode, String target, PlannedRequest planned, HttpResponseData response,
                        Throwable error, String signal, int retryAttempt, WildcardCalibration.Assessment calibration,
                        PlannedRequest fallbackControl, HttpResponseData fallbackResponse) {
    public ScanEvent(String mode, String target, PlannedRequest planned, HttpResponseData response,
                     Throwable error, String signal, int retryAttempt) {
        this(mode, target, planned, response, error, signal, retryAttempt, WildcardCalibration.Assessment.DISABLED, null, null);
    }
}
