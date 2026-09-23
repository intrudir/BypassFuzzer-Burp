package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpResponseData;

/** One physical attempt; consumers persist evidence before returning. */
public record ScanEvent(String mode, String target, PlannedRequest planned, HttpResponseData response,
                        Throwable error, String signal, int retryAttempt) { }
