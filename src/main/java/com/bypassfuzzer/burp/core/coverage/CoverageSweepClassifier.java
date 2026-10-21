package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.scan.SweepClassifier;

/** Montoya boundary for Burp's shared Sweep classification rules. */
public final class CoverageSweepClassifier {
    public static final String LIKELY_PUBLIC_PREFIX = SweepClassifier.LIKELY_PUBLIC_PREFIX;
    public static final String LIKELY_UNAUTHENTICATED_BYPASS_PREFIX = SweepClassifier.LIKELY_UNAUTHENTICATED_BYPASS_PREFIX;
    public static final String BYPASS_PREFIX = SweepClassifier.BYPASS_PREFIX;
    private static SweepClassifier.Baseline baseline(CoverageSweepCandidate c) {
        return c == null ? null : new SweepClassifier.Baseline(c.statusCode(), c.contentLength(), c.contentType());
    }
    public static SweepClassifier.Response toCore(HttpResponse response) {
        if (response == null) return null;
        String type = response.headers().stream().filter(h -> h.name().equalsIgnoreCase("Content-Type"))
            .map(h -> h.value()).findFirst().orElse("");
        return new SweepClassifier.Response(response.statusCode(), response.body() == null ? 0 : response.body().length(), type);
    }
    public static boolean isInteresting(CoverageSweepCandidate c, HttpResponse control, HttpResponse probe) {
        return SweepClassifier.isInteresting(baseline(c), toCore(control), toCore(probe));
    }
    public static String signal(CoverageSweepCandidate c, HttpResponse control, HttpResponse probe) {
        return SweepClassifier.signal(baseline(c), toCore(control), toCore(probe));
    }
    public static String unauthenticatedControlSignal(CoverageSweepCandidate c, HttpResponse anonymous) {
        return SweepClassifier.unauthenticatedControlSignal(baseline(c), toCore(anonymous));
    }
    public static String unauthenticatedMutationSignal(HttpResponse anonymous, HttpResponse probe) {
        return SweepClassifier.unauthenticatedMutationSignal(toCore(anonymous), toCore(probe));
    }
    public static String authenticatedBypassSignal(CoverageSweepCandidate c, HttpResponse anonymous, HttpResponse probe) {
        return SweepClassifier.authenticatedBypassSignal(baseline(c), toCore(anonymous), toCore(probe));
    }
}
