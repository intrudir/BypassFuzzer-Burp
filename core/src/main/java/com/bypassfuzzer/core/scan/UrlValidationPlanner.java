package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.urlvalidation.UrlValidationCandidate;
import com.bypassfuzzer.core.urlvalidation.UrlValidationOptions;
import com.bypassfuzzer.core.urlvalidation.UrlValidationPayload;
import com.bypassfuzzer.core.urlvalidation.UrlValidationPayloadGenerator;

import java.util.ArrayList;
import java.util.List;

public final class UrlValidationPlanner {
    private final UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();

    public List<PlannedRequest> plan(HttpRequestData request, UrlValidationOptions options, int maximum) {
        String marker = options.normalizedMarkerText();
        int count = RequestRewriter.count(request, marker);
        if (count == 0) throw new IllegalArgumentException("Marker " + marker + " was not found in the request");
        if (options.normalizedAttackerHost().isBlank()) throw new IllegalArgumentException("Attacker host is required");
        UrlValidationCandidate candidate = new UrlValidationCandidate(marker, marker, "marker");
        List<PlannedRequest> output = new ArrayList<>();
        output.add(PlannedRequest.baseline(request, "url-validation.baseline"));
        for (UrlValidationPayload payload : generator.generate(candidate, options)) {
            try {
                output.add(new PlannedRequest(payload.family().displayName(), payload.describe(marker),
                    payload.encoding().label(), RequestRewriter.replace(request, marker, payload.value()), false));
            } catch (IllegalArgumentException unsafeWireValue) {
                // A raw payload containing CR/LF cannot be represented safely at this transport boundary.
                // Its encoded variants remain available when the corresponding encoding is selected.
                continue;
            }
            if (output.size() >= Math.max(1, maximum)) break;
        }
        return List.copyOf(output);
    }
}
