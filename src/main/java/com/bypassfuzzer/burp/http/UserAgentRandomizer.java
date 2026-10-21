package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.UserAgentMode;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.core.http.*;
import java.util.List;

/** Montoya boundary for the shared User-Agent implementation. */
final class UserAgentRandomizer {
    static HttpRequest reconcile(HttpRequest baseline, HttpRequest request, UserAgentMode mode, long seed) {
        return new RequestHeaderPolicy<>(MontoyaRequestAccess.INSTANCE, List.of(), mode, seed)
            .reconcileMutation(baseline, request);
    }
    static String valueFor(UserAgentMode mode, long seed, HttpRequest request) {
        if (mode == null || mode == UserAgentMode.DISABLED)
            return request == null ? "" : java.util.Objects.toString(request.headerValue("User-Agent"), "");
        return UserAgentVariants.valueFor(mode, seed, request.method(), request.url(),
            MontoyaRequestAccess.INSTANCE.headers(request), request.bodyToString());
    }
}
