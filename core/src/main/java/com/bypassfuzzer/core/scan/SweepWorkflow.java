package com.bypassfuzzer.core.scan;
import com.bypassfuzzer.core.http.CookieHeaderUtils;

import com.bypassfuzzer.core.http.*;
import java.util.Set;
import java.util.function.*;

/** The Burp master's per-candidate Sweep state machine, independent of message transport. */
public final class SweepWorkflow<Q, S> {
    public record Options(boolean authenticated, boolean verifyUnauthenticated, boolean skipPublic,
                          Set<String> authHeaders, Set<String> authCookies) { }
    public record Candidate<Q, S>(Q request, S originalResponse, String target, SweepClassifier.Baseline baseline) { }
    public record Probe<Q>(String label, String family, Q request, HttpProtocol protocol) { }
    public record Result<Q, S>(String attackType, Probe<Q> probe, String target, String signal, S response,
                               Q originalRequest, S originalResponse, Q verificationRequest, S verificationResponse) { }
    public interface Observer<Q, S> {
        void planned(int count);
        void completed();
        void skippedPublic();
        void result(Result<Q, S> result);
    }
    private final RequestAccess<Q> access;
    private final Function<S, SweepClassifier.Response> responses;
    public SweepWorkflow(RequestAccess<Q> access, Function<S, SweepClassifier.Response> responses) {
        this.access = access;
        this.responses = responses;
    }

    public Q stripAuthentication(Q request, Set<String> headers, Set<String> cookies) {
        Q stripped = access.removeHeader(access.removeHeader(request, "Authorization"), "Proxy-Authorization");
        if (headers != null) for (String name : headers)
            if (name != null && !name.isBlank()) stripped = access.removeHeader(stripped, name.trim());
        String cookie = access.headers(stripped).stream().filter(h -> h.name().equalsIgnoreCase("Cookie"))
            .map(HttpHeader::value).findFirst().orElse(null);
        if (cookie != null) {
            stripped = access.removeHeader(stripped, "Cookie");
            String retained = CookieHeaderUtils.removeCookies(cookie, cookies);
            if (retained != null && !retained.isBlank()) stripped = access.addHeader(stripped, "Cookie", retained);
        }
        return stripped;
    }

    public void execute(Candidate<Q, S> candidate, Options options, RequestHeaderPolicy<Q> policy,
        Supplier<java.util.List<Probe<Q>>> probes, Function<Probe<Q>, S> send,
        BooleanSupplier continuing, Observer<Q, S> observer) {
        S control = null, anonymous = null;
        Q verification = null;
        if (options.authenticated() && options.verifyUnauthenticated()) {
            Q stripped = stripAuthentication(candidate.request(), options.authHeaders(), options.authCookies());
            verification = policy.withoutAuthentication(options.authHeaders(), options.authCookies())
                .reconcileMutation(stripped, stripped);
            var probe = new Probe<>("Original request without authentication", "Unauthenticated Control", verification, HttpProtocol.AUTO);
            observer.planned(1);
            anonymous = send.apply(probe);
            observer.completed();
            String signal = anonymous == null ? "No response" :
                SweepClassifier.unauthenticatedControlSignal(candidate.baseline(), responses.apply(anonymous));
            boolean skip = options.skipPublic() && signal.startsWith(SweepClassifier.LIKELY_PUBLIC_PREFIX);
            if (skip) observer.skippedPublic();
            observer.result(new Result<>("Authenticated Coverage Sweep", probe, candidate.target(), signal, anonymous,
                candidate.request(), candidate.originalResponse(), verification, anonymous));
            if (skip) return;
        }
        if (!continuing.getAsBoolean()) return;
        var planned = probes.get();
        observer.planned(planned.size());
        for (var probe : planned) {
            if (!continuing.getAsBoolean()) return;
            S response = send.apply(probe);
            observer.completed();
            if (probe.family().equals("Control")) control = response;
            String signal = "";
            if (response == null) signal = "No response";
            else if (options.authenticated()) {
                if (options.verifyUnauthenticated()) {
                    signal = SweepClassifier.authenticatedBypassSignal(candidate.baseline(), converted(anonymous), converted(response));
                    if (signal.isBlank()) signal = SweepClassifier.unauthenticatedMutationSignal(converted(anonymous), converted(response));
                }
            } else if (!probe.family().equals("Control")) {
                signal = SweepClassifier.signal(candidate.baseline(), converted(control), converted(response));
            }
            observer.result(new Result<>(options.authenticated() ? "Authenticated Coverage Sweep" : "Coverage Sweep",
                probe, candidate.target(), signal, response, candidate.request(),
                candidate.originalResponse() == null ? control : candidate.originalResponse(), verification, anonymous));
        }
    }

    private SweepClassifier.Response converted(S value) { return value == null ? null : responses.apply(value); }
}
