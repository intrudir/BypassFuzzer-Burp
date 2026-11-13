package com.bypassfuzzer.core.scan;
import com.bypassfuzzer.core.http.CookieHeaderUtils;

import com.bypassfuzzer.core.http.*;
import java.util.Set;
import java.util.function.*;

/** The Burp master's per-candidate Sweep state machine, independent of message transport. */
public final class SweepWorkflow<Q, S> {
    public record Options(boolean authenticated, boolean verifyUnauthenticated, boolean skipPublic,
                          Set<String> authHeaders, Set<String> authCookies, boolean wildcardCalibration, Set<Integer> throttleCodes) {
        public Options(boolean authenticated, boolean verifyUnauthenticated, boolean skipPublic, Set<String> authHeaders, Set<String> authCookies) {
            this(authenticated, verifyUnauthenticated, skipPublic, authHeaders, authCookies, true, Set.of(429, 503));
        }
    }
    public record Candidate<Q, S>(Q request, S originalResponse, String target, SweepClassifier.Baseline baseline) { }
    public record Probe<Q>(String label, String family, Q request, HttpProtocol protocol, String playbookId, ControlRole controlRole) {
        public Probe(String label, String family, Q request, HttpProtocol protocol) {
            this(label, family, request, protocol, "", family.equals("Control") ? ControlRole.ORIGINAL :
                family.equals("Unauthenticated Control") ? ControlRole.TARGET : ControlRole.NONE);
        }
    }
    public record Result<Q, S>(String attackType, Probe<Q> probe, String target, String signal, S response,
                               Q originalRequest, S originalResponse, Q verificationRequest, S verificationResponse,
                               WildcardCalibration.Assessment calibration, Q fallbackRequest, S fallbackResponse) {
        public Result(String attackType, Probe<Q> probe, String target, String signal, S response,
                      Q originalRequest, S originalResponse, Q verificationRequest, S verificationResponse) {
            this(attackType, probe, target, signal, response, originalRequest, originalResponse, verificationRequest, verificationResponse,
                 WildcardCalibration.Assessment.DISABLED, null, null);
        }
    }
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
        // Establish the original baseline before sending calibration traffic.
        for (var probe : planned) {
            if (probe.controlRole() != ControlRole.ORIGINAL) continue;
            if (!continuing.getAsBoolean()) return;
            S response = send.apply(probe); observer.completed(); control = response;
            observer.result(new Result<>(options.authenticated() ? "Authenticated Coverage Sweep" : "Coverage Sweep",
                probe,candidate.target(),response == null ? "No response" : "",response,candidate.request(),
                candidate.originalResponse() == null ? response : candidate.originalResponse(),verification,anonymous));
        }
        var fallbackRequests = new java.util.EnumMap<HttpProtocol, Q>(HttpProtocol.class);
        var fallbackResponses = new java.util.EnumMap<HttpProtocol, S>(HttpProtocol.class);
        if (options.wildcardCalibration() && WildcardCalibration.eligible(access.method(candidate.request()))) {
            Q seed = options.authenticated() ? stripAuthentication(candidate.request(), options.authHeaders(), options.authCookies()) : candidate.request();
            var calibrationPolicy = options.authenticated() ? policy.withoutAuthentication(options.authHeaders(), options.authCookies()) : policy;
            var protocols = new java.util.LinkedHashSet<HttpProtocol>();
            planned.stream().filter(p -> p.controlRole() == ControlRole.NONE).forEach(p -> protocols.add(p.protocol()));
            for (var protocol : protocols) {
                if (!continuing.getAsBoolean()) return;
                Q request = access.withProtocol(calibrationPolicy.reconcileMutation(seed, WildcardCalibration.control(seed, access)), protocol);
                var probe = new Probe<>(WildcardCalibration.controlLabel(protocol), "Calibration", request, protocol, "", ControlRole.WILDCARD);
                observer.planned(1);
                S response = send.apply(probe);
                observer.completed();
                fallbackRequests.put(protocol, request);
                if (response != null) fallbackResponses.put(protocol, response);
                String signal = response == null || options.throttleCodes().contains(responses.apply(response).statusCode())
                    ? "Calibration unavailable" : "Calibration control";
                observer.result(new Result<>(options.authenticated() ? "Authenticated Coverage Sweep" : "Coverage Sweep",
                    probe, candidate.target(), signal, response, candidate.request(), candidate.originalResponse(), verification, anonymous));
            }
        }
        for (var probe : planned) {
            if (probe.controlRole() == ControlRole.ORIGINAL) continue;
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
                candidate.originalResponse() == null ? control : candidate.originalResponse(), verification, anonymous,
                probe.controlRole() != ControlRole.NONE || !fallbackRequests.containsKey(probe.protocol()) ? WildcardCalibration.Assessment.DISABLED :
                    WildcardCalibration.compare(access.method(probe.request()), converted(fallbackResponses.get(probe.protocol())), converted(response), options.throttleCodes()),
                fallbackRequests.get(probe.protocol()), fallbackResponses.get(probe.protocol())));
        }
    }

    private SweepClassifier.Response converted(S value) { return value == null ? null : responses.apply(value); }
}
