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
    public record Candidate<Q, S>(Q request, S originalResponse, String target, SweepClassifier.Baseline baseline,
                                  HttpProtocol protocol) { }
    public record Probe<Q>(String label, String family, Q request, HttpProtocol protocol, String playbookId, ControlRole controlRole) {
        public Probe(String label, String family, Q request, HttpProtocol protocol) {
            this(label, family, request, protocol, "", family.equals("Control") ? ControlRole.ORIGINAL :
                family.equals("Unauthenticated Control") ? ControlRole.TARGET : ControlRole.NONE);
        }
    }
    public record Result<Q, S>(String attackType, Probe<Q> probe, String target, String signal, S response,
                               Q originalRequest, S originalResponse, Q verificationRequest, S verificationResponse,
                               WildcardCalibration.Assessment calibration, Q fallbackRequest, S fallbackResponse,
                               SweepClassifier.Context context) { }
    public interface Observer<Q, S> {
        void planned(int count);
        void completed();
        void skippedPublic();
        void result(Result<Q, S> result);
    }
    /** Per-seed work retained across configuration generations, without retaining mutation bodies. */
    public static final class Memory<Q,S> {
        private record Control<Q,S>(Probe<Q> probe, S response) { }
        private final java.util.Map<String,Control<Q,S>> controls = new java.util.HashMap<>();
        private final java.util.Set<String> completed = new java.util.HashSet<>();
        private final java.util.Map<String,Result<Q,S>> latest = new java.util.HashMap<>();
        private long context;
        private boolean fresh;
        public void context(long value) { context=value; }
        private String key(Probe<Q> probe) { return probe.protocol()+"\n"+probe.controlRole()+"\n"+probe.playbookId()+"\n"+probe.family()+"\n"+probe.label(); }
        private String controlKey(Probe<Q> probe) { return context+"\n"+probe.protocol()+"\n"+probe.controlRole()+"\n"+probe.family(); }
        public boolean completed(Probe<Q> probe) { return probe.controlRole()==ControlRole.NONE && completed.contains(key(probe)); }
        private boolean needed(Probe<Q> probe) { return probe.controlRole()==ControlRole.NONE ? !completed(probe) : !controls.containsKey(controlKey(probe)); }
        private Probe<Q> stable(Probe<Q> probe) {
            var cached=controls.get(controlKey(probe));
            return probe.controlRole()!=ControlRole.NONE && cached!=null ? cached.probe() : probe;
        }
        private S send(Probe<Q> probe, Function<Probe<Q>,S> sender, Observer<Q,S> observer) {
            var cached=probe.controlRole()==ControlRole.NONE ? null : controls.get(controlKey(probe));
            fresh=cached==null;
            if (!fresh) return cached.response();
            S response=sender.apply(probe);
            if (probe.controlRole()==ControlRole.NONE) completed.add(key(probe));
            else controls.put(controlKey(probe),new Control<>(probe,response));
            observer.completed(); return response;
        }
        private void emit(Result<Q,S> value, Observer<Q,S> observer) {
            latest.put(key(value.probe()),new Result<>(value.attackType(),value.probe(),value.target(),value.signal(),null,
                value.originalRequest(),value.originalResponse(),value.verificationRequest(),value.verificationResponse(),value.calibration(),value.fallbackRequest(),value.fallbackResponse(),value.context()));
            if (fresh) observer.result(value);
        }
        public Result<Q,S> latest(Probe<Q> probe) { return latest.get(key(probe)); }
        public Result<Q,S> refresh(Result<Q,S> previous) { return latest.getOrDefault(key(previous.probe()),previous); }
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
        execute(candidate,options,policy,probes,send,continuing,observer,new Memory<>());
    }

    public void execute(Candidate<Q,S> candidate, Options options, RequestHeaderPolicy<Q> policy,
        Supplier<java.util.List<Probe<Q>>> probes, Function<Probe<Q>,S> send,
        BooleanSupplier continuing, Observer<Q,S> observer, Memory<Q,S> memory) {
        S control = null, anonymous = null;
        Q verification = null;
        if (options.authenticated() && options.verifyUnauthenticated()) {
            Q stripped = stripAuthentication(candidate.request(), options.authHeaders(), options.authCookies());
            verification = policy.withoutAuthentication(options.authHeaders(), options.authCookies())
                .reconcileMutation(stripped, stripped);
            var probe = memory.stable(new Probe<>("Original request without authentication", "Unauthenticated Control", verification, candidate.protocol()));
            verification=probe.request();
            if(memory.needed(probe)) observer.planned(1);
            anonymous = memory.send(probe,send,observer);
            String signal = anonymous == null ? "No response" :
                SweepClassifier.unauthenticatedControlSignal(candidate.baseline(), responses.apply(anonymous));
            boolean skip = options.skipPublic() && signal.startsWith(SweepClassifier.LIKELY_PUBLIC_PREFIX);
            if (skip) observer.skippedPublic();
            memory.emit(result(candidate, options, probe, anonymous, control, verification, anonymous, null, null),observer);
            if (skip) return;
        }
        if (!continuing.getAsBoolean()) return;
        var planned = probes.get();
        observer.planned((int)planned.stream().filter(memory::needed).count());
        // Establish the original baseline before sending calibration traffic.
        for (var probe : planned) {
            if (probe.controlRole() != ControlRole.ORIGINAL) continue;
            if (!continuing.getAsBoolean()) return;
            var stable = memory.stable(probe);
            S response = memory.send(stable,send,observer); control = response;
            memory.emit(result(candidate, options, stable, response, control, verification, anonymous, null, null),observer);
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
                var probe = memory.stable(new Probe<>(WildcardCalibration.controlLabel(protocol), "Calibration", request, protocol, "", ControlRole.WILDCARD));
                request=probe.request();
                if(memory.needed(probe)) observer.planned(1);
                S response = memory.send(probe,send,observer);
                fallbackRequests.put(protocol, request);
                if (response != null) fallbackResponses.put(protocol, response);
                memory.emit(result(candidate, options, probe, response, control, verification, anonymous, null, null),observer);
            }
        }
        for (var probe : planned) {
            if (probe.controlRole() == ControlRole.ORIGINAL) continue;
            if (!continuing.getAsBoolean()) return;
            if(memory.completed(probe)) {
                memory.latest.put(memory.key(probe),result(candidate,options,probe,null,control,verification,anonymous,
                    fallbackRequests.get(probe.protocol()),fallbackResponses.get(probe.protocol())));
                continue;
            }
            S response = memory.send(probe,send,observer);
            if (probe.family().equals("Control")) control = response;
            memory.emit(result(candidate, options, probe, response, control, verification, anonymous,
                fallbackRequests.get(probe.protocol()), fallbackResponses.get(probe.protocol())),observer);
        }
    }

    private Result<Q, S> result(Candidate<Q, S> candidate, Options options, Probe<Q> probe, S response,
                                 S control, Q verification, S anonymous, Q fallback, S fallbackResponse) {
        var context = new SweepClassifier.Context(options.authenticated(), candidate.baseline(),
            converted(control), converted(anonymous), options.throttleCodes());
        return new Result<>(options.authenticated() ? "Authenticated Coverage Sweep" : "Coverage Sweep",
            probe, candidate.target(), context.signal(probe.controlRole(), converted(response)), response,
            candidate.request(), candidate.originalResponse() == null ? control : candidate.originalResponse(),
            verification, anonymous, assessment(probe, response, fallback, fallbackResponse, context), fallback, fallbackResponse, context);
    }

    public Result<Q, S> retry(Result<Q, S> original, S response) {
        var context = original.context();
        return new Result<>(original.attackType(), original.probe(), original.target(),
            context.signal(original.probe().controlRole(), converted(response)), response, original.originalRequest(),
            original.originalResponse(), original.verificationRequest(), original.verificationResponse(),
            assessment(original.probe(), response, original.fallbackRequest(), original.fallbackResponse(), context),
            original.fallbackRequest(), original.fallbackResponse(), context);
    }

    private WildcardCalibration.Assessment assessment(Probe<Q> probe, S response, Q fallback, S fallbackResponse,
                                                     SweepClassifier.Context context) {
        return probe.controlRole() != ControlRole.NONE || fallback == null ? WildcardCalibration.Assessment.DISABLED
            : WildcardCalibration.compare(access.method(probe.request()), converted(fallbackResponse), converted(response), context.throttleCodes());
    }

    private SweepClassifier.Response converted(S value) { return value == null ? null : responses.apply(value); }
}
