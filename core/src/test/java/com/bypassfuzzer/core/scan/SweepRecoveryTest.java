package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SweepRecoveryTest {
    private static HttpRequestData seed(HttpProtocol protocol) {
        return new RawHttpRequestParser().parse("GET /private HTTP/1.1\r\nHost: example.test\r\nAuthorization: fixture\r\n\r\n".getBytes(),
            TargetOrigin.parse("https://example.test")).withProtocol(protocol);
    }
    private static HttpResponseData response(int status) {
        return new HttpResponseData(HttpProtocol.HTTP_1, status, List.of(new HttpHeader("Content-Type", "text/plain")), "ok".getBytes(), 0);
    }
    private static RequestHeaderPolicy<HttpRequestData> policy() {
        return new RequestHeaderPolicy<>(RequestAccess.CORE, List.of(), UserAgentMode.DISABLED, 0);
    }
    private static SweepWorkflow.Observer<HttpRequestData, HttpResponseData> observer(List<SweepWorkflow.Result<HttpRequestData, HttpResponseData>> output) {
        return new SweepWorkflow.Observer<>() {
            public void planned(int count) { }
            public void completed() { }
            public void skippedPublic() { fail("A blocked anonymous control must not skip this candidate"); }
            public void result(SweepWorkflow.Result<HttpRequestData, HttpResponseData> result) { output.add(result); }
        };
    }

    @Test void anonymousVerificationStaysInTheSelectedProtocolPass() {
        for (var protocol : List.of(HttpProtocol.HTTP_1, HttpProtocol.HTTP_2, HttpProtocol.HTTP_1_0, HttpProtocol.AUTO)) {
            var seed = seed(protocol);
            var events = new ArrayList<SweepWorkflow.Result<HttpRequestData, HttpResponseData>>();
            var workflow = new SweepWorkflow<HttpRequestData, HttpResponseData>(RequestAccess.CORE, SweepClassifier::response);
            workflow.execute(new SweepWorkflow.Candidate<>(seed, response(200), "owned", new SweepClassifier.Baseline(200, 2, "text/plain"), protocol),
                new SweepWorkflow.Options(true, true, true, Set.of("Authorization"), Set.of(), false, Set.of(429)), policy(),
                () -> List.of(new SweepWorkflow.Probe<>("mutation", "Path", seed.removeHeader("Authorization").withRawTarget("/mutation"), protocol)),
                probe -> {
                    assertEquals(protocol, probe.protocol()); assertEquals(protocol, probe.request().protocol());
                    assertTrue(probe.request().firstHeader("Authorization").isEmpty());
                    return response(probe.controlRole() == ControlRole.TARGET ? 403 : 200);
                }, () -> true, observer(events));
            assertEquals(2, events.size());
            assertTrue(events.get(1).signal().startsWith(SweepClassifier.BYPASS_PREFIX));
        }
    }

    @Test void retriesUseTheRetainedComparisonsAndRefreshSignalsAndCalibration() {
        for (boolean authenticated : List.of(false, true)) {
            var seed = seed(HttpProtocol.HTTP_1); var captured = response(authenticated ? 200 : 401);
            var events = new ArrayList<SweepWorkflow.Result<HttpRequestData, HttpResponseData>>();
            var workflow = new SweepWorkflow<HttpRequestData, HttpResponseData>(RequestAccess.CORE, SweepClassifier::response);
            workflow.execute(new SweepWorkflow.Candidate<>(seed, captured, "owned", new SweepClassifier.Baseline(captured.statusCode(), 2, "text/plain"), HttpProtocol.HTTP_1),
                new SweepWorkflow.Options(authenticated, authenticated, true, Set.of("Authorization"), Set.of(), true, Set.of(429)), policy(),
                () -> {
                    var plan = new ArrayList<SweepWorkflow.Probe<HttpRequestData>>();
                    if (!authenticated) plan.add(new SweepWorkflow.Probe<>("Original", "Control", seed, HttpProtocol.HTTP_1));
                    plan.add(new SweepWorkflow.Probe<>("mutation", "Path", seed.withRawTarget("/mutation"), HttpProtocol.HTTP_1)); return plan;
                }, probe -> response(probe.controlRole() == ControlRole.WILDCARD ? 200 : probe.controlRole() == ControlRole.NONE ? 429 : 403),
                () -> true, observer(events));
            var original = events.get(events.size() - 1);
            assertEquals(WildcardCalibration.Assessment.UNAVAILABLE, original.calibration());
            assertEquals("", original.signal());
            var recovered = workflow.retry(original, response(200));
            assertEquals(authenticated ? "BYPASS?: authenticated 200 -> anonymous 403 -> probe 200" : "403 -> 200", recovered.signal());
            assertEquals(WildcardCalibration.Assessment.MATCH, recovered.calibration());
            assertTrue(recovered.context().isFinding(ControlRole.NONE, SweepClassifier.response(recovered.response())));
            assertSame(original.originalResponse(), recovered.originalResponse());
            assertSame(original.fallbackRequest(), recovered.fallbackRequest());
            assertSame(original.context(), recovered.context());
            assertEquals("No response", workflow.retry(original, null).signal());
            assertEquals(WildcardCalibration.Assessment.UNAVAILABLE, workflow.retry(original, null).calibration());
        }
    }

    @Test void recoveredCalibrationRemainsAControlRatherThanAFinding() {
        var context = new SweepClassifier.Context(false, new SweepClassifier.Baseline(403, 2, "text/plain"),
            SweepClassifier.response(response(403)), null, Set.of(429));
        assertEquals("Calibration unavailable", context.signal(ControlRole.WILDCARD, SweepClassifier.response(response(429))));
        assertEquals("Calibration control", context.signal(ControlRole.WILDCARD, SweepClassifier.response(response(200))));
        assertFalse(context.isFinding(ControlRole.WILDCARD, SweepClassifier.response(response(200))));
    }
}
