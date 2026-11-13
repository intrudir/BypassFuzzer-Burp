package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionResultsWorkspaceTest {
    @Test void editableManualRetryDrainsThenExcludesAllRemainingRequests() throws Exception {
        var sender=new BlockingFirstSender(response(200));var workspace=workspace(sender);
        var config=new com.bypassfuzzer.core.scan.RunConfiguration(Set.of(),1,1,400,Set.of(),List.of(),Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0);
        var primary=new com.bypassfuzzer.core.scan.LiveRun(config,java.util.Map.of());workspace.attachRunControl(() -> primary);
        workspace.addResult(new AttackResult("Bypass","first",request("/one","","GET",null,""),response(429)));
        workspace.addResult(new AttackResult("Bypass","second",request("/two","","GET",null,""),response(429)));
        workspace.retryThrottled(false);assertTrue(sender.firstStarted.await(3,TimeUnit.SECONDS));workspace.pauseThrottleRetry();
        var run=workspace.editableRun();assertEquals(com.bypassfuzzer.core.scan.LiveRun.State.PAUSING,run.snapshot().state());sender.releaseFirst.countDown();
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);while(run.snapshot().state()!=com.bypassfuzzer.core.scan.LiveRun.State.PAUSED && System.nanoTime()<end)Thread.sleep(10);
        assertEquals(com.bypassfuzzer.core.scan.LiveRun.State.PAUSED,run.snapshot().state());
        run.apply(new com.bypassfuzzer.core.scan.RunConfiguration(Set.of("example.com"),1,1,20,Set.of(),List.of(new com.bypassfuzzer.core.http.ConfiguredHeader("User-Agent","edited")),Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0));
        workspace.resumeThrottleRetry();waitForRetry(workspace);assertEquals(1,sender.sendCount.get());assertEquals(0,workspace.throttledRetryCount());workspace.cleanup();
    }

    @Test void manualSweepRetryRefreshesSignalAndFallbackAnnotation() throws Exception {
        var sender = new SequenceSender(response(403), response(200));
        var workspace = workspace(sender);
        var original = request("/original", "", "GET", null, "");
        var probe = request("/mutation", "", "GET", null, "");
        var fallback = request("/__bf_control_fixture", "", "GET", null, "");
        var fallbackResponse = response(200);
        var context = new com.bypassfuzzer.core.scan.SweepClassifier.Context(false,
            new com.bypassfuzzer.core.scan.SweepClassifier.Baseline(403, 0, "text/plain"),
            new com.bypassfuzzer.core.scan.SweepClassifier.Response(403, 0, "text/plain"), null, Set.of(429));
        var failed = new AttackResult("Coverage Sweep", "probe", "target", "Path", "", probe, response(429), original, response(403))
            .withEvidenceMetadata(new AttackResult.EvidenceMetadata("bypass.path.base", com.bypassfuzzer.core.scan.ControlRole.NONE,
                com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.UNAVAILABLE, fallback, fallbackResponse, context));
        workspace.addResult(failed);
        workspace.retryThrottled(false); waitForRetry(workspace);
        var retried = workspace.allResults().get(1);
        assertEquals(200, retried.getStatusCode());
        assertEquals("403 -> 200", retried.getSignal());
        assertEquals("Possible fallback", retried.getEvidenceMetadata().annotation());
        assertEquals(0, workspace.throttledRetryCount());
        assertEquals(failed.getOriginalResponse(), retried.getOriginalResponse());
        assertEquals(fallbackResponse, retried.getEvidenceMetadata().fallbackResponse());
        workspace.cleanup();
    }


    @Test
    void calibrationVisibilityPreservesBaselinesFallbackEvidenceAndFailedControls() throws Exception {
        SessionResultsWorkspace workspace = workspace(new SequenceSender(response(200)));
        var request = request("/api-docs/control", "", "GET", null, "");
        var empty404 = response(404);
        when(empty404.headers()).thenReturn(List.of());
        var metadata = new AttackResult.EvidenceMetadata("", com.bypassfuzzer.core.scan.ControlRole.WILDCARD,
            com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.DISABLED, null, null);
        AttackResult control = new AttackResult("Calibration", "control", request, empty404).withEvidenceMetadata(metadata);
        AttackResult unavailable = new AttackResult("Calibration", "failed control", request, null).withEvidenceMetadata(metadata);
        workspace.addResult(control); workspace.addResult(unavailable);
        for (var role : List.of(com.bypassfuzzer.core.scan.ControlRole.ORIGINAL,
            com.bypassfuzzer.core.scan.ControlRole.AUTHORIZED, com.bypassfuzzer.core.scan.ControlRole.TARGET)) {
            workspace.addResult(new AttackResult("Baseline", role.name(), request, empty404).withEvidenceMetadata(
                new AttackResult.EvidenceMetadata("", role, com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.DISABLED, null, null)));
        }
        AttackResult candidate = new AttackResult("Path", "candidate", request, empty404).withEvidenceMetadata(
            new AttackResult.EvidenceMetadata("bypass.path.base", com.bypassfuzzer.core.scan.ControlRole.NONE,
                com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.MATCH, request, empty404));
        workspace.addResult(candidate);
        Field field = SessionResultsWorkspace.class.getDeclaredField("showCalibrationRequests"); field.setAccessible(true);
        javax.swing.JCheckBox toggle = (javax.swing.JCheckBox) field.get(workspace);
        assertFalse(toggle.isSelected()); assertTrue(toggle.isVisible());
        assertEquals(4, workspace.shownResultsCount()); assertEquals(6, workspace.allResultsCount());
        assertTrue(workspace.visibleResultsAsTsv().contains("candidate"));
        assertFalse(workspace.visibleResultsAsTsv().contains("failed control"));
        assertEquals(1, workspace.throttledRetryCount(), "hidden unavailable evidence stays in the retry queue");
        SwingUtilities.invokeAndWait(toggle::doClick);
        assertEquals(6, workspace.shownResultsCount());
        assertTrue(workspace.visibleResultsAsTsv().contains("failed control"));
        SwingUtilities.invokeAndWait(toggle::doClick);
        assertEquals(4, workspace.shownResultsCount()); assertEquals(6, workspace.allResultsCount());
        assertTrue(workspace.allResults().contains(candidate));
        assertEquals(empty404, candidate.getEvidenceMetadata().fallbackResponse());
        assertEquals("Possible fallback", candidate.getEvidenceMetadata().annotation());
        workspace.cleanup();
    }

    @Test
    void sharedWorkspaceAlwaysExposesTheRetryQueueControl() throws Exception {
        SessionResultsWorkspace workspace = workspace(new SequenceSender(response(200)));
        Field field = SessionResultsWorkspace.class.getDeclaredField("retryQueueButton");
        field.setAccessible(true);
        javax.swing.JButton queue = (javax.swing.JButton) field.get(workspace);

        assertTrue(queue.isVisible());
        assertEquals("Retry queue (0)", queue.getText());
    }

    @Test
    void noResponseResultAppearsInVisibleRetryQueueAndClearsAfterSuccess() throws Exception {
        SequenceSender sender = new SequenceSender(response(200));
        SessionResultsWorkspace workspace = workspace(sender);
        HttpRequest request = request("/no-response", "", "GET", null, "");
        AttackResult failed = new AttackResult("Coverage Sweep", "probe", "target", "Path", "No response",
            request, null);

        workspace.addResult(failed);
        SwingUtilities.invokeAndWait(() -> { });

        assertEquals(1, workspace.throttledRetryCount());
        assertTrue(workspace.retryThrottledButton().getText().contains("(1)"));

        workspace.retryThrottled(false);
        waitForRetry(workspace);
        SwingUtilities.invokeAndWait(() -> { });

        assertEquals(1, sender.sendCount);
        assertEquals(1, workspace.retryRequestCount());
        assertEquals(0, workspace.throttledRetryCount());
        assertTrue(workspace.retryThrottledButton().getText().contains("(0)"));
    }

    @Test
    void successfulRetryLeavesAuditRowAndRemovesRequestFromQueue() throws Exception {
        SequenceSender sender = new SequenceSender(response(200));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        AttackResult throttled = new AttackResult("Header", "payload", request("/admin", "", "GET", null, ""),
            response(429));

        workspace.addResult(throttled);
        workspace.addResult(throttled);

        assertEquals(1, workspace.throttledRetryCount());
        workspace.retryThrottled(false);
        waitForRetry(workspace);

        assertEquals(0, workspace.throttledRetryCount());
        assertEquals(3, workspace.allResultsCount());
        AttackResult retry = workspace.allResults().get(2);
        assertEquals("payload", retry.getPayload());
        assertEquals(1, retry.getThrottleRetryAttempt());
        assertEquals(200, retry.getStatusCode());
    }

    @Test
    void requestThatRemainsThrottledStaysQueuedForAnotherPass() throws Exception {
        SequenceSender sender = new SequenceSender(response(429));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(new AttackResult("Path", "variant",
            request("/admin", "", "GET", null, ""), response(429)));

        workspace.retryThrottled(false);
        waitForRetry(workspace);

        assertEquals(1, workspace.throttledRetryCount());
        assertEquals(2, workspace.allResultsCount());
        assertEquals(1, workspace.allResults().get(1).getThrottleRetryAttempt());
        assertEquals(429, workspace.allResults().get(1).getStatusCode());
    }

    @Test
    void unsafeMethodsRemainQueuedUnlessExplicitlyIncluded() throws Exception {
        SequenceSender sender = new SequenceSender(response(200));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(new AttackResult("Header", "payload",
            request("/update", "", "POST", null, ""), response(429)));

        workspace.retryThrottled(false);

        assertFalse(workspace.isRetryRunning());
        assertEquals(1, workspace.throttledRetryCount());
        assertEquals(0, sender.sendCount);

        workspace.retryThrottled(true);
        waitForRetry(workspace);

        assertEquals(0, workspace.throttledRetryCount());
        assertEquals(1, sender.sendCount);
    }

    @Test
    void primaryRunDisablesDeferredRetryUntilCompletion() throws Exception {
        SequenceSender sender = new SequenceSender(response(200));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(new AttackResult("Header", "payload",
            request("/admin", "", "GET", null, ""), response(429)));
        workspace.setPrimaryRunActive(true);

        workspace.retryThrottled(false);

        assertFalse(workspace.isRetryRunning());
        assertEquals(1, workspace.throttledRetryCount());
        assertEquals(0, sender.sendCount);
    }

    @Test
    void sweepRetryQuarantinesAnEntireStablePayloadShapeAfterOneControlAndSample() throws Exception {
        SequenceSender sender = new SequenceSender(response(403), response(429));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(sweepResult("GET /one", "/one.bak", "/one", "Path suffix .bak"));
        workspace.addResult(sweepResult("GET /two", "/two.bak", "/two", "Path suffix .bak"));

        workspace.retryThrottled(false);
        waitForRetry(workspace);

        assertEquals(2, sender.sendCount);
        assertEquals(2, workspace.retryRequestCount());
        assertEquals(0, workspace.throttledRetryCount());
        assertEquals(2, workspace.patternBlockedRetryCount());
        assertEquals(2, workspace.throttledRetrySnapshot().size());
        assertEquals(3, workspace.allResultsCount());
        assertTrue(workspace.retryStatusText().contains("stable pattern-blocked"));

        workspace.retryThrottled(false);
        assertFalse(workspace.isRetryRunning());
        assertEquals(2, sender.sendCount);
        assertEquals(2, workspace.retryRequestCount());
    }

    @Test
    void aNewPrimaryRunResetsManualRetryRequestTelemetry() throws Exception {
        SequenceSender sender = new SequenceSender(response(200));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.addResult(new AttackResult("Path", "variant",
            request("/admin", "", "GET", null, ""), response(429)));

        workspace.retryThrottled(false);
        waitForRetry(workspace);
        assertEquals(1, workspace.retryRequestCount());

        workspace.setPrimaryRunActive(true);
        assertEquals(0, workspace.retryRequestCount());
    }

    @Test
    void sweepRetryContinuesGroupWhenControlAndSampleAreNoLongerThrottled() throws Exception {
        SequenceSender sender = new SequenceSender(response(403), response(403), response(403));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(sweepResult("GET /one", "/one.bak", "/one", "Path suffix .bak"));
        workspace.addResult(sweepResult("GET /two", "/two.bak", "/two", "Path suffix .bak"));

        workspace.retryThrottled(false);
        waitForRetry(workspace);

        assertEquals(3, sender.sendCount);
        assertEquals(0, workspace.throttledRetryCount());
        assertEquals(0, workspace.patternBlockedRetryCount());
        assertEquals(4, workspace.allResultsCount());
    }

    @Test
    void sweepRetryKeepsQueueRetryableWhenControlIsAlsoThrottled() throws Exception {
        SequenceSender sender = new SequenceSender(response(429));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(sweepResult("GET /one", "/one.bak", "/one", "Path suffix .bak"));
        workspace.addResult(sweepResult("GET /two", "/two.bak", "/two", "Path suffix .bak"));

        workspace.retryThrottled(false);
        waitForRetry(workspace);

        assertEquals(1, sender.sendCount);
        assertEquals(2, workspace.throttledRetryCount());
        assertEquals(0, workspace.patternBlockedRetryCount());
        assertEquals(2, workspace.allResultsCount());
    }

    @Test
    void manualRetryCanPauseBetweenRequestsAndResumeWhereItLeftOff() throws Exception {
        BlockingFirstSender sender = new BlockingFirstSender(response(429));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(new AttackResult("Path", "one",
            request("/one", "", "GET", null, ""), response(429)));
        workspace.addResult(new AttackResult("Path", "two",
            request("/two", "", "GET", null, ""), response(429)));

        workspace.retryThrottled(false);
        assertTrue(sender.firstStarted.await(2, TimeUnit.SECONDS));
        workspace.pauseThrottleRetry();
        sender.releaseFirst.countDown();
        Thread.sleep(150);

        assertTrue(workspace.isRetryRunning());
        assertTrue(workspace.isRetryPaused());
        assertEquals(1, sender.sendCount.get());

        workspace.resumeThrottleRetry();
        waitForRetry(workspace);

        assertEquals(2, sender.sendCount.get());
        assertEquals(2, workspace.throttledRetryCount());
    }

    @Test
    void stoppingManualRetryKeepsUnfinishedRequestsQueued() throws Exception {
        BlockingFirstSender sender = new BlockingFirstSender(response(429));
        SessionResultsWorkspace workspace = workspace(sender);
        workspace.configureThrottleRetries(retrySettings(Set.of(429)));
        workspace.addResult(new AttackResult("Path", "one",
            request("/one", "", "GET", null, ""), response(429)));
        workspace.addResult(new AttackResult("Path", "two",
            request("/two", "", "GET", null, ""), response(429)));

        workspace.retryThrottled(false);
        assertTrue(sender.firstStarted.await(2, TimeUnit.SECONDS));
        workspace.stopThrottleRetry();
        sender.releaseFirst.countDown();
        waitForRetry(workspace);

        assertEquals(2, workspace.throttledRetryCount());
        assertTrue(workspace.retryStatusText().contains("stopped"));
    }

    private SessionResultsWorkspace workspace(RequestSender sender) {
        return new SessionResultsWorkspace(
            api(),
            message -> { },
            ignored -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.DEFAULT,
            false,
            sender
        );
    }

    private AttackResult sweepResult(String targetLabel, String mutationPath,
                                     String originalPath, String payload) {
        return new AttackResult(
            "Coverage Sweep", payload, targetLabel, "Extension / Negotiation", "",
            request(mutationPath, "", "GET", null, ""), response(429),
            request(originalPath, "", "GET", null, ""), response(403)
        );
    }

    private void waitForRetry(SessionResultsWorkspace workspace) throws Exception {
        for (int index = 0; index < 200 && workspace.isRetryRunning(); index++) {
            Thread.sleep(20);
            SwingUtilities.invokeAndWait(() -> { });
        }
        assertFalse(workspace.isRetryRunning());
    }

    private MontoyaApi api() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        return api;
    }

    private HttpResponse response(int status) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(0);
        when(response.headers()).thenReturn(List.of(header("Content-Type", "text/plain")));
        return response;
    }

    private static ThrottleSettings retrySettings(Set<Integer> statusCodes) {
        return new ThrottleSettings(statusCodes, 1, 1, 400.0,
            ThrottleSettings.Posture.CONSERVATIVE);
    }

    private HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                default -> null;
            }
        );
    }

    private static final class BlockingFirstSender implements RequestSender {
        private final HttpResponse response;
        private final AtomicInteger sendCount = new AtomicInteger();
        private final CountDownLatch firstStarted = new CountDownLatch(1);
        private final CountDownLatch releaseFirst = new CountDownLatch(1);

        private BlockingFirstSender(HttpResponse response) {
            this.response = response;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            if (sendCount.incrementAndGet() == 1) {
                firstStarted.countDown();
                try {
                    releaseFirst.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }

    private static final class SequenceSender implements RequestSender {
        private final ArrayDeque<HttpResponse> responses;
        private int sendCount;

        private SequenceSender(HttpResponse... responses) {
            this.responses = new ArrayDeque<>(List.of(responses));
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            sendCount++;
            return responses.isEmpty() ? null : responses.removeFirst();
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }
}
