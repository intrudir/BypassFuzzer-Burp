package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdorEngineTest {
    @Test
    void successfulQueryBaselinesContinueIntoDefaultMutations() throws InterruptedException {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest original = HttpRequestTestFactory.request(
            "/v3/bolt/user/permissions?include_nuance_permissions&project_id=7650",
            null, "GET", null, "");
        CountDownLatch done = new CountDownLatch(1);
        List<AttackResult> results = new CopyOnWriteArrayList<>();
        IdorEngine engine = new IdorEngine(api, new RequestSender() {
            @Override public HttpResponse send(HttpRequest request) { return response(200); }
            @Override public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) {
                return send(request);
            }
        });
        IdorOptions options = new IdorOptions("7650", "7648", new IdorRunOptions(Set.of()),
            "query:project_id#1", Set.of(), 2, false);

        assertTrue(engine.start(original, options, results::add, done::countDown));
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(4, results.size());
        assertEquals(4, engine.httpRequestsSent());
        assertEquals("TARGET_BASELINE_2XX_REVIEW", results.get(1).getSignal());
        assertNull(engine.lastDiagnostic());
        verify(api.logging(), never()).logToError(any(String.class));
    }

    @Test
    void executionFailureLogsStackTraceToBurpErrors() throws InterruptedException {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest original = HttpRequestTestFactory.request("/users/1", null, "GET", null, "");
        CountDownLatch done = new CountDownLatch(1);
        IdorEngine engine = new IdorEngine(api, new RequestSender() {
            @Override public HttpResponse send(HttpRequest request) { return response(403); }
            @Override public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) {
                return send(request);
            }
        });

        assertTrue(engine.start(original, new IdorOptions("1", "2", new IdorRunOptions(Set.of())),
            result -> { throw new IllegalStateException("result delivery failed"); }, done::countDown));
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertTrue(engine.lastDiagnostic().contains("IllegalStateException"));
        verify(api.logging()).logToError(contains("IDOR scan failed"), any(Exception.class));
    }

    @Test
    void failedControlsStopBeforeMutations() throws InterruptedException {
        HttpRequest original = HttpRequestTestFactory.request("/users/1", null, "GET", null, "");
        CountDownLatch done = new CountDownLatch(1);
        List<AttackResult> results = new CopyOnWriteArrayList<>();
        IdorEngine engine = new IdorEngine(new RequestSender() {
            @Override public HttpResponse send(HttpRequest request) { return null; }
            @Override public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) { return null; }
        });

        assertTrue(engine.start(original, new IdorOptions("1", "2", new IdorRunOptions(Set.of())),
            results::add, done::countDown));
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(2, results.size());
        assertEquals("idor.baseline.control", results.get(0).getPayload());
        assertEquals("idor.baseline.target", results.get(1).getPayload());
        assertEquals(2, engine.httpRequestsSent());
    }

    @Test
    void mutationResultCarriesBothControlResponses() throws InterruptedException {
        HttpRequest original = HttpRequestTestFactory.request("/users/1", null, "GET", null, "");
        CountDownLatch done = new CountDownLatch(1);
        List<AttackResult> results = new CopyOnWriteArrayList<>();
        IdorEngine engine = new IdorEngine(new RequestSender() {
            @Override public HttpResponse send(HttpRequest request) {
                return response(request.path().equals("/users/2") ? 403 : 200);
            }
            @Override public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) {
                return send(request);
            }
        });
        IdorOptions options = new IdorOptions("1", "2", new IdorRunOptions(Set.of()),
            "path:2", Set.of("idor.path.suffix_formats"), 1, false);
        assertTrue(engine.start(original, options, results::add, done::countDown));
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(3, results.size(), results.stream()
            .map(result -> result.getPayload() + " " + result.getRequest().path() + " "
                + result.getPayloadEncoding() + " " + result.getStatusCode()).toList().toString());
        AttackResult mutation = results.get(2);
        assertEquals(200, mutation.getOriginalResponse().statusCode());
        assertEquals(403, mutation.getVerificationResponse().statusCode());
        assertEquals("/users/1", mutation.getOriginalRequest().path());
        assertEquals("/users/2", mutation.getVerificationRequest().path());
    }

    private HttpResponse response(int status) {
        HttpResponse value = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("ok".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(body.length()).thenReturn(2);
        when(value.statusCode()).thenReturn((short) status);
        when(value.body()).thenReturn(body);
        when(value.headers()).thenReturn(List.of());
        return value;
    }
}
