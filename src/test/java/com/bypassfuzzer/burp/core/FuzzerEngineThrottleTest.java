package com.bypassfuzzer.burp.core;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FuzzerEngineThrottleTest {

    @Test
    void exhaustedAutomaticRetriesRemainVisibleAndAuditable() throws Exception {
        FuzzerConfig config = trailingDotOnlyConfig();
        FixedSender sender = new FixedSender(response(429));
        FuzzerEngine engine = new FuzzerEngine(null, config, new GlobalTrafficGovernor(), sender);
        List<AttackResult> results = new CopyOnWriteArrayList<>();
        CountDownLatch completed = new CountDownLatch(1);

        assertTrue(engine.startFuzzing(
            request("/admin", "", "GET", null, ""), results::add, completed::countDown));
        assertTrue(completed.await(10, TimeUnit.SECONDS));

        assertEquals(4, sender.sendCount);
        assertEquals(4, results.size(), "initial 429 plus all three retry responses must be visible");
        assertEquals(List.of(0, 1, 2, 3),
            results.stream().map(AttackResult::getThrottleRetryAttempt).toList());
        assertTrue(results.stream().allMatch(result -> result.getStatusCode() == 429));

        FuzzerProgress progress = engine.progress();
        assertEquals(1, progress.plannedPayloads());
        assertEquals(4, progress.httpRequestsSent());
        assertEquals(4, progress.resultsRecorded());
        assertEquals(1, progress.automaticRetriesPending(),
            "the exhausted payload must remain available to the shared manual retry workspace");
        assertEquals(0, progress.automaticRetriesRejected());
    }

    private static FuzzerConfig trailingDotOnlyConfig() {
        FuzzerConfig config = new FuzzerConfig();
        config.setEnableHeaderAttack(false);
        config.setEnablePathAttack(false);
        config.setEnableVerbAttack(false);
        config.setEnableParamAttack(false);
        config.setEnableCookieParamAttack(false);
        config.setEnableTrailingSlashAttack(false);
        config.setEnableExtensionAttack(false);
        config.setEnableContentTypeAttack(false);
        config.setEnableEncodingAttack(false);
        config.setEnableProtocolAttack(false);
        config.setEnableCaseAttack(false);
        config.setEnableTrailingDotAttack(true);
        config.setEnableCollaboratorPayloads(false);
        config.setConcurrency(1);
        config.setPerHostConcurrency(1);
        config.setThrottleStatusCodes(Set.of(429));
        return config;
    }

    private static HttpResponse response(int status) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(0);
        when(response.headers()).thenReturn(List.<HttpHeader>of());
        return response;
    }

    private static final class FixedSender implements RequestSender {
        private final HttpResponse response;
        private int sendCount;

        private FixedSender(HttpResponse response) {
            this.response = response;
        }

        @Override
        public synchronized HttpResponse send(HttpRequest request) {
            sendCount++;
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) {
            return send(request);
        }
    }
}
