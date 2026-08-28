package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

class UrlValidationEngineTest {

    @Test
    void countsEveryPhysicalRequestAttemptIndependentlyFromResultRows() throws Exception {
        List<AttackResult> results = new ArrayList<>();
        CountDownLatch completion = new CountDownLatch(1);
        UrlValidationEngine engine = new UrlValidationEngine(
            mock(MontoyaApi.class, RETURNS_DEEP_STUBS),
            new GlobalTrafficGovernor(),
            new NullResponseRequestSender(),
            new UrlValidationCandidateFinder() {
                @Override
                public List<UrlValidationCandidate> find(
                    burp.api.montoya.http.message.requests.HttpRequest request,
                    UrlValidationOptions options) {
                    return List.of(new UrlValidationCandidate(
                        "marker", "trusted.example", "marker", (base, payload) -> base));
                }
            });
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "attacker.example",
            false,
            "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL),
            Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS),
            Set.of(UrlValidationEncoding.RAW),
            Set.of(429, 503));

        assertTrue(engine.start(
            request("/redirect", "next={INJECT}", "GET", null, ""),
            options,
            result -> {
                results.add(result);
                engine.stop();
            },
            completion::countDown));
        assertTrue(completion.await(5, TimeUnit.SECONDS));

        assertFalse(results.isEmpty());
        assertEquals(results.size(), engine.httpRequestsSent());
    }

    private static final class NullResponseRequestSender implements RequestSender {
        @Override
        public HttpResponse send(burp.api.montoya.http.message.requests.HttpRequest request) {
            return null;
        }

        @Override
        public HttpResponse send(burp.api.montoya.http.message.requests.HttpRequest request,
                                 long timeout, TimeUnit timeUnit) {
            return null;
        }
    }
}
