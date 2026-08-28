package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.ThrottledRequest;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.RetryQueue;
import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AttackExecutorThrottleTest {

    @Test
    void throttledAttemptIsBothVisibleAndScheduledForRetry() {
        HttpResponse throttled = response(429);
        RetryQueue<ThrottledRequest> retries = new RetryQueue<>();
        List<AttackResult> visibleResults = new ArrayList<>();
        AttackExecutor executor = new AttackExecutor(new FixedSender(throttled));
        executor.enableRetryQueue(retries);
        HostThrottleCoordinator coordinator = new HostThrottleCoordinator(
            new ThrottleSettings(Set.of(429), 1, 1, 400.0,
                ThrottleSettings.Posture.RIDE_HARD),
            null
        );

        executor.execute("Path", "..%2F", request("/admin", "", "GET", null, ""),
            visibleResults::add, () -> true, coordinator);

        assertEquals(1, visibleResults.size(), "the 429 must remain visible as HTTP evidence");
        assertEquals(429, visibleResults.get(0).getStatusCode());
        assertEquals(1, retries.size(), "the same payload must still be scheduled for retry");
    }

    @Test
    void automaticRetryCapacityNeverSuppressesThrottleEvidence() {
        HttpResponse throttled = response(429);
        RetryQueue<ThrottledRequest> retries = new RetryQueue<>(1);
        List<AttackResult> visibleResults = new ArrayList<>();
        AttackExecutor executor = new AttackExecutor(new FixedSender(throttled));
        executor.enableRetryQueue(retries);
        HostThrottleCoordinator coordinator = new HostThrottleCoordinator(
            new ThrottleSettings(Set.of(429), 1, 1, 400.0,
                ThrottleSettings.Posture.RIDE_HARD),
            null
        );

        executor.execute("Path", "one", request("/one", "", "GET", null, ""),
            visibleResults::add, () -> true, coordinator);
        executor.execute("Path", "two", request("/two", "", "GET", null, ""),
            visibleResults::add, () -> true, coordinator);

        assertEquals(2, visibleResults.size());
        assertEquals(1, retries.size());
        assertEquals(1, retries.rejectedCount());
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

    private record FixedSender(HttpResponse response) implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) {
            return response;
        }
    }
}
