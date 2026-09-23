package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;

class MontoyaRequestSenderTest {

    @Test
    void safeSweepRequestRetriesOverHttp1WhenAutomaticModeHasNoResponse() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        HttpRequestResponse automaticExchange = mock(HttpRequestResponse.class);
        HttpRequestResponse http1Exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        when(request.method()).thenReturn("GET");
        when(request.url()).thenReturn("https://example.com/admin");
        when(api.http().sendRequest(request)).thenReturn(automaticExchange);
        when(automaticExchange.response()).thenReturn(null);
        when(api.http().sendRequest(request, HttpMode.HTTP_1)).thenReturn(http1Exchange);
        when(http1Exchange.response()).thenReturn(response);

        HttpResponse sent = new MontoyaRequestSender(api, true).send(request);

        assertSame(response, sent);
        verify(api.http()).sendRequest(request, HttpMode.HTTP_1);
    }

    @Test
    void safeSweepRequestRetriesAutomaticModeBeforeSwitchingProtocol() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        HttpRequestResponse automaticExchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        when(request.method()).thenReturn("GET");
        when(request.url()).thenReturn("https://example.com/admin");
        when(api.http().sendRequest(request)).thenReturn(automaticExchange);
        when(automaticExchange.response()).thenReturn(null, response);

        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        HttpResponse sent = new MontoyaRequestSender(api, governor, true).send(request);

        assertSame(response, sent);
        assertEquals(2, governor.snapshot().admittedRequests());
        verify(api.http(), org.mockito.Mockito.times(2)).sendRequest(request);
    }

    @Test
    void safeSweepRequestRetriesOverHttp1WhenAutomaticModeThrows() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        HttpRequestResponse http1Exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        when(request.method()).thenReturn("GET");
        when(request.url()).thenReturn("https://example.com/admin");
        when(api.http().sendRequest(request)).thenThrow(new IllegalStateException("HTTP/2 stream failed"));
        when(api.http().sendRequest(request, HttpMode.HTTP_1)).thenReturn(http1Exchange);
        when(http1Exchange.response()).thenReturn(response);

        HttpResponse sent = new MontoyaRequestSender(api, true).send(request);

        assertSame(response, sent);
        verify(api.http()).sendRequest(request, HttpMode.HTTP_1);
    }

    @Test
    void explicitHttpModeIsPassedDirectlyToMontoya() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        when(api.http().sendRequest(request, HttpMode.HTTP_1)).thenReturn(exchange);
        when(exchange.response()).thenReturn(response);

        HttpResponse sent = new MontoyaRequestSender(api).send(request, HttpMode.HTTP_1);

        assertSame(response, sent);
        verify(api.http()).sendRequest(request, HttpMode.HTTP_1);
    }

    @Test
    void timedSendReturnsNullWithoutShuttingDownInjectedExecutor() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            when(api.http().sendRequest(request).response()).thenAnswer(invocation -> {
                Thread.sleep(100);
                return mock(HttpResponse.class);
            });

            MontoyaRequestSender sender = new MontoyaRequestSender(api, executor);

            assertNull(sender.send(request, 10, TimeUnit.MILLISECONDS));
            assertFalse(executor.isShutdown());
            verify(api.logging()).logToError(contains("Timed HTTP request exceeded"));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void timedSendReportsTransportExceptionToBurpErrors() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        when(api.http().sendRequest(request)).thenThrow(new IllegalStateException("connection failed"));

        assertNull(new MontoyaRequestSender(api).send(request, 1, TimeUnit.SECONDS));

        verify(api.logging()).logToError(contains("Timed HTTP request failed"), any(Throwable.class));
    }

    @Test
    void timedSendPreservesExplicitHttpMode() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        when(api.http().sendRequest(request, HttpMode.HTTP_2)).thenReturn(exchange);
        when(exchange.response()).thenReturn(response);

        HttpResponse sent = new MontoyaRequestSender(api).send(
            request, HttpMode.HTTP_2, 1, TimeUnit.SECONDS);

        assertSame(response, sent);
        verify(api.http()).sendRequest(request, HttpMode.HTTP_2);
    }
}
