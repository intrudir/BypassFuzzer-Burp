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

    @Test void locallyPausedPacingDoesNotHoldSharedTrafficSlots() throws Exception {
        MontoyaApi api=mock(MontoyaApi.class,org.mockito.Mockito.RETURNS_DEEP_STUBS);
        var local=com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request("/local","","GET",null,"");
        var other=com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request("/other","","GET",null,"");
        var exchange=mock(HttpRequestResponse.class);var response=mock(HttpResponse.class);when(exchange.response()).thenReturn(response);
        when(api.http().sendRequest(local,HttpMode.HTTP_1)).thenReturn(exchange);when(api.http().sendRequest(other,HttpMode.HTTP_1)).thenReturn(exchange);
        var governor=new GlobalTrafficGovernor();governor.configure(true,1,1000);
        var slow=new com.bypassfuzzer.core.scan.LiveRun(new com.bypassfuzzer.core.scan.RunConfiguration(java.util.Set.of(),1,1,0.1,java.util.Set.of(),java.util.List.of(),java.util.Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0),java.util.Map.of());
        var fast=new com.bypassfuzzer.core.scan.LiveRun(new com.bypassfuzzer.core.scan.RunConfiguration(java.util.Set.of(),1,1,1000,java.util.Set.of(),java.util.List.of(),java.util.Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0),java.util.Map.of());
        var sender=new MontoyaRequestSender(api,governor);var callers=Executors.newFixedThreadPool(2);
        try {
            assertSame(response,sender.sendManaged(local,HttpMode.HTTP_1,1,TimeUnit.SECONDS,() -> true,slow,0));
            var paced=callers.submit(() -> sender.sendManaged(local,HttpMode.HTTP_1,1,TimeUnit.SECONDS,() -> true,slow,0));
            Thread.sleep(100);slow.pause();assertEquals(com.bypassfuzzer.core.scan.LiveRun.State.PAUSED,slow.snapshot().state());
            var independent=callers.submit(() -> sender.sendManaged(other,HttpMode.HTTP_1,1,TimeUnit.SECONDS,() -> true,fast,0));
            assertSame(response,independent.get(2,TimeUnit.SECONDS));assertFalse(paced.isDone());assertEquals(2,governor.snapshot().admittedRequests());
        }finally{slow.stop();fast.stop();governor.resume();callers.shutdownNow();}
    }

    @Test void managedSweepRetainsAutomaticProtocolRecoveryAndCountsPhysicalAttempts() {
        MontoyaApi api=mock(MontoyaApi.class,org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request=com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request("/private","","GET",null,"");
        HttpRequestResponse automatic=mock(HttpRequestResponse.class),http1=mock(HttpRequestResponse.class);HttpResponse response=mock(HttpResponse.class);
        when(api.http().sendRequest(request)).thenReturn(automatic);when(automatic.response()).thenReturn(null);
        when(api.http().sendRequest(request,HttpMode.HTTP_1)).thenReturn(http1);when(http1.response()).thenReturn(response);
        var config=new com.bypassfuzzer.core.scan.RunConfiguration(java.util.Set.of(),1,1,400,java.util.Set.of(),java.util.List.of(),java.util.Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0);
        var run=new com.bypassfuzzer.core.scan.LiveRun(config,java.util.Map.of());
        assertSame(response,new MontoyaRequestSender(api,new GlobalTrafficGovernor(),true).sendManaged(request,null,1,TimeUnit.SECONDS,() -> true,run,0));
        assertEquals(3,run.snapshot().requestsSent());verify(api.http(),org.mockito.Mockito.times(2)).sendRequest(request);verify(api.http()).sendRequest(request,HttpMode.HTTP_1);
    }

    @Test void localEditWhileGloballyPausedDoesNotStartTimeoutOrSendStaleWork() throws Exception {
        MontoyaApi api=mock(MontoyaApi.class,org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request=com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request("/private","","GET",null,"");
        var governor=new GlobalTrafficGovernor();governor.pause();
        var config=new com.bypassfuzzer.core.scan.RunConfiguration(java.util.Set.of(),1,1,400,java.util.Set.of(),java.util.List.of(),java.util.Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0);
        var run=new com.bypassfuzzer.core.scan.LiveRun(config,java.util.Map.of());
        var caller=Executors.newSingleThreadExecutor();
        try {
            var future=caller.submit(() -> new MontoyaRequestSender(api,governor).sendManaged(request,null,20,TimeUnit.MILLISECONDS,() -> true,run,0));
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(governor.snapshot().queued()==0 && System.nanoTime()<deadline)Thread.sleep(10);
            assertEquals(1,governor.snapshot().queued());Thread.sleep(80);assertFalse(future.isDone());
            run.pause();assertEquals(com.bypassfuzzer.core.scan.LiveRun.State.PAUSED,run.snapshot().state());
            run.apply(new com.bypassfuzzer.core.scan.RunConfiguration(java.util.Set.of("example.com"),1,1,20,java.util.Set.of(),java.util.List.of(),java.util.Set.of(),com.bypassfuzzer.core.http.UserAgentMode.DISABLED,0));run.resume();
            var failure=org.junit.jupiter.api.Assertions.assertThrows(java.util.concurrent.ExecutionException.class,() -> future.get(3,TimeUnit.SECONDS));
            org.junit.jupiter.api.Assertions.assertInstanceOf(com.bypassfuzzer.core.scan.LiveRun.Reconfigured.class,failure.getCause());
            assertEquals(0,run.snapshot().requestsSent());assertEquals(true,governor.snapshot().paused());org.mockito.Mockito.verifyNoInteractions(api.http());
        }finally{run.stop();governor.resume();caller.shutdownNow();}
    }

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
