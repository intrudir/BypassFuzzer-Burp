package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.scan.PlannedRequest;
import com.bypassfuzzer.core.scan.ScanOptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BurpScanAdapterTest {

    @ParameterizedTest
    @ValueSource(strings = {"bypass", "url-validation"})
    void automaticModePreservesServerErrorResponse(String scanMode) throws Exception {
        HttpRequest original = request("/admin", "", "GET", null, "");
        HttpResponse response = serverError();
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(api.http().sendRequest(any(HttpRequest.class))).thenReturn(exchange);
        when(exchange.response()).thenReturn(response);
        ScanOptions options = new ScanOptions(HttpProtocol.AUTO, Duration.ofSeconds(1),
            1, 1, Set.of(429, 503), 0, false, "ride-hard", "off", 30_000, false, false);
        List<AttackResult> results = new ArrayList<>();

        new BurpScanAdapter(original, new MontoyaRequestSender(api), options).run(scanMode,
            base -> List.of(new PlannedRequest("Header", "probe", "probe", base, false)), results::add);

        assertEquals(1, results.size());
        assertEquals(500, results.get(0).getStatusCode());
        assertEquals(6, results.get(0).getContentLength());
        assertSame(response, results.get(0).getResponse());
        verify(api.http()).sendRequest(any(HttpRequest.class));
        verify(api.http(), never()).sendRequest(any(HttpRequest.class), nullable(HttpMode.class));
    }

    @Test
    void idorPreservesServerErrorBaselineWithExplicitHttpMode() throws Exception {
        HttpRequest original = request("/users/2", "", "GET", null, "");
        HttpResponse response = serverError();
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(api.http().sendRequest(any(HttpRequest.class), org.mockito.ArgumentMatchers.eq(HttpMode.HTTP_1)))
            .thenReturn(exchange);
        when(exchange.response()).thenReturn(response);
        ScanOptions options = new ScanOptions(HttpProtocol.HTTP_1, Duration.ofSeconds(1),
            1, 1, Set.of(429, 503), 0, false, "ride-hard", "off", 30_000);
        List<AttackResult> results = new ArrayList<>();

        new BurpScanAdapter(original, new MontoyaRequestSender(api), options).run("idor",
            base -> List.of(PlannedRequest.baseline(base, "Authorized control")), results::add);

        assertEquals(1, results.size());
        assertEquals(500, results.get(0).getStatusCode());
        assertEquals(6, results.get(0).getContentLength());
        assertSame(response, results.get(0).getResponse());
        verify(api.http()).sendRequest(any(HttpRequest.class), org.mockito.ArgumentMatchers.eq(HttpMode.HTTP_1));
        verify(api.http(), never()).sendRequest(any(HttpRequest.class));
    }

    private HttpResponse serverError() {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(response.statusCode()).thenReturn((short) 500);
        when(response.body()).thenReturn(body);
        when(body.getBytes()).thenReturn("denied".getBytes());
        when(body.length()).thenReturn(6);
        when(response.headers()).thenReturn(List.of());
        return response;
    }
}
