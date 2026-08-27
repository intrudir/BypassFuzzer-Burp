package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AttackResultTest {

    @Test
    void movesPerProbeEvidenceToTempFilesAndKeepsSharedBaselinesByIdentity() {
        HttpRequest request = mock(HttpRequest.class);
        HttpRequest storedRequest = mock(HttpRequest.class);
        HttpRequest originalRequest = mock(HttpRequest.class);
        HttpResponse response = response(200, 12);
        HttpResponse storedResponse = response(200, 12);
        HttpResponse originalResponse = response(403, 7);
        when(request.copyToTempFile()).thenReturn(storedRequest);
        when(response.copyToTempFile()).thenReturn(storedResponse);
        AttackResult result = new AttackResult("Sweep", "payload", "target", "Path", "403 -> 200",
            request, response, originalRequest, originalResponse);

        AttackResult durable = result.copyEvidenceToTempFile();

        assertTrue(durable.isEvidenceOnDisk());
        assertSame(storedRequest, durable.getRequest());
        assertSame(storedResponse, durable.getResponse());
        assertSame(originalRequest, durable.getOriginalRequest());
        assertSame(originalResponse, durable.getOriginalResponse());
        assertEquals(200, durable.getStatusCode());
        assertEquals(12, durable.getContentLength());
        assertSame(durable, durable.copyEvidenceToTempFile());
        verify(originalRequest, never()).copyToTempFile();
        verify(originalResponse, never()).copyToTempFile();
    }

    private HttpResponse response(int status, int length) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(length);
        when(response.headers()).thenReturn(List.of());
        return response;
    }
}
