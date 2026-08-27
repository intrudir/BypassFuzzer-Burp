package com.bypassfuzzer.core.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RawHttpRequestParserTest {
    @Test
    void keepsRoutingOriginSeparateFromDuplicateHostHeadersAndRawTarget() {
        byte[] raw = ("POST /a/%2e/b?x=1 HTTP/1.1\r\nHost: fuzzed.example\r\nHost: duplicate.example\r\nX-Test: one\r\n\r\nbody")
            .getBytes(StandardCharsets.ISO_8859_1);
        HttpRequestData request = new RawHttpRequestParser().parse(raw, TargetOrigin.parse("https://route.example:8443"));

        assertEquals("route.example", request.origin().host());
        assertEquals("/a/%2e/b?x=1", request.rawTarget());
        assertEquals(2, request.headers().stream().filter(header -> header.name().equalsIgnoreCase("Host")).count());
        assertArrayEquals("body".getBytes(StandardCharsets.ISO_8859_1), request.body());
    }
}
