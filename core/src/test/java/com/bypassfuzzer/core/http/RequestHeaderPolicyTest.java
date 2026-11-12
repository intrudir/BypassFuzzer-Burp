package com.bypassfuzzer.core.http;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RequestHeaderPolicyTest {
    private HttpRequestData seed() {
        return new RawHttpRequestParser().parse(
            "GET /apiDoc?tenant=blue HTTP/1.1\r\nHost: example.test\r\nUser-Agent: captured\r\nX-Keep: original\r\n\r\n".getBytes(),
            TargetOrigin.parse("https://example.test"));
    }

    @ParameterizedTest
    @EnumSource(UserAgentMode.class)
    void headerlessProtocolRetainsItsWireShapeForFixedAndRandomizedHeaders(UserAgentMode mode) {
        var original = seed();
        var probe = original.withProtocol(HttpProtocol.HTTP_0_9);
        var policy = new RequestHeaderPolicy<>(RequestAccess.CORE,
            List.of(new ConfiguredHeader("User-Agent", "Sweep-Repro-UA"), new ConfiguredHeader("X-Tenant", "blue")), mode, 42);

        assertFalse(RequestAccess.CORE.supportsHeaders(probe));
        assertSame(probe, policy.applyToBase(probe));
        assertSame(probe, policy.reconcileMutation(original, probe));
        assertEquals("GET /apiDoc?tenant=blue\r\n", probe.toRaw());
        assertEquals(original.origin(), probe.origin());
    }

    @ParameterizedTest
    @EnumSource(value = HttpProtocol.class, names = {"AUTO", "HTTP_1", "HTTP_1_0", "HTTP_2"})
    void headerSupportingProtocolsKeepConfiguredValuesAndPayloadDeltas(HttpProtocol protocol) {
        var original = seed().withProtocol(protocol);
        var probe = original.upsertHeader("User-Agent", "payload-agent").upsertHeader("X-Keep", "mutated");
        var policy = new RequestHeaderPolicy<>(RequestAccess.CORE,
            List.of(new ConfiguredHeader("User-Agent", "Sweep-Repro-UA")), UserAgentMode.DISABLED, 0);
        var reconciled = policy.reconcileMutation(original, probe);

        assertTrue(RequestAccess.CORE.supportsHeaders(probe));
        assertEquals(List.of("Sweep-Repro-UA", "payload-agent"), reconciled.headers().stream()
            .filter(h -> h.name().equalsIgnoreCase("User-Agent")).map(HttpHeader::value).toList());
        assertEquals("mutated", reconciled.firstHeader("X-Keep").orElseThrow());
        assertEquals(protocol, reconciled.protocol());
        assertEquals(probe.rawTarget(), reconciled.rawTarget());
        assertArrayEquals(probe.body(), reconciled.body());
    }
}
