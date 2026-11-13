package com.bypassfuzzer.burp.session;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionPreflightAnalyzerTest {

    private final SessionPreflightAnalyzer analyzer = new SessionPreflightAnalyzer();

    @Test
    void warnsWhenRootPathDisablesPathLikeAttacks() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.pathWithoutQuery()).thenReturn("/");
        when(request.method()).thenReturn("GET");
        when(request.url()).thenReturn("https://example.com/");
        when(request.body()).thenReturn(emptyBody());

        SessionRunOptions options = new SessionRunOptions(
            false, true, false, false, false, true, true, false, true, false, false,
            false, false, false, 1, Set.of()
        );

        assertEquals(
            List.of("Path, Trailing Slash, Extension, Encoding attacks will be skipped (root path '/' detected)"),
            analyzer.analyze(request, options)
        );
    }

    @Test
    void contentTypeHeaderProbesRemainAvailableWithoutParameters() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.pathWithoutQuery()).thenReturn("/admin");
        when(request.method()).thenReturn("GET");
        when(request.url()).thenReturn("https://example.com/admin");
        when(request.body()).thenReturn(emptyBody());

        SessionRunOptions options = new SessionRunOptions(
            false, false, false, false, false, false, false, true, false, false, false,
            false, false, false, 1, Set.of()
        );

        assertEquals(List.of(), analyzer.analyze(request, options));
    }

    private ByteArray emptyBody() {
        return (ByteArray) Proxy.newProxyInstance(
            ByteArray.class.getClassLoader(),
            new Class[]{ByteArray.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "length" -> 0;
                case "getBytes" -> new byte[0];
                case "toString" -> "";
                case "iterator" -> List.<Byte>of().iterator();
                default -> throw new UnsupportedOperationException(method.getName());
            }
        );
    }
}
