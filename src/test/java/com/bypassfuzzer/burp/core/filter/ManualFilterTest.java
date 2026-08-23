package com.bypassfuzzer.burp.core.filter;

import com.bypassfuzzer.burp.core.attacks.AttackResult;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ManualFilterTest {

    @Test
    void filtersResultsBySignalSubstring() {
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setSignalContainsFilter("bypass?");
        ManualFilter filter = new ManualFilter(config);

        assertTrue(filter.shouldShow(result("BYPASS?: authenticated 200 -> anonymous 403 -> probe 200")));
        assertFalse(filter.shouldShow(result("LIKELY PUBLIC: authenticated 200 -> unauthenticated 200")));
        assertFalse(filter.shouldShow(result("")));
    }

    @Test
    void filtersResultsBySignalRegex() {
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setSignalContainsFilter("BYPASS\\?( \\(weak\\))?: .*anonymous (401|403) -> probe 2[0-9][0-9]");
        config.setSignalContainsRegex(true);
        ManualFilter filter = new ManualFilter(config);

        assertTrue(filter.shouldShow(result("BYPASS?: authenticated 200 -> anonymous 403 -> probe 200")));
        assertFalse(filter.shouldShow(result("BYPASS? (weak): authenticated 200 -> anonymous 404 -> probe 200")));
    }

    @Test
    void filtersResponsesThatContainConfiguredTextWhenMatchIsInverted() {
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setResponseContainsFilter("access denied");
        config.setResponseMatchInverted(true);
        ManualFilter filter = new ManualFilter(config);

        assertFalse(filter.shouldShow(responseResult("HTTP/1.1 403 Forbidden\r\n\r\nAccess denied")));
        assertTrue(filter.shouldShow(responseResult("HTTP/1.1 200 OK\r\n\r\nWelcome")));
        assertFalse(filter.shouldShow(responseResult(null)));
    }

    @Test
    void supportsInvertedResponseRegex() {
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setResponseContainsFilter("error\\s+[0-9]{3}");
        config.setResponseContainsRegex(true);
        config.setResponseMatchInverted(true);
        ManualFilter filter = new ManualFilter(config);

        assertFalse(filter.shouldShow(responseResult("Error 500")));
        assertTrue(filter.shouldShow(responseResult("Request completed")));
    }

    private AttackResult result(String signal) {
        return new AttackResult("Coverage Sweep", "probe", "target", "family", signal, null, null);
    }

    private AttackResult responseResult(String rawResponse) {
        HttpResponse response = null;
        if (rawResponse != null) {
            response = mock(HttpResponse.class);
            ByteArray body = mock(ByteArray.class);
            when(body.length()).thenReturn(rawResponse.length());
            when(response.body()).thenReturn(body);
            when(response.headers()).thenReturn(List.of());
            when(response.toString()).thenReturn(rawResponse);
        }
        return new AttackResult("Coverage Sweep", "probe", "target", "family", "", null, response);
    }
}
