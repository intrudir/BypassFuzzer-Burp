package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserAgentRandomizerTest {

    @Test
    void syntheticTokensAreStableWithinARunAndVaryByRequest() {
        HttpRequest first = request("/admin", "debug=true", "GET", null, "");
        HttpRequest second = request("/reports", "", "GET", null, "");

        String firstValue = UserAgentRandomizer.valueFor(UserAgentMode.SYNTHETIC, 42L, first);
        String repeatedValue = UserAgentRandomizer.valueFor(UserAgentMode.SYNTHETIC, 42L, first);
        String secondValue = UserAgentRandomizer.valueFor(UserAgentMode.SYNTHETIC, 42L, second);

        assertEquals(firstValue, repeatedValue);
        assertNotEquals(firstValue, secondValue);
        assertTrue(firstValue.matches("vexa-[0-9a-f]{10}/[0-9]+\\.[0-9]+ "
            + "orbit-[0-9a-f]{8}/[0-9]+\\.[0-9]+"), firstValue);
        assertFalse(firstValue.contains("Mozilla"));
    }

    @Test
    void browserLikeModeProducesBrowserShapedVariants() {
        String value = UserAgentRandomizer.valueFor(
            UserAgentMode.BROWSER_LIKE, 99L,
            request("/admin", "", "GET", null, ""));

        assertTrue(value.startsWith("Mozilla/5.0 ("), value);
        assertTrue(value.contains("Chrome/") || value.contains("Firefox/")
            || value.contains("Version/"), value);
    }

    @Test
    void randomizedBaseReplacesFixedValueAndPreservesUserAgentAttackPayload() {
        HttpRequest baseline = HeaderRequestTestFactory.request(
            Map.entry("User-Agent", "fixed-agent"));
        HttpRequest attacked = HeaderRequestTestFactory.request(
            Map.entry("User-Agent", "fixed-agent"),
            Map.entry("User-Agent", "https://payload.example"));

        HttpRequest randomized = UserAgentRandomizer.reconcile(
            baseline, attacked, UserAgentMode.SYNTHETIC, 7L);
        List<String> values = HeaderRequestTestFactory.values(randomized, "User-Agent");

        assertEquals(2, values.size());
        assertTrue(values.get(0).startsWith("vexa-"), values.toString());
        assertEquals("https://payload.example", values.get(1));
    }

    @Test
    void disabledModeLeavesRequestUntouched() {
        HttpRequest request = requestWithHeaders("/admin", "", "GET",
            Map.of("User-Agent", "fixed-agent"), "");

        assertSame(request, UserAgentRandomizer.reconcile(
            request, request, UserAgentMode.DISABLED, 1L));
    }
}
