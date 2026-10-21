package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.ConfiguredHeader;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.values;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfiguredHeaderPolicyTest {

    @Test
    void replacesCapturedHeaderAndPreservesConfiguredDuplicates() {
        HttpRequest original = request(Map.entry("Authorization", "Bearer captured"),
            Map.entry("X-Keep", "original"));
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("Authorization", "Bearer one"),
            new ConfiguredHeader("authorization", "Bearer two")));

        HttpRequest sent = policy.reconcileMutation(original, original);

        assertEquals(List.of("Bearer one", "Bearer two"), values(sent, "Authorization"));
        assertEquals(List.of("original"), values(sent, "X-Keep"));
    }

    @Test
    void preservesFullConfiguredOrderBeforeAppendingPayloads() {
        HttpRequest original = request(Map.entry("X-A", "captured"));
        HttpRequest mutated = original.withUpdatedHeader("X-A", "payload");
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("X-A", "one"),
            new ConfiguredHeader("X-B", "middle"),
            new ConfiguredHeader("x-a", "two")));

        HttpRequest sent = policy.reconcileMutation(original, mutated);
        String raw = sent.toString();

        org.junit.jupiter.api.Assertions.assertTrue(raw.indexOf("X-A: one") < raw.indexOf("X-B: middle"));
        org.junit.jupiter.api.Assertions.assertTrue(raw.indexOf("X-B: middle") < raw.indexOf("x-a: two"));
        org.junit.jupiter.api.Assertions.assertTrue(raw.indexOf("x-a: two") < raw.indexOf("X-A: payload"));
    }

    @Test
    void configuredValuePrecedesHeaderAttackPayload() {
        HttpRequest original = request(Map.entry("Origin", "{INJECT}"));
        HttpRequest mutated = original.withUpdatedHeader("Origin", "https://attacker.test");
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("Origin", "https://trusted.test")));

        HttpRequest sent = policy.reconcileMutation(original, mutated);

        assertEquals(List.of("https://trusted.test", "https://attacker.test"), values(sent, "Origin"));
    }

    @Test
    void addedDuplicateDoesNotCarryCapturedValueIntoFinalRequest() {
        HttpRequest original = request(Map.entry("Authorization", "Bearer captured"));
        HttpRequest mutated = original.withAddedHeader("Authorization", "Basic bypass");
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("Authorization", "Bearer stable")));

        HttpRequest sent = policy.reconcileMutation(original, mutated);

        assertEquals(List.of("Bearer stable", "Basic bypass"), values(sent, "Authorization"));
    }

    @Test
    void cookieAppendKeepsConfiguredCookieThenOnlyPayloadDelta() {
        HttpRequest original = request(Map.entry("Cookie", "captured=old"));
        HttpRequest mutated = original.withUpdatedHeader("Cookie", "captured=old; debug=true");
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("Cookie", "session=valid")));

        HttpRequest sent = policy.reconcileMutation(original, mutated);

        assertEquals(List.of("session=valid", "debug=true"), values(sent, "Cookie"));
    }

    @Test
    void anonymousPolicyDropsSelectedCredentialsButRetainsOtherHeadersAndCookies() {
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("Authorization", "Bearer valid"),
            new ConfiguredHeader("X-Tenant", "blue"),
            new ConfiguredHeader("Cookie", "session=secret; theme=dark")));
        ConfiguredHeaderPolicy anonymous = policy.withoutAuthentication(
            Set.of("Authorization"), Set.of("session"));
        HttpRequest original = request();

        HttpRequest sent = anonymous.reconcileMutation(original, original);

        assertEquals(List.of(), values(sent, "Authorization"));
        assertEquals(List.of("blue"), values(sent, "X-Tenant"));
        assertEquals(List.of("theme=dark"), values(sent, "Cookie"));
    }
}
