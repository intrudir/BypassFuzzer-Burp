package com.bypassfuzzer.burp.core.urlvalidation;
import com.bypassfuzzer.core.urlvalidation.UrlValidationPayload;
import com.bypassfuzzer.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.core.urlvalidation.UrlValidationContext;
import com.bypassfuzzer.core.urlvalidation.UrlValidationAttackSetting;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlValidationPayloadGeneratorTest {

    @Test
    void intrudersEncodingPercentEncodesSelectedCharactersAcrossFamilies() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "http",
            Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME, UrlValidationContext.CORS_ORIGIN),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK
            ),
            Set.of(UrlValidationEncoding.INTRUDERS),
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertEquals(413, payloads.size());
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.encoding() == UrlValidationEncoding.INTRUDERS
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.CORS_ORIGIN
                && payload.encoding() == UrlValidationEncoding.INTRUDERS
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().contains("127.0.0.1")
        ));
        // Source-based generation with INTRUDERS keeps [ and ] literal (they're
        // in the safe set). Old rendered cache had them encoded as %5B/%5D.
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().contains("[::]")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().contains("//127.0.0.1")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().contains("%400")
        ));
        assertFalse(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().equals("https://%0D%0A//127.0.0.1")
        ));
    }

    @Test
    void selectedFamiliesLimitPayloadGeneration() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "http",
            Set.of(UrlValidationContext.CORS_ORIGIN),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK
            ),
            Set.of(UrlValidationEncoding.UNICODE_ESCAPE),
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertEquals(35, payloads.size());
        assertTrue(payloads.stream().allMatch(payload -> payload.family() == UrlValidationContext.CORS_ORIGIN));
        assertEquals(
            payloads.size(),
            payloads.stream().filter(payload -> payload.encoding() == UrlValidationEncoding.UNICODE_ESCAPE).count()
        );
        assertTrue(payloads.stream().anyMatch(payload -> payload.value().equals("null")));
    }

    @Test
    void optionalAttackSettingsAppendSourcePayloads() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK,
                UrlValidationAttackSetting.CLOUD_METADATA_ENDPOINTS
            ),
            Set.of(UrlValidationEncoding.INTRUDERS),
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        // Source-based generation (no rendered cache) produces slightly different
        // counts and encoding shapes than the old cache path.
        assertTrue(payloads.size() > 230, "expected > 230 payloads; got " + payloads.size());
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.value().equals("http://169.254.169.254/latest/meta-data/")
        ));
        // Cloud metadata loopback variant — brackets stay literal under INTRUDERS
        // ([ and ] are in the safe set).
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.value().contains("[::]")
        ));
    }

    @Test
    void cloudMetadataPayloadsAreShapedPerFamily() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            false,
            "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME),
            Set.of(UrlValidationAttackSetting.CLOUD_METADATA_ENDPOINTS),
            Set.of(UrlValidationEncoding.INTRUDERS),
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertEquals(34, payloads.size());
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().equals("http://169.254.169.254/latest/meta-data/")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.HOSTNAME
                && payload.value().equals("169.254.169.254")
        ));
        assertFalse(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.HOSTNAME
                && payload.value().contains("/latest/meta-data/")
        ));
        assertFalse(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.HOSTNAME
                && payload.value().startsWith("http://")
        ));
    }

    @Test
    void attackerHostSupplierGeneratesDistinctHostsPerPayload() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "fallback.example",
            true,
            "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL),
            Set.of(UrlValidationAttackSetting.FAKE_RELATIVE_URLS),
            Set.of(UrlValidationEncoding.RAW),
            Set.of()
        );
        AtomicInteger counter = new AtomicInteger();

        List<UrlValidationPayload> payloads = generator.generate(
            candidate,
            options,
            () -> "collab-" + counter.incrementAndGet() + ".oastify.com"
        );

        List<String> userInfoPayloads = payloads.stream()
            .map(UrlValidationPayload::value)
            .filter(value -> value.contains("@collab-"))
            .collect(Collectors.toList());

        assertEquals(3, userInfoPayloads.size());
        assertTrue(userInfoPayloads.contains("https://@collab-5.oastify.com"));
        assertTrue(userInfoPayloads.contains("http:@collab-6.oastify.com"));
        assertTrue(userInfoPayloads.contains("https:@collab-7.oastify.com"));
    }

    // --- Upstream sync sanity checks ---
    // The bundled url_validation_source_data.json mirrors the upstream
    // PortSwigger url-cheatsheet-data repo. These tests fail if a local
    // edit accidentally drops or duplicates payloads. scripts/sync-url-
    // cheatsheet.py pulls fresh upstream data; if it changes a count
    // below, bump the expected number.

    @Test
    void bundledSourceDataHasExpectedCategorySizes() throws Exception {
        // Load the raw JSON resource and count payloads per category. Catches
        // local edits that drop/duplicate entries or break the file format.
        try (InputStream stream = getClass().getResourceAsStream("/payloads/url_validation_source_data.json")) {
            assertTrue(stream != null, "resource /payloads/url_validation_source_data.json must load");
            List<Map<String, Object>> wordlists = new Gson().fromJson(
                new InputStreamReader(stream, StandardCharsets.UTF_8),
                new TypeToken<List<Map<String, Object>>>() {}.getType()
            );

            Map<String, Integer> expected = Map.of(
                "DOMAIN_ALLOW_LIST_BYPASS",         94,
                "FAKE_RELATIVE_URLS",                73,
                "LOOPBACK",                          68,
                "IPV6",                               3,
                "CLOUD_METADATA_ENDPOINTS",          17,
                "URL_SPLITTING_UNICODE_CHARACTERS",  51
            );

            assertEquals(expected.size(), wordlists.size(), "expected 6 wordlist categories");
            for (Map<String, Object> wordlist : wordlists) {
                String setting = (String) wordlist.get("setting");
                List<?> payloads = (List<?>) wordlist.get("payloads");
                Integer want = expected.get(setting);
                assertTrue(want != null, "unexpected category: " + setting);
                assertEquals(
                    want.intValue(), payloads.size(),
                    setting + " drifted from upstream. Re-run scripts/sync-url-cheatsheet.py "
                        + "and bump the expected value in this test if the upstream count changed."
                );
            }
        }
    }

    @Test
    void normalizationAttackEmitsFullwidthVariantsOfAttackerAndAllowed() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate("{INJECT}", "{INJECT}", "marker", (request, newValue) -> request);
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}", "trusted.example", "attacker.example", false, "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME),
            Set.of(UrlValidationAttackSetting.NORMALIZATION_ATTACK),
            Set.of(UrlValidationEncoding.RAW),
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertFalse(payloads.isEmpty(), "expected normalization attack to emit payloads");
        // All-fullwidth attacker host should appear as an absolute URL.
        String expectedFullwidthAttacker = "\uff41\uff54\uff54\uff41\uff43\uff4b\uff45\uff52"; // "attacker" in fullwidth
        assertTrue(
            payloads.stream().anyMatch(p -> p.value().contains(expectedFullwidthAttacker)),
            "expected all-fullwidth attacker host in output"
        );
        // Hostname context should emit a bare host (no scheme).
        assertTrue(
            payloads.stream()
                .filter(p -> p.family() == UrlValidationContext.HOSTNAME)
                .anyMatch(p -> !p.value().startsWith("http")),
            "HOSTNAME payloads should be bare host, not URL-shaped"
        );
        // Subdomain-cousin shape: fullwidth-allowed dot attacker.
        assertTrue(
            payloads.stream().anyMatch(p -> p.value().contains(".attacker.example")),
            "expected fullwidth-allowed.attacker.example cousin-domain shape"
        );
    }

    @Test
    void loopbackCorsPayloadsAreNoLongerFiltered() {
        // Upstream tags loopback payloads like 127.0.0.1 and [::1] with CORS.
        // We previously dropped them via a hardcoded exclusion list; now we
        // follow upstream and emit them.
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate("{INJECT}", "{INJECT}", "marker", (request, newValue) -> request);
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}", "trusted.example", "attacker.example", false, "https",
            Set.of(UrlValidationContext.CORS_ORIGIN),
            Set.of(UrlValidationAttackSetting.LOOPBACK),
            Set.of(UrlValidationEncoding.RAW),
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        // Presence of any previously-excluded id is enough to prove the filter is gone.
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("127.0.0.1")),
            "expected a 127.0.0.1 CORS payload; got " + payloads.size() + " total");
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("localhost")),
            "expected a localhost CORS payload");
    }
}
