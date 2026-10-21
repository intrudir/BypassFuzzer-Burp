package com.bypassfuzzer.burp.session;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.core.http.ConfiguredHeader;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionRunOptionsTest {

    @Test
    void exposesEnabledAttackTypesAndAppliesThemToConfig() {
        SessionRunOptions options = new SessionRunOptions(
            true, false, true, false, false, true, false, true, false, true, false,
            true, false, true, 4, Set.of(429, 503)
        );

        assertEquals(Set.of(
            AttackType.HEADER,
            AttackType.VERB,
            AttackType.TRAILING_SLASH,
            AttackType.CONTENT_TYPE,
            AttackType.PROTOCOL
        ), options.enabledAttackTypes());

        FuzzerConfig config = new FuzzerConfig();
        options.applyTo(config);

        assertTrue(config.isEnableHeaderAttack());
        assertFalse(config.isEnablePathAttack());
        assertTrue(config.isEnableVerbAttack());
        assertTrue(config.isEnableTrailingSlashAttack());
        assertTrue(config.isEnableContentTypeAttack());
        assertTrue(config.isEnableProtocolAttack());
        assertTrue(config.isEnableCollaboratorPayloads());
        assertTrue(config.isEnableFuzzExistingCookies());
        assertEquals(4, config.getConcurrency());
        assertEquals(Set.of(429, 503), config.getThrottleStatusCodes());
    }

    @Test
    void appliesPerRunRequestHeadersToFuzzerConfig() {
        SessionRunOptions options = new SessionRunOptions(
            true, false, false, false, false, false, false, false, false, false, false,
            false, false, false, 1, Set.of(429),
            com.bypassfuzzer.core.throttle.ThrottleSettings.Posture.RIDE_HARD,
            java.util.List.of(new ConfiguredHeader("Authorization", "Bearer stable"))
        );
        FuzzerConfig config = new FuzzerConfig();

        options.applyTo(config);

        assertEquals(java.util.List.of(new ConfiguredHeader("Authorization", "Bearer stable")),
            config.getRequestHeaders());
    }
}
