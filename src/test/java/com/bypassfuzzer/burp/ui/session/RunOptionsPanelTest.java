package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.core.http.ConfiguredHeader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RunOptionsPanelTest {

    @Test
    void collaboratorHeaderPayloadsAreSelectedByDefaultWhenAvailable() {
        RunOptionsPanel panel = new RunOptionsPanel(new FuzzerConfig(), true);

        assertTrue(panel.isCollaboratorEnabled());
    }

    @Test
    void collaboratorHeaderPayloadsRemainDisabledWhenUnavailable() {
        RunOptionsPanel panel = new RunOptionsPanel(new FuzzerConfig(), false);

        assertFalse(panel.isCollaboratorEnabled());
    }

    @Test
    void requestHeadersAreScopedToThisOptionsPanel() {
        FuzzerConfig configured = new FuzzerConfig();
        configured.setRequestHeaders(java.util.List.of(new ConfiguredHeader("Authorization", "Bearer stable")));

        RunOptionsPanel first = new RunOptionsPanel(configured, true);
        RunOptionsPanel second = new RunOptionsPanel(new FuzzerConfig(), true);

        assertEquals(java.util.List.of(new ConfiguredHeader("Authorization", "Bearer stable")),
            first.requestHeaders());
        assertTrue(second.requestHeaders().isEmpty());
    }
}
