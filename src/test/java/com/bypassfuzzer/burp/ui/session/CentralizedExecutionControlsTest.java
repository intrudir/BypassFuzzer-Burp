package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.http.UserAgentMode;
import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JTextField;
import java.lang.reflect.Field;
import java.util.Set;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CentralizedExecutionControlsTest {

    @Test
    void bypassIdorAndUrlValidationExposeTheSameHeaderAndThrottleControls() throws Exception {
        RunOptionsPanel bypass = new RunOptionsPanel(new FuzzerConfig(), false);
        IdorRunOptionsPanel idor = new IdorRunOptionsPanel(new IdorRunOptions(Set.of(429, 503)));
        UrlValidationOptionsPanel url = new UrlValidationOptionsPanel(
            request("/redirect", "", "GET", null, ""), false);

        assertCompleteControls(bypass);
        assertCompleteControls(idor);
        assertCompleteControls(url);
    }

    @Test
    void userAgentSelectionFlowsThroughEveryModeOptionsBoundary() throws Exception {
        RunOptionsPanel bypass = new RunOptionsPanel(new FuzzerConfig(), false);
        RequestHeadersControl bypassHeaders = field(bypass, "requestHeadersControl", RequestHeadersControl.class);
        bypassHeaders.setUserAgentMode(UserAgentMode.SYNTHETIC);
        assertEquals(UserAgentMode.SYNTHETIC, bypass.userAgentMode());
        assertTrue(bypass.userAgentRandomizationSeed() != 0L);

        IdorRunOptionsPanel idor = new IdorRunOptionsPanel(new IdorRunOptions(Set.of(429)));
        RequestHeadersControl idorHeaders = field(idor, "requestHeadersControl", RequestHeadersControl.class);
        idorHeaders.setUserAgentMode(UserAgentMode.BROWSER_LIKE);
        assertEquals(UserAgentMode.BROWSER_LIKE, idor.collect().userAgentMode());
        assertTrue(idor.collect().userAgentRandomizationSeed() != 0L);

        UrlValidationOptionsPanel url = new UrlValidationOptionsPanel(
            request("/redirect", "", "GET", null, ""), false);
        RequestHeadersControl urlHeaders = field(url, "requestHeadersControl", RequestHeadersControl.class);
        urlHeaders.setUserAgentMode(UserAgentMode.SYNTHETIC);
        assertEquals(UserAgentMode.SYNTHETIC, url.userAgentMode());
        assertTrue(url.userAgentRandomizationSeed() != 0L);
    }

    private void assertCompleteControls(Object panel) throws Exception {
        RequestHeadersControl headers = field(panel, "requestHeadersControl", RequestHeadersControl.class);
        ThrottleSettingsControl throttle = field(panel, "throttleControl", ThrottleSettingsControl.class);

        assertNotNull(field(headers, "userAgentRandomizationCheckBox", JCheckBox.class));
        assertNotNull(field(throttle, "concurrencyField", JTextField.class));
        assertNotNull(field(throttle, "perHostConcurrencyField", JTextField.class));
        assertTrue(field(throttle, "showGlobalPause", Boolean.class));
    }

    private <T> T field(Object target, String name, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }
}
