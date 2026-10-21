package com.bypassfuzzer.burp.ui.session;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import com.bypassfuzzer.core.http.ConfiguredHeader;
import java.util.List;

class UrlValidationOptionsPanelTest {

    @Test
    void collectsPerModeRequestHeaders() throws Exception {
        UrlValidationOptionsPanel panel = new UrlValidationOptionsPanel(
            request("/redirect", "", "GET", null, ""), false);
        Field field = UrlValidationOptionsPanel.class.getDeclaredField("requestHeadersControl");
        field.setAccessible(true);
        RequestHeadersControl control = (RequestHeadersControl) field.get(panel);
        control.setHeaders(List.of(new ConfiguredHeader("Origin", "https://trusted.test")));

        assertEquals(List.of(new ConfiguredHeader("Origin", "https://trusted.test")),
            panel.requestHeaders());
    }
}
