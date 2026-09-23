package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationAttackSetting;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationContext;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationOptions;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import java.util.Set;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UrlValidationRequestPreviewTest {
    @Test
    void previewRowsContainTheGeneratedRequestForEachPayload() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        var original = request("/redirect", "url={INJECT}", "GET", null, "");
        UrlValidationPanel panel = new UrlValidationPanel(api, original);
        try {
            var options = new UrlValidationOptions("{INJECT}", "trusted.test", "attacker.test",
                false, "https", Set.of(UrlValidationContext.ABSOLUTE_URL),
                Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS),
                Set.of(UrlValidationEncoding.RAW), Set.of(429, 503));
            var rows = panel.buildPreviewRows(original, options);
            assertTrue(rows.size() > 1);
            assertEquals("Baseline", rows.get(0).stage());
            assertEquals(original.path(), rows.get(0).request().path());
            assertTrue(rows.stream().skip(1).anyMatch(row -> row.request().path().contains("attacker.test")));
            assertTrue(rows.stream().skip(1).allMatch(row -> !row.payload().isBlank()));
        } finally {
            panel.cleanup();
        }
    }
}
