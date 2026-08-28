package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import com.bypassfuzzer.burp.ui.dashboard.ActivitySnapshot;
import com.bypassfuzzer.burp.ui.session.IdorPanel;
import com.bypassfuzzer.burp.ui.session.SessionResultsWorkspace;
import com.bypassfuzzer.burp.ui.session.UrlValidationPanel;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.Field;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FuzzingSessionTabTest {

    @Test
    void targetedSessionContainsOnlyItsSelectedMode() {
        FuzzingSessionTab tab = session(TargetedMode.IDOR);
        String uiText = visibleText(tab);

        assertTrue(uiText.contains("Configure Attack"));
        assertTrue(uiText.contains("Debug Info"));
        assertFalse(uiText.contains("Options..."));
        assertFalse(uiText.contains("URL validation payloads"));
    }

    @Test
    void bypassKeepsAttackTypesInlineAndMovesRunOptionsBehindButton() {
        FuzzingSessionTab tab = session(TargetedMode.BYPASS);
        String uiText = visibleText(tab);

        assertTrue(uiText.contains("Options..."));
        assertTrue(uiText.contains("Header"));
        assertTrue(uiText.contains("Check All"));
        assertFalse(uiText.contains("Throttle..."));
        assertFalse(uiText.contains("Requests/second"));
    }

    @Test
    void idorMovesIdentifiersAndRunOptionsBehindConfigureAttack() {
        FuzzingSessionTab tab = session(TargetedMode.IDOR);
        String uiText = visibleText(tab);

        assertTrue(uiText.contains("Configure Attack"));
        assertFalse(uiText.contains("Identifier 1 (authorized):"));
        assertFalse(uiText.contains("IDOR Options"));
    }

    @Test
    void everyTargetedModeExposesPauseControl() {
        for (TargetedMode mode : TargetedMode.values()) {
            assertTrue(visibleText(session(mode)).contains("Pause"), mode.title() + " should expose Pause");
        }
    }

    @Test
    void idorAndUrlValidationDoNotReportUnsentResultRowsAsHttpRequests() throws Exception {
        for (TargetedMode mode : new TargetedMode[]{TargetedMode.IDOR, TargetedMode.URL_VALIDATION}) {
            FuzzingSessionTab tab = session(mode);
            try {
                Object panel = mode == TargetedMode.IDOR
                    ? field(tab, "idorPanel", IdorPanel.class)
                    : field(tab, "urlValidationPanel", UrlValidationPanel.class);
                SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
                workspace.addResult(new AttackResult(
                    mode.title(), "synthetic unsent row", request("/users/alice", "", "GET", null, ""), null));

                ActivitySnapshot snapshot = tab.activitySnapshot();
                assertEquals(0, snapshot.sentCount(), mode.title());
                assertTrue(snapshot.progress().contains("1 result"), mode.title());
                assertTrue(snapshot.progress().contains("0 HTTP sent"), mode.title());
            } finally {
                tab.cleanup();
            }
        }
    }

    private FuzzingSessionTab session(TargetedMode mode) {
        return new FuzzingSessionTab(
            api(),
            new FuzzingSessionController(api(), request("/users/alice", "", "GET", null, "")),
            mode
        );
    }

    private MontoyaApi api() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        return api;
    }

    private <T> T field(Object target, String name, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }

    private String visibleText(Component root) {
        StringBuilder text = new StringBuilder();
        collectText(root, text);
        return text.toString();
    }

    private void collectText(Component component, StringBuilder text) {
        if (component instanceof javax.swing.JLabel label) {
            text.append(label.getText()).append('\n');
        } else if (component instanceof javax.swing.AbstractButton button) {
            text.append(button.getText()).append('\n');
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectText(child, text);
            }
        }
    }
}
