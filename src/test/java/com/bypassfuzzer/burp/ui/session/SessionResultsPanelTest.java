package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultHighlighter;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.RowSorter;
import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionResultsPanelTest {

    @Test
    void shortResultsWorkspaceReservesReadableNativeEditorSpace() throws Exception {
        SessionResultsPanel[] panels = new SessionResultsPanel[1];
        SwingUtilities.invokeAndWait(() -> {
            panels[0] = new SessionResultsPanel(api(), new ResultHighlighter(), () -> { },
                SessionResultsPanel.ViewerLayout.BELOW_TABLE,
                SessionResultsPanel.TableLayout.URL_VALIDATION);
            // Burp constructs inactive tabs before their final visible layout.
            panels[0].setSize(1200, 60);
            panels[0].doLayout();
        });
        SwingUtilities.invokeAndWait(() -> {
            panels[0].setSize(1200, 430);
            panels[0].doLayout();
            panels[0].addNotify();
        });
        SwingUtilities.invokeAndWait(() -> { });
        SwingUtilities.invokeAndWait(() -> {
            SessionResultsPanel panel = panels[0];
            JSplitPane split = (JSplitPane) panel.getComponent(0);
            split.doLayout();
            assertTrue(split.getBottomComponent().getHeight() >= 320,
                "Native message toolbars must leave room to read the message");
            assertTrue(split.getTopComponent().getHeight() >= 70,
                "Result rows must remain visible alongside the message");
            // Subsequent user choices survive resize events.
            split.setDividerLocation(130);
            split.setSize(1200, 480);
            split.doLayout();
            assertTrue(split.getDividerLocation() >= 130);
            panel.removeNotify();
        });
    }

    @Test
    void urlValidationTableSortsStringMetadataColumnsWithoutTypeErrors() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.URL_VALIDATION
        );

        panel.addResult(new AttackResult("URL Validation", "payload-1", "target", "family", "Zulu", null, null), true);
        panel.addResult(new AttackResult("URL Validation", "payload-2", "target", "family", "Alpha", null, null), true);

        JTable table = resultsTable(panel);
        RowSorter<?> sorter = table.getRowSorter();

        assertDoesNotThrow(() -> sorter.toggleSortOrder(3));
        assertEquals("Alpha", table.getValueAt(0, 3));
        assertEquals("Zulu", table.getValueAt(1, 3));
    }

    @Test
    void coverageSweepTableLabelsInterestingMarkerAsSignal() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.COVERAGE_SWEEP
        );

        panel.addResult(new AttackResult("Coverage Sweep", "payload", "target", "family", "403 -> 200", null, null), true);

        JTable table = resultsTable(panel);

        assertEquals("Signal", table.getColumnName(4));
        assertEquals("403 -> 200", table.getValueAt(0, 4));
        assertEquals("No response", table.getValueAt(0, 5));
        JTabbedPane viewerTabs = findTabbedPane(panel);
        assertEquals(2, viewerTabs.getTabCount());
        assertEquals("Probe", viewerTabs.getTitleAt(0));
        assertEquals("Original", viewerTabs.getTitleAt(1));

        panel.setAuthVerificationTabsVisible(true);
        assertEquals(3, viewerTabs.getTabCount());
        assertEquals("Auth verification", viewerTabs.getTitleAt(2));

        panel.setAuthVerificationTabsVisible(false);
        assertEquals(2, viewerTabs.getTabCount());
    }

    @Test
    void coverageSweepSelectionShowsOriginalRequestAndResponse() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.COVERAGE_SWEEP
        );
        HttpRequest request = mock(HttpRequest.class);
        HttpRequest originalRequest = mock(HttpRequest.class);
        HttpResponse originalResponse = mock(HttpResponse.class);
        HttpRequest verificationRequest = mock(HttpRequest.class);
        HttpResponse verificationResponse = mock(HttpResponse.class);
        panel.addResult(new AttackResult(
            "Coverage Sweep",
            "payload",
            "target",
            "family",
            "",
            request,
            null,
            originalRequest,
            originalResponse,
            verificationRequest,
            verificationResponse
        ), true);

        resultsTable(panel).setRowSelectionInterval(0, 0);

        verify(field(panel, "originalRequestViewer", HttpRequestEditor.class)).setRequest(originalRequest);
        verify(field(panel, "originalResponseViewer", HttpResponseEditor.class)).setResponse(originalResponse);
        verify(field(panel, "verificationRequestViewer", HttpRequestEditor.class)).setRequest(verificationRequest);
        verify(field(panel, "verificationResponseViewer", HttpResponseEditor.class)).setResponse(verificationResponse);
    }


    @Test
    void idorTableSortsStringMetadataColumnsWithoutTypeErrors() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.IDOR
        );

        panel.addResult(new AttackResult(
            "IDOR",
            "variant-1",
            "Zulu Group",
            "idor.hybrid.zulu",
            null,
            null,
            null
        ), true);
        panel.addResult(new AttackResult(
            "IDOR",
            "variant-2",
            "Alpha Group",
            "idor.hybrid.alpha",
            null,
            null,
            null
        ), true);

        JTable table = resultsTable(panel);
        RowSorter<?> sorter = table.getRowSorter();

        assertDoesNotThrow(() -> sorter.toggleSortOrder(1));
        assertEquals("Alpha Group", table.getValueAt(0, 1));
        assertEquals("Zulu Group", table.getValueAt(1, 1));
    }

    @Test
    void idorGroupCellUsesBadgeStylingForControlAndBaseline() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.IDOR
        );

        panel.addResult(new AttackResult("IDOR", "control", "Control", "idor.baseline.control", null, null, null), true);
        panel.addResult(new AttackResult("IDOR", "baseline", "Baseline", "idor.baseline.target", null, null, null), true);

        JTable table = resultsTable(panel);
        Component controlCell = table.prepareRenderer(table.getCellRenderer(0, 1), 0, 1);
        Component baselineCell = table.prepareRenderer(table.getCellRenderer(1, 1), 1, 1);

        assertNotEquals(table.getBackground(), controlCell.getBackground());
        assertNotEquals(table.getBackground(), baselineCell.getBackground());
    }

    private MontoyaApi api() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpRequestEditor originalRequestEditor = mock(HttpRequestEditor.class);
        HttpRequestEditor verificationRequestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        HttpResponseEditor originalResponseEditor = mock(HttpResponseEditor.class);
        HttpResponseEditor verificationResponseEditor = mock(HttpResponseEditor.class);

        when(api.userInterface().createHttpRequestEditor()).thenReturn(
            requestEditor, originalRequestEditor, verificationRequestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(
            responseEditor, originalResponseEditor, verificationResponseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(originalRequestEditor.uiComponent()).thenReturn(new JPanel());
        when(verificationRequestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        when(originalResponseEditor.uiComponent()).thenReturn(new JPanel());
        when(verificationResponseEditor.uiComponent()).thenReturn(new JPanel());

        return api;
    }

    private JTable resultsTable(SessionResultsPanel panel) throws Exception {
        return field(panel, "resultsTable", JTable.class);
    }

    private <T> T field(SessionResultsPanel panel, String name, Class<T> type) throws Exception {
        Field field = SessionResultsPanel.class.getDeclaredField(name);
        field.setAccessible(true);
        return type.cast(field.get(panel));
    }

    private JTabbedPane findTabbedPane(Container container) {
        for (Component component : container.getComponents()) {
            if (component instanceof JTabbedPane tabbedPane) {
                return tabbedPane;
            }
            if (component instanceof Container child) {
                JTabbedPane nested = findTabbedPane(child);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }
}
