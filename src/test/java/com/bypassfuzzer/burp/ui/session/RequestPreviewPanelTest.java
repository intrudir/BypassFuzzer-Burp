package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.util.List;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RequestPreviewPanelTest {
    @Test
    void sortingAndSelectingRowsShowsTheMatchingRequestInBurpEditor() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
            HttpRequestEditor editor = mock(HttpRequestEditor.class);
            when(api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)).thenReturn(editor);
            when(editor.uiComponent()).thenReturn(new JPanel());
            HttpRequest first = request("/items/zeta", "", "GET", null, "");
            HttpRequest second = request("/items/alpha", "", "GET", null, "");
            RequestPreviewPanel preview = new RequestPreviewPanel(api, List.of(
                new RequestPreviewPanel.Row("Attack", "Path", "zeta", "first", "", first),
                new RequestPreviewPanel.Row("Attack", "Path", "alpha", "second", "", second)));

            assertEquals("Payload", preview.table().getColumnName(3));
            assertEquals(2, preview.table().getRowCount());
            verify(editor).setRequest(first);
            preview.table().getRowSorter().toggleSortOrder(3);
            preview.table().setRowSelectionInterval(0, 0);
            assertEquals("alpha", preview.table().getValueAt(0, 3));
            verify(editor).setRequest(second);
        });
    }
}
