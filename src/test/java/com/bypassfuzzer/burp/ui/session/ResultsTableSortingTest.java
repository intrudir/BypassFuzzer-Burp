package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultFilterController;
import com.bypassfuzzer.burp.core.filter.ResultHighlighter;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ResultsTableSortingTest {
    @Test void everyHeaderClickSortsNumericAndTextColumnsIncludingAfterReordering() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (var layout : SessionResultsPanel.TableLayout.values()) {
                var panel = panel(layout);
                JTable table = table(panel);
                panel.addResults(List.of(row(403, "zulu"), row(200, "bravo"), row(500, "alpha"),
                    row(404, "echo"), row(0, "delta")), ignored -> true);
                table.moveColumn(table.getColumnModel().getColumnIndex("Status"), 1);
                for (String column : List.of("Status", "Length", "Payload", "#")) {
                    // IDOR calls its payload column Variant.
                    String name = column.equals("Payload") && layout == SessionResultsPanel.TableLayout.IDOR ? "Variant" : column;
                    for (int clicks = 1; clicks <= 4; clicks++) {
                        click(table, name, clicks);
                        int modelColumn = table.convertColumnIndexToModel(table.getColumnModel().getColumnIndex(name));
                        var key = table.getRowSorter().getSortKeys().get(0);
                        assertEquals(modelColumn, key.getColumn(), layout + " / " + name);
                        assertEquals(clicks % 2 == 1 ? SortOrder.ASCENDING : SortOrder.DESCENDING,
                            key.getSortOrder(), layout + " / " + name + " / click " + clicks);
                        assertOrdered(table, name, clicks % 2 == 0);
                    }
                }
                // A column-divider double click must keep its native resize semantics.
                List<Integer> observed = new ArrayList<>();
                table.getTableHeader().addMouseListener(new MouseAdapter() {
                    @Override public void mouseClicked(MouseEvent event) { observed.add(event.getClickCount()); }
                });
                Rectangle bounds = table.getTableHeader().getHeaderRect(1);
                dispatch(table.getTableHeader(), bounds.x + bounds.width - 1, 2);
                assertEquals(List.of(2), observed);
            }
        });
    }

    @Test void smartAndManualFiltersPreserveSortingAcrossNewResultBatches() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (var layout : SessionResultsPanel.TableLayout.values()) {
                var panel = panel(layout);
                JTable table = table(panel);
                var filters = new ResultFilterController();
                filters.filterConfig().setSmartFilterRepeats(2);
                List<AttackResult> rows = new ArrayList<>();
                for (int status : List.of(403, 200, 404))
                    for (int n = 0; n < 3; n++) rows.add(row(status, status + "-" + n));
                rows.forEach(filters::track);
                panel.addResults(rows, filters::shouldShow);
                click(table, "Status", 1);
                filters.filterConfig().setSmartFilterEnabled(true);
                panel.applyFilter(filters::shouldShow);
                assertEquals(6, table.getRowCount());
                assertOrdered(table, "Status", false);
                click(table, "Status", 2);
                assertOrdered(table, "Status", true);
                var additions = List.of(row(201, "new low"), row(503, "new high"), row(0, "unavailable"));
                additions.forEach(filters::track);
                panel.addResults(additions, filters::shouldShow);
                assertEquals(9, table.getRowCount());
                assertOrdered(table, "Status", true);
                filters.filterConfig().setManualFilterEnabled(true);
                filters.filterConfig().setHiddenStatusCodes(java.util.Set.of(403));
                panel.applyFilter(filters::shouldShow);
                assertEquals(7, table.getRowCount());
                assertOrdered(table, "Status", true);
                filters.filterConfig().setSmartFilterEnabled(false);
                panel.applyFilter(filters::shouldShow);
                assertEquals(9, table.getRowCount());
                assertOrdered(table, "Status", true);
                click(table, "Status", 3);
                assertOrdered(table, "Status", false);
                panel.clear();
                panel.addResult(row(404, "after clear"), true);
                click(table, "Status", 4);
                assertEquals(SortOrder.DESCENDING, table.getRowSorter().getSortKeys().get(0).getSortOrder());
            }
        });
    }

    @Test void allResultsLayoutsKeepMetadataCenteredAndCompactAfterResizeAndReordering() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (var layout : SessionResultsPanel.TableLayout.values()) {
                var panel = panel(layout);
                JTable table = table(panel);
                panel.addResults(List.of(row(200, "payload"), row(0, "unavailable")), ignored -> true);
                for (int width : List.of(1280, 1700)) {
                    table.setSize(width, 200);
                    table.doLayout();
                    for (String name : List.of("#", "Status", "Length")) {
                        int col = table.getColumnModel().getColumnIndex(name);
                        assertTrue(table.getColumnModel().getColumn(col).getWidth() < 160, layout + " / " + name);
                        for (int row = 0; row < table.getRowCount(); row++) {
                            JLabel cell = (JLabel) table.prepareRenderer(table.getCellRenderer(row, col), row, col);
                            assertEquals(SwingConstants.CENTER, cell.getHorizontalAlignment(), layout + " / " + name);
                            assertTrue(cell.getPreferredSize().width <= table.getColumnModel().getColumn(col).getWidth(),
                                "Metadata should fit without truncation: " + cell.getText());
                        }
                        var header = table.getTableHeader();
                        JLabel label = (JLabel) header.getDefaultRenderer().getTableCellRendererComponent(
                            table, name, false, false, -1, col);
                        assertEquals(SwingConstants.CENTER, label.getHorizontalAlignment());
                    }
                }
                table.moveColumn(table.getColumnModel().getColumnIndex("Status"), 1);
                click(table, "Status", 1);
                for (int col = 0; col < table.getColumnCount(); col++) {
                    String name = table.getColumnName(col);
                    int expected = List.of("#", "Status", "Length", "Group").contains(name)
                        ? SwingConstants.CENTER : SwingConstants.LEFT;
                    JLabel cell = (JLabel) table.prepareRenderer(table.getCellRenderer(0, col), 0, col);
                    assertEquals(expected, cell.getHorizontalAlignment(), layout + " / moved " + name);
                    if (layout == SessionResultsPanel.TableLayout.IDOR && name.equals("Playbook"))
                        assertEquals(Font.MONOSPACED, cell.getFont().getFamily());
                }
            }
        });
    }

    @Test void filteringPreservesExplicitUnsortedInsertionOrder() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = panel(SessionResultsPanel.TableLayout.DEFAULT);
            JTable table = table(panel);
            panel.addResults(List.of(row(403, "first"), row(200, "second"), row(404, "third")), ignored -> true);
            table.getRowSorter().setSortKeys(List.of());
            panel.applyFilter(result -> result.getStatusCode() != 200);
            assertTrue(table.getRowSorter().getSortKeys().isEmpty());
            assertEquals(1, table.getValueAt(0, 0));
            assertEquals(3, table.getValueAt(1, 0));
        });
    }

    private static SessionResultsPanel panel(SessionResultsPanel.TableLayout layout) {
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        when(api.userInterface().createHttpRequestEditor()).thenAnswer(invocation -> {
            var editor = mock(HttpRequestEditor.class);
            when(editor.uiComponent()).thenReturn(new JPanel());
            return editor;
        });
        when(api.userInterface().createHttpResponseEditor()).thenAnswer(invocation -> {
            var editor = mock(HttpResponseEditor.class);
            when(editor.uiComponent()).thenReturn(new JPanel());
            return editor;
        });
        return new SessionResultsPanel(api, new ResultHighlighter(), () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE, layout);
    }

    private static AttackResult row(int status, String payload) {
        HttpResponse response = status == 0 ? null : mock(HttpResponse.class);
        if (response != null) {
            var body = mock(ByteArray.class);
            when(body.length()).thenReturn(status % 7);
            when(response.body()).thenReturn(body);
            when(response.statusCode()).thenReturn((short) status);
            when(response.headers()).thenReturn(List.of());
        }
        return new AttackResult("Bypass", payload, null, response);
    }

    private static JTable table(Container root) {
        for (Component child : root.getComponents()) {
            if (child instanceof JTable found) return found;
            if (child instanceof Container container) {
                JTable found = table(container);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static void click(JTable table, String column, int count) {
        JTableHeader header = table.getTableHeader();
        header.setSize(1600, 34);
        Rectangle bounds = header.getHeaderRect(table.getColumnModel().getColumnIndex(column));
        dispatch(header, bounds.x + bounds.width / 2, count);
    }

    private static void dispatch(JTableHeader header, int x, int count) {
        header.dispatchEvent(new MouseEvent(header, MouseEvent.MOUSE_CLICKED, System.currentTimeMillis(),
            0, x, 17, 0, 0, count, false, MouseEvent.BUTTON1));
    }

    private static void assertOrdered(JTable table, String name, boolean descending) {
        int column = table.getColumnModel().getColumnIndex(name);
        List<Object> values = new ArrayList<>();
        for (int row = 0; row < table.getRowCount(); row++) values.add(table.getValueAt(row, column));
        List<Object> expected = new ArrayList<>(values);
        Comparator<Object> compare = name.equals("Status") || name.equals("Length") || name.equals("#")
            ? Comparator.comparingInt(value -> value instanceof Number number ? number.intValue() : 0)
            : Comparator.comparing(Object::toString);
        expected.sort(descending ? compare.reversed() : compare);
        assertEquals(expected, values, name + " must be sorted " + (descending ? "descending" : "ascending"));
    }
}
