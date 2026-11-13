package com.bypassfuzzer.burp.ui;

import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.awt.Color;
import static org.junit.jupiter.api.Assertions.*;

class WorkbenchThemeTest {
    @Test
    void staysInsideTheExtensionAndStylesNewChildren() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            Object buttonDefault = UIManager.get("Button.background");
            Object tabDefault = UIManager.get("TabbedPaneUI");
            JPanel hostEditor = new JPanel();
            hostEditor.setBackground(Color.PINK);
            JPanel root = new JPanel();
            root.add(WorkbenchTheme.nativeEditor(hostEditor));
            WorkbenchTheme.apply(root);
            JButton newSessionAction = new JButton("Preview");
            root.add(newSessionAction);
            assertEquals(WorkbenchTheme.SURFACE, root.getBackground());
            assertEquals(WorkbenchTheme.TEXT, newSessionAction.getForeground());
            assertEquals(Color.PINK, hostEditor.getBackground());
            assertSame(buttonDefault, UIManager.get("Button.background"));
            assertSame(tabDefault, UIManager.get("TabbedPaneUI"));
            int listeners = root.getContainerListeners().length;
            WorkbenchTheme.apply(root);
            assertEquals(listeners, root.getContainerListeners().length);
        });
    }
    @Test
    void candidateColumnsMatchHeadersWithoutLeakingAlignmentOrReplacingCheckboxes() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JTable table = new JTable(new javax.swing.table.DefaultTableModel(
                new Object[][]{{true, "GET", "api.test", "/admin", "Imported", "application/json"}},
                new String[]{"Run", "Method", "Host", "Path", "Status", "Content-Type"}) {
                @Override public Class<?> getColumnClass(int column) {
                    return column == 0 ? Boolean.class : String.class;
                }
            });
            WorkbenchTheme.apply(table);
            table.setAutoCreateRowSorter(true);
            table.getRowSorter().toggleSortOrder(4);
            table.setSize(1280, 160);
            table.doLayout();
            for (int column = 0; column < table.getColumnCount(); column++) {
                int expected = column == 0 || column == 1 || column == 4 ? SwingConstants.CENTER : SwingConstants.LEFT;
                var header = table.getTableHeader();
                JLabel label = (JLabel) header.getDefaultRenderer().getTableCellRendererComponent(
                    table, table.getColumnName(column), false, false, -1, column);
                assertEquals(expected, label.getHorizontalAlignment());
                if (column == 4) assertNotNull(label.getIcon(), "Keep the status sort indicator");
                var cell = table.prepareRenderer(table.getCellRenderer(0, column), 0, column);
                if (column == 0) assertInstanceOf(JCheckBox.class, cell);
                else assertEquals(expected, ((JLabel) cell).getHorizontalAlignment());
            }
            assertTrue(table.getColumn("Path").getWidth() > table.getColumn("Status").getWidth());
            assertTrue(table.getColumn("Method").getWidth() <= 100);
            assertTrue(table.getColumn("Run").getWidth() <= 60);
        });
    }
}
