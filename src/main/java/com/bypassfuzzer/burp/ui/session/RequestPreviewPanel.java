package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.util.List;

/** Common table-to-native-editor preview for generated attack requests. */
public final class RequestPreviewPanel extends JPanel {
    public record Row(String stage, String family, String payload, String variant,
                      String encoding, HttpRequest request) {
        public Row {
            if (request == null) throw new IllegalArgumentException("Preview request is required");
            stage = safe(stage);
            family = safe(family);
            payload = safe(payload);
            variant = safe(variant);
            encoding = safe(encoding);
        }
    }

    private static final String[] COLUMNS =
        {"#", "Stage", "Family", "Payload", "Variant", "Encoding", "Method", "Path"};

    private final List<Row> rows;
    private final JTable table;
    private final HttpRequestEditor editor;

    public RequestPreviewPanel(MontoyaApi api, List<Row> rows) {
        super(new BorderLayout(0, 6));
        this.rows = List.copyOf(rows);
        this.editor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.table = new JTable(new PreviewTableModel());
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {52, 100, 190, 270, 220, 100, 80, 280};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (event.getValueIsAdjusting()) return;
            int selected = table.getSelectedRow();
            editor.setRequest(selected < 0 ? null : this.rows.get(table.convertRowIndexToModel(selected)).request());
        });

        JScrollPane list = new JScrollPane(table);
        list.setBorder(BorderFactory.createTitledBorder("Planned requests"));
        JPanel message = new JPanel(new BorderLayout());
        message.setBorder(BorderFactory.createTitledBorder("Selected request"));
        message.add(editor.uiComponent(), BorderLayout.CENTER);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, list, message);
        split.setResizeWeight(0.42);
        split.setDividerLocation(290);
        add(split, BorderLayout.CENTER);
        setPreferredSize(new Dimension(1100, 690));
        if (!this.rows.isEmpty()) table.setRowSelectionInterval(0, 0);
    }

    public static JDialog open(MontoyaApi api, Component parent, String title,
                               String summary, List<Row> rows) {
        Window owner = SwingUtilities.getWindowAncestor(parent);
        if (owner == null) owner = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(owner, title, Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        JPanel content = new JPanel(new BorderLayout(0, 6));
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        JTextArea heading = new JTextArea(summary == null || summary.isBlank()
            ? rows.size() + " planned request(s)" : summary);
        heading.setEditable(false);
        heading.setOpaque(false);
        heading.setLineWrap(true);
        heading.setWrapStyleWord(true);
        content.add(heading, BorderLayout.NORTH);
        content.add(new RequestPreviewPanel(api, rows), BorderLayout.CENTER);
        JButton close = new JButton("Close");
        close.addActionListener(event -> dialog.dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(close);
        content.add(buttons, BorderLayout.SOUTH);
        dialog.setContentPane(content);
        dialog.pack();
        dialog.setMinimumSize(new Dimension(850, 560));
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
        return dialog;
    }

    JTable table() { return table; }

    private final class PreviewTableModel extends AbstractTableModel {
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }
        @Override public Class<?> getColumnClass(int column) { return column == 0 ? Integer.class : String.class; }
        @Override public Object getValueAt(int row, int column) {
            Row item = rows.get(row);
            return switch (column) {
                case 0 -> row + 1;
                case 1 -> display(item.stage());
                case 2 -> display(item.family());
                case 3 -> display(item.payload());
                case 4 -> display(item.variant());
                case 5 -> display(item.encoding());
                case 6 -> item.request().method();
                case 7 -> item.request().path();
                default -> "";
            };
        }
    }

    private static String safe(String value) { return value == null ? "" : value; }
    private static String display(String value) {
        return value.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
