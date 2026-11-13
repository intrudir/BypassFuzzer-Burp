package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultHighlighter;
import com.bypassfuzzer.burp.ui.FuzzerResultsTableModel;

import com.bypassfuzzer.burp.ui.WorkbenchTheme;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;

/**
 * Owns the results table, highlight popup, and Burp request/response viewers.
 */
public class SessionResultsPanel extends JPanel {

    private static final Color IDOR_CONTROL_BADGE = new Color(46, 86, 132);
    private static final Color IDOR_BASELINE_BADGE = new Color(122, 88, 32);
    private static final Color IDOR_SUCCESS = new Color(108, 214, 152);
    private static final Color IDOR_REDIRECT = new Color(104, 182, 255);
    private static final Color IDOR_CLIENT_ERROR = new Color(236, 183, 79);
    private static final Color IDOR_SERVER_ERROR = new Color(229, 116, 116);
    private static final Color IDOR_PLAYBOOK = new Color(190, 214, 255);

    public enum ViewerLayout {
        BELOW_TABLE,
        RIGHT_OF_TABLE
    }

    public enum TableLayout {
        DEFAULT,
        IDOR,
        URL_VALIDATION,
        COVERAGE_SWEEP
    }

    private final ResultHighlighter highlighter;
    private final Runnable filterRefreshListener;
    private final FuzzerResultsTableModel tableModel;
    private final JTable resultsTable;
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private final HttpRequestEditor originalRequestViewer;
    private final HttpResponseEditor originalResponseViewer;
    private final HttpRequestEditor fallbackRequestViewer;
    private final HttpResponseEditor fallbackResponseViewer;
    private final HttpRequestEditor verificationRequestViewer;
    private final HttpResponseEditor verificationResponseViewer;
    private JTabbedPane viewerTabs;
    private JPopupMenu tablePopupMenu;
    private AttackResult displayedResult;

    private final ViewerLayout viewerLayout;
    private final TableLayout tableLayout;

    public SessionResultsPanel(MontoyaApi api, ResultHighlighter highlighter, Runnable filterRefreshListener) {
        this(api, highlighter, filterRefreshListener, ViewerLayout.BELOW_TABLE, TableLayout.DEFAULT);
    }

    public SessionResultsPanel(MontoyaApi api, ResultHighlighter highlighter, Runnable filterRefreshListener, ViewerLayout viewerLayout) {
        this(api, highlighter, filterRefreshListener, viewerLayout, TableLayout.DEFAULT);
    }

    public SessionResultsPanel(MontoyaApi api, ResultHighlighter highlighter, Runnable filterRefreshListener,
                               ViewerLayout viewerLayout, TableLayout tableLayout) {
        super(new BorderLayout());
        this.highlighter = highlighter;
        this.filterRefreshListener = filterRefreshListener;
        this.viewerLayout = viewerLayout == null ? ViewerLayout.BELOW_TABLE : viewerLayout;
        this.tableLayout = tableLayout == null ? TableLayout.DEFAULT : tableLayout;
        this.tableModel = new FuzzerResultsTableModel(toModelLayout(this.tableLayout));
        this.resultsTable = new JTable(tableModel) {
            @Override public boolean getScrollableTracksViewportWidth() {
                return getParent() == null || getParent().getWidth() >= getMinimumSize().width;
            }
        };
        this.resultsTable.setTableHeader(new ResultsTableHeader(this.resultsTable.getColumnModel()));
        this.fallbackRequestViewer = api.userInterface().createHttpRequestEditor();
        this.fallbackResponseViewer = api.userInterface().createHttpResponseEditor();
        this.requestViewer = api.userInterface().createHttpRequestEditor();
        this.responseViewer = api.userInterface().createHttpResponseEditor();
        this.originalRequestViewer = this.tableLayout == TableLayout.COVERAGE_SWEEP
            ? api.userInterface().createHttpRequestEditor() : null;
        this.originalResponseViewer = this.tableLayout == TableLayout.COVERAGE_SWEEP
            ? api.userInterface().createHttpResponseEditor() : null;
        this.verificationRequestViewer = this.tableLayout == TableLayout.COVERAGE_SWEEP
            ? api.userInterface().createHttpRequestEditor() : null;
        this.verificationResponseViewer = this.tableLayout == TableLayout.COVERAGE_SWEEP
            ? api.userInterface().createHttpResponseEditor() : null;
        initializeUi();
        WorkbenchTheme.apply(this);
    }

    public void addResult(AttackResult result, boolean passesFilter) {
        tableModel.addResult(result, passesFilter);
    }

    public void addResults(List<AttackResult> results, Predicate<AttackResult> filter) {
        tableModel.addResults(results, filter);
    }

    public void applyFilter(Predicate<AttackResult> filter) {
        // The model sends a data-change event; the existing sorter reapplies its current keys.
        tableModel.applyFilter(filter);
        resultsTable.repaint();
    }

    public void clear() {
        tableModel.clear();
        displayedResult = null;
        fallbackRequestViewer.setRequest(null); fallbackResponseViewer.setResponse(null);
        int fallback = viewerTabs.indexOfTab("Fallback control"); if (fallback >= 0) viewerTabs.removeTabAt(fallback);
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
        if (originalRequestViewer != null) {
            originalRequestViewer.setRequest(null);
        }
        if (originalResponseViewer != null) {
            originalResponseViewer.setResponse(null);
        }
        if (verificationRequestViewer != null) {
            verificationRequestViewer.setRequest(null);
        }
        if (verificationResponseViewer != null) {
            verificationResponseViewer.setResponse(null);
        }
    }

    public int shownResultsCount() {
        return tableModel.getRowCount();
    }

    public int allResultsCount() {
        return tableModel.getAllResultsCount();
    }

    public List<AttackResult> allResults() {
        return tableModel.getAllResults();
    }

    public String visibleRowsAsTsv() {
        StringBuilder sb = new StringBuilder(Math.max(256, resultsTable.getRowCount() * 96));
        appendHeader(sb);
        for (int viewRow = 0; viewRow < resultsTable.getRowCount(); viewRow++) {
            appendRow(sb, viewRow);
        }
        return sb.toString();
    }

    private void initializeUi() {
        resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        initializeRowSorter();
        configureRenderer();
        configureSelection();
        createTablePopupMenu();
        configurePopupHandling();
        configureCopyAction();
        configureColumns();

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);

        viewerTabs = new JTabbedPane();
        viewerTabs.addTab("Probe", exchange(requestViewer.uiComponent(), responseViewer.uiComponent()));
        if (originalRequestViewer != null && originalResponseViewer != null) {
            viewerTabs.addTab("Original", exchange(originalRequestViewer.uiComponent(), originalResponseViewer.uiComponent()));
        }

        int splitOrientation = viewerLayout == ViewerLayout.RIGHT_OF_TABLE
            ? JSplitPane.HORIZONTAL_SPLIT
            : JSplitPane.VERTICAL_SPLIT;
        tableScrollPane.setMinimumSize(new java.awt.Dimension(120, 90));
        JSplitPane splitPane = new JSplitPane(splitOrientation, tableScrollPane, viewerTabs);
        splitPane.setResizeWeight(viewerLayout == ViewerLayout.RIGHT_OF_TABLE ? 0.52 : 0.4);
        // Native Burp editors include tab/search toolbars. Initialize after layout,
        // then keep both the results and viewers usable after resize or tab changes.
        class WorkspaceDivider extends ComponentAdapter implements HierarchyListener {
            private boolean initialized;

            private void positionAfterLayout() {
                SwingUtilities.invokeLater(() -> {
                    if (!splitPane.isShowing() || splitPane.getWidth() <= 0 || splitPane.getHeight() <= 0) return;
                    if (viewerLayout == ViewerLayout.RIGHT_OF_TABLE) {
                        if (!initialized) splitPane.setDividerLocation(0.52);
                    } else {
                        int available = Math.max(0, splitPane.getHeight() - splitPane.getDividerSize());
                        int minimumTable = Math.min(90, available / 3);
                        int minimumViewer = Math.min(240, available - minimumTable);
                        int desired = initialized ? splitPane.getDividerLocation()
                            : Math.max(minimumTable, Math.min((int) (available * 0.4), available - 320));
                        int bounded = Math.max(minimumTable, Math.min(desired, available - minimumViewer));
                        if (bounded != splitPane.getDividerLocation()) splitPane.setDividerLocation(bounded);
                    }
                    initialized = true;
                });
            }

            @Override public void componentResized(ComponentEvent event) { positionAfterLayout(); }
            @Override public void hierarchyChanged(HierarchyEvent event) {
                if ((event.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0) positionAfterLayout();
            }
        }
        WorkspaceDivider divider = new WorkspaceDivider();
        splitPane.addComponentListener(divider);
        splitPane.addHierarchyListener(divider);
        add(splitPane, BorderLayout.CENTER);
    }

    /** Shows authentication verification exchanges only for authenticated-traffic sweeps. */
    public void setAuthVerificationTabsVisible(boolean visible) {
        if (viewerTabs == null || verificationRequestViewer == null || verificationResponseViewer == null) {
            return;
        }

        int existing = viewerTabs.indexOfTab("Auth verification");
        if (visible == (existing >= 0)) return;
        if (visible) {
            viewerTabs.addTab("Auth verification", exchange(
                verificationRequestViewer.uiComponent(), verificationResponseViewer.uiComponent()));
        } else {
            viewerTabs.removeTabAt(existing);
        }
        viewerTabs.revalidate();
        viewerTabs.repaint();
    }

    private JPanel exchange(Component request, Component response) {
        JPanel requestPanel = new JPanel(new BorderLayout(0, 8));
        requestPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 12, 10, 8));
        requestPanel.add(WorkbenchTheme.muted("Request"), BorderLayout.NORTH);
        requestPanel.add(WorkbenchTheme.nativeEditor(request), BorderLayout.CENTER);
        JPanel responsePanel = new JPanel(new BorderLayout(0, 8));
        responsePanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 12, 10, 8));
        responsePanel.add(WorkbenchTheme.muted("Response"), BorderLayout.NORTH);
        responsePanel.add(WorkbenchTheme.nativeEditor(response), BorderLayout.CENTER);
        requestPanel.setMinimumSize(new java.awt.Dimension(120, 160));
        responsePanel.setMinimumSize(new java.awt.Dimension(120, 160));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        split.setResizeWeight(0.5);
        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.5));
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private void configureRenderer() {
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                setHorizontalAlignment(SwingConstants.LEFT);
                setFont(table.getFont());

                AttackResult result = tableModel.getResult(table.convertRowIndexToModel(row));
                if (!isSelected) {
                    Color rowColor = result == null ? null : highlighter.colorFor(result);
                    component.setBackground(rowColor != null ? rowColor : table.getBackground());
                    component.setForeground(rowColor != null ? WorkbenchTheme.EDITOR : table.getForeground());
                }

                if (tableLayout == TableLayout.IDOR && result != null) {
                    applyIdorCellStyling(table, component, value, table.convertColumnIndexToModel(column), isSelected, result);
                } else {
                    String name = table.getColumnName(column);
                    if (name.equals("Payload")) setFont(WorkbenchTheme.MONO);
                    if (name.equals("Status") && result != null) {
                        if (result.getResponse() == null) setForeground(WorkbenchTheme.WARNING);
                        else if (result.getStatusCode() >= 200 && result.getStatusCode() < 300)
                            setForeground(WorkbenchTheme.POSITIVE);
                    }
                }
                setBorder(javax.swing.BorderFactory.createCompoundBorder(
                    javax.swing.BorderFactory.createMatteBorder(0, isSelected && column == 0 ? 3 : 0, 0, 0,
                        WorkbenchTheme.ACCENT), javax.swing.BorderFactory.createEmptyBorder(0, 8, 0, 8)));
                setToolTipText(result == null ? null : result.getTargetLabel() + " | " + result.getEvidenceMetadata().playbookId()
                    + " | " + result.getEvidenceMetadata().annotation());
                return component;
            }
        };
        resultsTable.setDefaultRenderer(Object.class, renderer);
        resultsTable.setDefaultRenderer(Integer.class, renderer);
    }

    private void applyIdorCellStyling(JTable table,
                                      Component component,
                                      Object value,
                                      int column,
                                      boolean isSelected,
                                      AttackResult result) {
        if (!(component instanceof DefaultTableCellRenderer renderer)) {
            return;
        }

        if (column == 1) {
            renderer.setHorizontalAlignment(SwingConstants.CENTER);
            renderer.setFont(table.getFont().deriveFont(Font.BOLD));

            if (!isSelected) {
                String group = result.getTargetLabel();
                if ("Control".equals(group)) {
                    component.setBackground(IDOR_CONTROL_BADGE);
                } else if ("Baseline".equals(group)) {
                    component.setBackground(IDOR_BASELINE_BADGE);
                }
            }
            return;
        }

        if (column == 2) {
            renderer.setFont(new Font(Font.MONOSPACED, table.getFont().getStyle(), table.getFont().getSize() - 1));
            if (!isSelected) {
                component.setForeground(IDOR_PLAYBOOK);
            }
            return;
        }

        if (column == 4) {
            renderer.setHorizontalAlignment(SwingConstants.CENTER);
            renderer.setFont(table.getFont().deriveFont(Font.BOLD));
            if (!isSelected && value instanceof Integer status) {
                component.setForeground(statusColor(status));
            }
            return;
        }
    }

    private Color statusColor(int status) {
        if (status >= 200 && status < 300) {
            return IDOR_SUCCESS;
        }
        if (status >= 300 && status < 400) {
            return IDOR_REDIRECT;
        }
        if (status >= 400 && status < 500) {
            return IDOR_CLIENT_ERROR;
        }
        if (status >= 500) {
            return IDOR_SERVER_ERROR;
        }
        return resultsTable.getForeground();
    }

    private void configureSelection() {
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0) {
                    showResultDetails(resultsTable.convertRowIndexToModel(selectedRow));
                }
            }
        });
    }

    private void configureColumns() {
        // WorkbenchTheme owns compact metadata columns across every tab.
        int[] widths = switch (tableLayout) {
            case COVERAGE_SWEEP -> new int[]{0, 250, 180, 140, 180, 0, 0, 160};
            case URL_VALIDATION -> new int[]{0, 120, 90, 90, 280, 0, 0, 130};
            case IDOR -> new int[]{0, 0, 210, 420, 0, 0, 170};
            case DEFAULT -> new int[]{0, 140, 420, 0, 0, 220};
        };
        for (int column = 0; column < widths.length; column++) {
            if (widths[column] == 0) continue;
            String name = resultsTable.getColumnName(column);
            int minimum = switch (name) {
                case "Payload", "Variant", "Playbook" -> 180;
                default -> 100;
            };
            resultsTable.getColumnModel().getColumn(column).setMinWidth(minimum);
            resultsTable.getColumnModel().getColumn(column).setPreferredWidth(widths[column]);
        }
    }

    private void initializeRowSorter() {
        TableRowSorter<FuzzerResultsTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setComparator(0, Comparator.comparingInt(o -> (Integer) o));
        if (tableLayout == TableLayout.URL_VALIDATION) {
            sorter.setComparator(5, Comparator.comparingInt(o -> (Integer) o));
            sorter.setComparator(6, Comparator.comparingInt(o -> (Integer) o));
        } else if (tableLayout == TableLayout.COVERAGE_SWEEP) {
            sorter.setComparator(5, Comparator.comparingInt(this::statusSortValue));
            sorter.setComparator(6, Comparator.comparingInt(o -> (Integer) o));
        } else if (tableLayout == TableLayout.IDOR) {
            sorter.setComparator(4, Comparator.comparingInt(o -> (Integer) o));
            sorter.setComparator(5, Comparator.comparingInt(o -> (Integer) o));
        } else {
            sorter.setComparator(3, Comparator.comparingInt(o -> (Integer) o));
            sorter.setComparator(4, Comparator.comparingInt(o -> (Integer) o));
        }
        sorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
        resultsTable.setRowSorter(sorter);
    }

    private void showResultDetails(int modelRow) {
        AttackResult result = tableModel.getResult(modelRow);
        if (result == null) {
            return;
        }

        if (result == displayedResult) {
            return;
        }
        displayedResult = result;

        int fallbackTab = viewerTabs.indexOfTab("Fallback control");
        boolean hasFallback = result.getEvidenceMetadata().fallbackRequest() != null;
        if (hasFallback && fallbackTab < 0) viewerTabs.addTab("Fallback control", exchange(fallbackRequestViewer.uiComponent(), fallbackResponseViewer.uiComponent()));
        if (!hasFallback && fallbackTab >= 0) viewerTabs.removeTabAt(fallbackTab);
        fallbackRequestViewer.setRequest(result.getEvidenceMetadata().fallbackRequest());
        fallbackResponseViewer.setResponse(result.getEvidenceMetadata().fallbackResponse());
        requestViewer.setRequest(result.getRequest());
        responseViewer.setResponse(result.getResponse());
        if (originalRequestViewer != null) {
            originalRequestViewer.setRequest(result.getOriginalRequest());
        }
        if (originalResponseViewer != null) {
            originalResponseViewer.setResponse(result.getOriginalResponse());
        }
        if (verificationRequestViewer != null) {
            verificationRequestViewer.setRequest(result.getVerificationRequest());
        }
        if (verificationResponseViewer != null) {
            verificationResponseViewer.setResponse(result.getVerificationResponse());
        }
    }

    private int statusSortValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (Exception e) {
            return -1;
        }
    }

    private void createTablePopupMenu() {
        tablePopupMenu = new JPopupMenu();
        highlighter.namedColors().forEach((name, color) -> {
            JMenuItem item = new JMenuItem("Highlight " + name);
            item.addActionListener(e -> updateHighlight(color, false));
            tablePopupMenu.add(item);
        });

        tablePopupMenu.addSeparator();
        JMenuItem clearItem = new JMenuItem("Clear Highlight");
        clearItem.addActionListener(e -> updateHighlight(null, true));
        tablePopupMenu.add(clearItem);

        tablePopupMenu.addSeparator();
        JMenuItem copyItem = new JMenuItem("Copy selected rows (TSV)");
        copyItem.addActionListener(e -> copySelectedRowsToClipboard());
        tablePopupMenu.add(copyItem);
    }

    private void configureCopyAction() {
        // Cross-platform accelerator: Cmd+C on macOS, Ctrl+C on Windows/Linux.
        int menuShortcut = menuShortcutMask();
        KeyStroke copyKey = KeyStroke.getKeyStroke(KeyEvent.VK_C, menuShortcut);
        String actionKey = "bypassfuzzer-copy-rows";
        resultsTable.getInputMap(JComponent.WHEN_FOCUSED).put(copyKey, actionKey);
        resultsTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(copyKey, actionKey);
        resultsTable.getActionMap().put(actionKey, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedRowsToClipboard();
            }
        });
    }

    private void copySelectedRowsToClipboard() {
        int[] viewRows = resultsTable.getSelectedRows();
        if (viewRows.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder(256);
        appendHeader(sb);

        for (int viewRow : viewRows) {
            appendRow(sb, viewRow);
        }

        if (GraphicsEnvironment.isHeadless()) {
            return;
        }

        try {
            Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new StringSelection(sb.toString()), null);
        } catch (HeadlessException e) {
            // Headless test/build environments do not expose a system clipboard.
        }
    }

    private void appendHeader(StringBuilder sb) {
        int columnCount = resultsTable.getColumnCount();
        for (int c = 0; c < columnCount; c++) {
            if (c > 0) {
                sb.append('\t');
            }
            sb.append(tsvCell(resultsTable.getColumnName(c)));
        }
        sb.append(System.lineSeparator());
    }

    private void appendRow(StringBuilder sb, int viewRow) {
        int columnCount = resultsTable.getColumnCount();
        for (int c = 0; c < columnCount; c++) {
            if (c > 0) {
                sb.append('\t');
            }
            sb.append(tsvCell(resultsTable.getValueAt(viewRow, c)));
        }
        sb.append(System.lineSeparator());
    }

    private String tsvCell(Object value) {
        String cell = value == null ? "" : value.toString();
        return cell.replace('\t', ' ')
            .replace("\r\n", " ")
            .replace('\n', ' ')
            .replace('\r', ' ');
    }

    private int menuShortcutMask() {
        if (GraphicsEnvironment.isHeadless()) {
            return InputEvent.CTRL_DOWN_MASK;
        }

        try {
            return Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        } catch (HeadlessException e) {
            return InputEvent.CTRL_DOWN_MASK;
        }
    }

    private void configurePopupHandling() {
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }

            private void showPopup(MouseEvent event) {
                if (!event.isPopupTrigger()) {
                    return;
                }

                int row = resultsTable.rowAtPoint(event.getPoint());
                if (row >= 0) {
                    // Only replace the selection if the right-clicked row is not already
                    // part of the current multi-selection — otherwise preserve it.
                    if (!resultsTable.isRowSelected(row)) {
                        resultsTable.setRowSelectionInterval(row, row);
                    }
                    tablePopupMenu.show(event.getComponent(), event.getX(), event.getY());
                }
            }
        });
    }

    private void updateHighlight(Color color, boolean clear) {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AttackResult result = tableModel.getResult(modelRow);
        if (result == null) {
            return;
        }

        if (clear) {
            highlighter.clear(result);
        } else {
            highlighter.highlight(result, color);
        }

        SwingUtilities.invokeLater(() -> {
            resultsTable.repaint();
            filterRefreshListener.run();
        });
    }

    private FuzzerResultsTableModel.TableLayout toModelLayout(TableLayout tableLayout) {
        return switch (tableLayout) {
            case URL_VALIDATION -> FuzzerResultsTableModel.TableLayout.URL_VALIDATION;
            case COVERAGE_SWEEP -> FuzzerResultsTableModel.TableLayout.COVERAGE_SWEEP;
            case IDOR -> FuzzerResultsTableModel.TableLayout.IDOR;
            case DEFAULT -> FuzzerResultsTableModel.TableLayout.DEFAULT;
        };
    }
}
