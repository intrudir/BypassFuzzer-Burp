package com.bypassfuzzer.burp.ui.dashboard;

import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;

import com.bypassfuzzer.burp.ui.WorkbenchTheme;

import javax.swing.AbstractCellEditor;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/** Master control plane for all open BypassFuzzer activities. */
public final class DashboardPanel extends JPanel {

    private final MontoyaApi api;
    private final GlobalTrafficGovernor governor;
    private final ActivityRegistry registry;
    private final ActivityTableModel tableModel = new ActivityTableModel();
    private final JTable activityTable = new JTable(tableModel);
    private final JCheckBox limitsEnabled = new JCheckBox("Enable global limits");
    private final JSpinner maxRate = new JSpinner(new SpinnerNumberModel(10.0, 0.1, 10_000.0, 0.5));
    private final JSpinner maxInFlight = new JSpinner(new SpinnerNumberModel(10, 1, 10_000, 1));
    private final JLabel activitySummary = new JLabel();
    private final JLabel trafficSummary = new JLabel();
    private final Timer refreshTimer;

    public DashboardPanel(MontoyaApi api, GlobalTrafficGovernor governor, ActivityRegistry registry) {
        super(new BorderLayout(0, 10));
        this.api = api;
        this.governor = governor;
        this.registry = registry;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        initializeUi();
        WorkbenchTheme.apply(this);
        applyLimits();
        refresh();
        refreshTimer = new Timer(500, event -> refresh());
        refreshTimer.start();
    }

    public void cleanup() {
        refreshTimer.stop();
    }

    public void refresh() {
        GlobalTrafficGovernor.Snapshot traffic = governor.snapshot();
        List<ActivityRegistry.Entry> entries = registry.entries();
        tableModel.update(entries, traffic.paused());
        long running = entries.stream().map(entry -> entry.activity().activitySnapshot())
            .filter(ActivitySnapshot::active).count();
        long locallyPaused = entries.stream().map(entry -> entry.activity().activitySnapshot())
            .filter(ActivitySnapshot::paused).count();
        activitySummary.setText(entries.size() + " open activities · " + running + " active · "
            + locallyPaused + " locally paused");
        trafficSummary.setText((traffic.paused() ? "GLOBAL PAUSE · " : "")
            + traffic.inFlight() + " in flight · " + traffic.queued() + " queued · "
            + (traffic.limitsEnabled()
                ? formatRate(traffic.maxRequestsPerSecondPerHost()) + " req/s per host · "
                    + traffic.maxInFlight() + " max in-flight"
                : "hard limits disabled"));
    }

    private void initializeUi() {
        JPanel header = new JPanel();
        header.setLayout(new javax.swing.BoxLayout(header, javax.swing.BoxLayout.Y_AXIS));

        JPanel globalActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JButton pauseAll = new JButton("Pause All");
        pauseAll.setName("dashboardPauseAll");
        pauseAll.setToolTipText("Blocks new BypassFuzzer HTTP requests. Existing requests may finish.");
        pauseAll.addActionListener(event -> {
            governor.pause();
            refresh();
        });
        JButton resumeAll = new JButton("Resume All");
        resumeAll.setName("dashboardResumeAll");
        resumeAll.setToolTipText("Lifts only the global pause; locally paused sessions remain paused.");
        resumeAll.addActionListener(event -> {
            governor.resume();
            refresh();
        });
        JButton stopAll = new JButton("Stop All");
        stopAll.setName("dashboardStopAll");
        stopAll.addActionListener(event -> confirmAndStopAll());
        globalActions.add(pauseAll);
        globalActions.add(resumeAll);
        globalActions.add(stopAll);
        globalActions.add(activitySummary);
        header.add(WorkbenchTheme.heading("Dashboard", "Manage every scan and retry pass from one place."));
        header.add(globalActions);

        JPanel limits = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        limits.setBorder(BorderFactory.createTitledBorder("Extension-wide traffic safety"));
        limitsEnabled.setName("globalLimitsEnabled");
        maxRate.setName("globalMaxRatePerHost");
        maxInFlight.setName("globalMaxInFlight");
        limits.add(limitsEnabled);
        limits.add(new JLabel("Max req/s per host:"));
        limits.add(maxRate);
        limits.add(new JLabel("Max total in-flight:"));
        limits.add(maxInFlight);
        limits.add(trafficSummary);
        limitsEnabled.addActionListener(event -> applyLimits());
        maxRate.addChangeListener(event -> applyLimits());
        maxInFlight.addChangeListener(event -> applyLimits());
        header.add(limits);
        add(header, BorderLayout.NORTH);

        configureTable();
        JScrollPane scrollPane = new JScrollPane(activityTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Open scan activities"));
        add(scrollPane, BorderLayout.CENTER);

        JTextArea guidance = new JTextArea(
            "Send requests from Burp to Bypass, IDOR, or URL Validation. Global limits apply to "
                + "every physical scan and retry request across all tabs. Limits reset when Burp restarts.");
        guidance.setEditable(false);
        guidance.setFocusable(false);
        guidance.setLineWrap(true);
        guidance.setWrapStyleWord(true);
        guidance.setOpaque(false);
        guidance.setBorder(BorderFactory.createTitledBorder("Getting started"));
        add(guidance, BorderLayout.SOUTH);
    }

    private void configureTable() {
        activityTable.setFillsViewportHeight(true);
        activityTable.setRowHeight(25);
        activityTable.getColumnModel().getColumn(1).setPreferredWidth(420);
        activityTable.getColumnModel().getColumn(3).setPreferredWidth(180);
        for (int column = 5; column <= 7; column++) {
            activityTable.getColumnModel().getColumn(column).setCellRenderer(new ActionRenderer());
            activityTable.getColumnModel().getColumn(column).setCellEditor(new ActionEditor(column));
        }
    }

    private void applyLimits() {
        governor.configure(limitsEnabled.isSelected(),
            ((Number) maxInFlight.getValue()).intValue(), ((Number) maxRate.getValue()).doubleValue());
        refresh();
    }

    private void confirmAndStopAll() {
        int choice = JOptionPane.showConfirmDialog(
            api.userInterface().swingUtils().suiteFrame(),
            "Stop every active BypassFuzzer scan and retry pass? Open tabs and results will remain.",
            "Stop All Scans",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (choice != JOptionPane.YES_OPTION) return;
        stopAllActivities();
    }

    void stopAllActivities() {
        registry.entries().forEach(entry -> {
            if (entry.activity().activitySnapshot().active()) entry.activity().stopActivity();
        });
        refresh();
    }

    private void performAction(int modelRow, int column) {
        ActivityTableModel.Row row = tableModel.row(modelRow);
        if (row == null) return;
        if (column == 5) row.entry().openAction().run();
        else if (column == 6 && row.snapshot().active()) {
            if (row.snapshot().paused()) row.entry().activity().resumeActivity();
            else row.entry().activity().pauseActivity();
        } else if (column == 7 && row.snapshot().active()) {
            row.entry().activity().stopActivity();
        }
        refresh();
    }

    private static String formatRate(double value) {
        return value == Math.rint(value) ? String.valueOf((long) value) : String.format("%.1f", value);
    }

    private final class ActionEditor extends AbstractCellEditor implements TableCellEditor {
        private final JButton button = new JButton();
        private final int actionColumn;
        private int modelRow = -1;

        private ActionEditor(int actionColumn) {
            this.actionColumn = actionColumn;
            button.setHorizontalAlignment(SwingConstants.CENTER);
            WorkbenchTheme.apply(button);
            button.addActionListener(event -> {
                int selectedRow = modelRow;
                fireEditingStopped();
                performAction(selectedRow, actionColumn);
            });
        }

        @Override
        public Object getCellEditorValue() {
            return button.getText();
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean selected,
                                                     int row, int column) {
            modelRow = table.convertRowIndexToModel(row);
            button.setText(String.valueOf(value));
            button.setEnabled(tableModel.actionEnabled(modelRow, actionColumn));
            return button;
        }
    }

    private final class ActionRenderer extends JButton implements TableCellRenderer {
        private ActionRenderer() {
            setHorizontalAlignment(SwingConstants.CENTER);
            WorkbenchTheme.apply(this);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focus, int row, int column) {
            int modelRow = table.convertRowIndexToModel(row);
            setText(String.valueOf(value));
            setEnabled(tableModel.actionEnabled(modelRow, column));
            return this;
        }
    }

    private static final class ActivityTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
            "Mode", "Target", "State", "Progress", "Sent", "Open", "Pause / Resume", "Stop"
        };
        private List<Row> rows = List.of();

        record Row(ActivityRegistry.Entry entry, ActivitySnapshot snapshot, boolean globallyPaused) { }

        void update(List<ActivityRegistry.Entry> entries, boolean globallyPaused) {
            List<Row> updated = new ArrayList<>();
            for (ActivityRegistry.Entry entry : entries) {
                updated.add(new Row(entry, entry.activity().activitySnapshot(), globallyPaused));
            }
            rows = List.copyOf(updated);
            fireTableDataChanged();
        }

        Row row(int index) {
            return index >= 0 && index < rows.size() ? rows.get(index) : null;
        }

        boolean actionEnabled(int rowIndex, int column) {
            Row value = row(rowIndex);
            if (value == null) return false;
            if (column == 5) return true;
            if (column == 6) {
                return value.snapshot().state() == ActivityState.RUNNING
                    || value.snapshot().state() == ActivityState.RETRYING
                    || value.snapshot().state() == ActivityState.PAUSED;
            }
            return value.snapshot().active() && value.snapshot().state() != ActivityState.STOPPING;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }
        @Override public boolean isCellEditable(int row, int column) { return column >= 5; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Row row = rows.get(rowIndex);
            ActivitySnapshot snapshot = row.snapshot();
            return switch (columnIndex) {
                case 0 -> snapshot.mode();
                case 1 -> snapshot.target();
                case 2 -> row.globallyPaused() && snapshot.active()
                    ? (snapshot.paused() ? "Paused locally + globally" : "Paused globally · " + snapshot.state().label())
                    : snapshot.state().label();
                case 3 -> snapshot.progress();
                case 4 -> snapshot.sentCount();
                case 5 -> "Open";
                case 6 -> snapshot.paused() ? "Resume" : "Pause";
                case 7 -> "Stop";
                default -> "";
            };
        }
    }
}
