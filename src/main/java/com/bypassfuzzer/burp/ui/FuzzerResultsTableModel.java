package com.bypassfuzzer.burp.ui;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Thread-safe table model for fuzzer results.
 * Follows PortSwigger's recommended pattern using AbstractTableModel with synchronized methods.
 */
public class FuzzerResultsTableModel extends AbstractTableModel {

    public enum TableLayout {
        DEFAULT(
            new String[]{"#", "Attack Type", "Payload", "Status", "Length", "Content-Type"},
            new Class<?>[]{Integer.class, String.class, String.class, Integer.class, Integer.class, String.class}
        ),
        IDOR(
            new String[]{"#", "Group", "Playbook", "Variant", "Status", "Length", "Content-Type"},
            new Class<?>[]{Integer.class, String.class, String.class, String.class, Integer.class, Integer.class, String.class}
        ),
        URL_VALIDATION(
            new String[]{"#", "Target", "Family", "Encoding", "Payload", "Status", "Length", "Content-Type"},
            new Class<?>[]{Integer.class, String.class, String.class, String.class, String.class, Integer.class, Integer.class, String.class}
        ),
        COVERAGE_SWEEP(
            new String[]{"#", "Target", "Family", "Signal", "Payload", "Status", "Length", "Content-Type"},
            new Class<?>[]{Integer.class, String.class, String.class, String.class, String.class, Object.class, Integer.class, String.class}
        );

        private final String[] columnNames;
        private final Class<?>[] columnClasses;

        TableLayout(String[] columnNames, Class<?>[] columnClasses) {
            this.columnNames = columnNames;
            this.columnClasses = columnClasses;
        }
    }

    private final List<AttackResult> results;
    private final List<AttackResult> allResults; // Unfiltered results
    private final Map<AttackResult, Integer> resultIds;
    private final TableLayout tableLayout;
    private int nextResultId;

    public FuzzerResultsTableModel() {
        this(TableLayout.DEFAULT);
    }

    public FuzzerResultsTableModel(TableLayout tableLayout) {
        this.results = new ArrayList<>();
        this.allResults = new ArrayList<>();
        this.resultIds = new HashMap<>();
        this.tableLayout = tableLayout == null ? TableLayout.DEFAULT : tableLayout;
        this.nextResultId = 1;
    }

    @Override
    public int getColumnCount() {
        return tableLayout.columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return tableLayout.columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return tableLayout.columnClasses[columnIndex];
    }

    @Override
    public synchronized int getRowCount() {
        return results.size();
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= results.size()) {
            return "";
        }

        AttackResult result = results.get(rowIndex);

        return switch (tableLayout) {
            case DEFAULT -> switch (columnIndex) {
                case 0 -> resultIds.getOrDefault(result, 0);
                case 1 -> result.getAttackType();
                case 2 -> truncatePayload(displayPayload(result), 100);
                case 3 -> result.getStatusCode();
                case 4 -> result.getContentLength();
                case 5 -> truncatePayload(result.getContentType(), 50);
                default -> "";
            };
            case IDOR -> switch (columnIndex) {
                case 0 -> resultIds.getOrDefault(result, 0);
                case 1 -> truncatePayload(emptyToDash(result.getTargetLabel()), 20);
                case 2 -> truncatePayload(emptyToDash(result.getPayloadFamily()), 34);
                case 3 -> truncatePayload(displayPayload(result), 78);
                case 4 -> result.getStatusCode();
                case 5 -> result.getContentLength();
                case 6 -> truncatePayload(result.getContentType(), 40);
                default -> "";
            };
            case URL_VALIDATION -> switch (columnIndex) {
                case 0 -> resultIds.getOrDefault(result, 0);
                case 1 -> truncatePayload(emptyToDash(result.getTargetLabel()), 28);
                case 2 -> truncatePayload(emptyToDash(result.getPayloadFamily()), 18);
                case 3 -> truncatePayload(emptyToDash(result.getPayloadEncoding()), 18);
                case 4 -> truncatePayload(displayPayload(result), 64);
                case 5 -> result.getStatusCode();
                case 6 -> result.getContentLength();
                case 7 -> truncatePayload(result.getContentType(), 40);
                default -> "";
            };
            case COVERAGE_SWEEP -> switch (columnIndex) {
                case 0 -> resultIds.getOrDefault(result, 0);
                case 1 -> emptyToDash(result.getTargetLabel());
                case 2 -> emptyToDash(result.getPayloadFamily());
                case 3 -> emptyToDash(result.getPayloadEncoding());
                case 4 -> displayPayload(result);
                case 5 -> result.getResponse() == null ? "No response" : result.getStatusCode();
                case 6 -> result.getContentLength();
                case 7 -> result.getContentType();
                default -> "";
            };
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    /**
     * Add a new result to the model.
     * This adds to both allResults (unfiltered) and results (filtered) if it passes the filter.
     *
     * @param result The attack result to add
     * @param passesFilter Whether this result passes the current filter
     */
    public synchronized void addResult(AttackResult result, boolean passesFilter) {
        resultIds.putIfAbsent(result, nextResultId++);
        allResults.add(result);

        if (passesFilter) {
            int index = results.size();
            results.add(result);
            fireTableRowsInserted(index, index);
        }
    }

    /** Adds a batch with one table notification, keeping the event thread responsive under load. */
    public synchronized void addResults(List<AttackResult> additions, Predicate<AttackResult> filter) {
        if (additions == null || additions.isEmpty()) return;
        int firstVisible = results.size();
        for (AttackResult result : additions) {
            resultIds.putIfAbsent(result, nextResultId++);
            allResults.add(result);
            if (filter == null || filter.test(result)) results.add(result);
        }
        if (results.size() > firstVisible) {
            fireTableRowsInserted(firstVisible, results.size() - 1);
        }
    }

    /**
     * Get a result by its row index in the filtered view.
     */
    public synchronized AttackResult getResult(int rowIndex) {
        if (rowIndex < 0 || rowIndex >= results.size()) {
            return null;
        }
        return results.get(rowIndex);
    }

    /**
     * Get all results (unfiltered).
     */
    public synchronized List<AttackResult> getAllResults() {
        return new ArrayList<>(allResults);
    }

    /**
     * Get filtered results.
     */
    public synchronized List<AttackResult> getFilteredResults() {
        return new ArrayList<>(results);
    }

    /**
     * Get count of all results (unfiltered).
     */
    public synchronized int getAllResultsCount() {
        return allResults.size();
    }

    /**
     * Rebuild the filtered results list based on a filter predicate.
     * This is called when filters change.
     *
     * @param filter Predicate that returns true if result should be shown
     */
    public synchronized void applyFilter(java.util.function.Predicate<AttackResult> filter) {
        results.clear();
        for (AttackResult result : allResults) {
            if (filter.test(result)) {
                results.add(result);
            }
        }
        fireTableDataChanged();
    }

    /**
     * Clear all results.
     */
    public synchronized void clear() {
        results.clear();
        allResults.clear();
        resultIds.clear();
        nextResultId = 1;
        fireTableDataChanged();
    }

    /**
     * Truncate a string to a maximum length with ellipsis.
     */
    private String truncatePayload(String payload, int maxLength) {
        if (payload == null) {
            return "";
        }
        if (payload.length() <= maxLength) {
            return payload;
        }
        return payload.substring(0, maxLength - 3) + "...";
    }

    private String displayPayload(AttackResult result) {
        if (result == null || result.getThrottleRetryAttempt() <= 0) {
            return result == null ? "" : result.getPayload();
        }
        return result.getPayload() + " [throttle retry #" + result.getThrottleRetryAttempt() + "]";
    }

    private String emptyToDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }
}
