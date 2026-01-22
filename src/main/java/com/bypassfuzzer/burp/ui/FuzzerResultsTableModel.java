package com.bypassfuzzer.burp.ui;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Thread-safe table model for fuzzer results.
 * Follows PortSwigger's recommended pattern using AbstractTableModel with synchronized methods.
 */
public class FuzzerResultsTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {"#", "Attack Type", "Payload", "Status", "Length", "Content-Type"};
    private static final Class<?>[] COLUMN_CLASSES = {Integer.class, String.class, String.class, Integer.class, Integer.class, String.class};

    private final List<AttackResult> results;
    private final List<AttackResult> allResults; // Unfiltered results

    public FuzzerResultsTableModel() {
        this.results = new ArrayList<>();
        this.allResults = new ArrayList<>();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
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

        return switch (columnIndex) {
            case 0 -> rowIndex + 1; // Row number (1-indexed)
            case 1 -> result.getAttackType();
            case 2 -> truncatePayload(result.getPayload(), 100);
            case 3 -> result.getStatusCode();
            case 4 -> result.getContentLength();
            case 5 -> truncatePayload(result.getContentType(), 50);
            default -> "";
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
        allResults.add(result);

        if (passesFilter) {
            int index = results.size();
            results.add(result);
            fireTableRowsInserted(index, index);
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
}
