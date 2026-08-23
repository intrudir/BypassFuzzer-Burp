package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.filter.FilterConfig;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.function.Consumer;

/**
 * Swing component for configuring smart/manual result filters.
 */
public class FilterPanel extends JPanel {

    private final FilterConfig filterConfig;
    private final Consumer<String> errorLogger;

    private Runnable filterChangeListener = () -> {
    };

    private JCheckBox smartFilterCheckbox;
    private JCheckBox manualFilterCheckbox;
    private JTextField hideStatusCodesField;
    private JTextField showOnlyStatusCodesField;
    private JTextField minLengthField;
    private JTextField maxLengthField;
    private JTextField hideContentLengthsField;
    private JTextField showOnlyContentLengthsField;
    private JTextField contentTypeField;
    private JTextField hostContainsField;
    private JTextField payloadContainsField;
    private JTextField signalContainsField;
    private JCheckBox signalRegexCheckbox;
    private JTextField responseContainsField;
    private JCheckBox responseRegexCheckbox;
    private JCheckBox responseDoesNotContainCheckbox;
    private JComboBox<String> highlightColorFilter;
    private JButton applyFilterButton;
    private JLabel filterStatusLabel;

    public FilterPanel(FilterConfig filterConfig, Consumer<String> errorLogger) {
        this.filterConfig = filterConfig;
        this.errorLogger = errorLogger;
        initializeUi();
    }

    public void setFilterChangeListener(Runnable filterChangeListener) {
        this.filterChangeListener = filterChangeListener == null ? () -> {
        } : filterChangeListener;
    }

    public String selectedHighlightColor() {
        return (String) highlightColorFilter.getSelectedItem();
    }

    public void setFilterStatus(String status) {
        filterStatusLabel.setText(status);
    }

    private void initializeUi() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        add(createSmartPanel());
        add(Box.createVerticalStrut(10));
        add(createManualPanel());
    }

    private JPanel createSmartPanel() {
        JPanel smartPanel = createSectionPanel("Smart Filter");

        smartFilterCheckbox = new JCheckBox("Enable (auto-detect patterns)");
        smartFilterCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        smartFilterCheckbox.addActionListener(e -> {
            filterConfig.setSmartFilterEnabled(smartFilterCheckbox.isSelected());
            filterChangeListener.run();
        });
        smartPanel.add(smartFilterCheckbox);

        smartPanel.add(Box.createVerticalStrut(5));
        filterStatusLabel = new JLabel("No filters active");
        filterStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        filterStatusLabel.setFont(filterStatusLabel.getFont().deriveFont(11f));
        smartPanel.add(filterStatusLabel);

        return smartPanel;
    }

    private JPanel createManualPanel() {
        JPanel manualPanel = createSectionPanel("Manual Filter");

        manualFilterCheckbox = new JCheckBox("Enable Manual Filter");
        manualFilterCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        manualFilterCheckbox.addActionListener(e -> {
            boolean enabled = manualFilterCheckbox.isSelected();
            filterConfig.setManualFilterEnabled(enabled);
            setManualControlsEnabled(enabled);
            if (!enabled) {
                filterChangeListener.run();
            }
        });
        manualPanel.add(manualFilterCheckbox);
        manualPanel.add(Box.createVerticalStrut(5));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        applyFilterButton = new JButton("Apply Manual Filters");
        applyFilterButton.setEnabled(false);
        applyFilterButton.addActionListener(e -> applyManualFilters());
        buttonPanel.add(applyFilterButton);
        manualPanel.add(buttonPanel);
        manualPanel.add(Box.createVerticalStrut(10));

        hideStatusCodesField = new JTextField(15);
        showOnlyStatusCodesField = new JTextField(15);
        minLengthField = new JTextField(8);
        maxLengthField = new JTextField(8);
        hideContentLengthsField = new JTextField(15);
        showOnlyContentLengthsField = new JTextField(15);
        contentTypeField = new JTextField(20);
        hostContainsField = new JTextField(20);
        payloadContainsField = new JTextField(20);
        signalContainsField = new JTextField(20);
        signalRegexCheckbox = new JCheckBox("Regex");
        responseContainsField = new JTextField(20);
        responseRegexCheckbox = new JCheckBox("Regex");
        responseDoesNotContainCheckbox = new JCheckBox("Does not contain");
        highlightColorFilter = new JComboBox<>(new String[]{
            "All", "Red", "Orange", "Yellow", "Green", "Blue", "Cyan", "Magenta", "Gray"
        });

        manualPanel.add(createStatusCodePanel());
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createLengthPanel());
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createContainsPanel("Content-Type", "Contains:", contentTypeField, "(e.g. html, json)"));
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createContainsPanel("Host", "Contains:", hostContainsField, "(e.g. api.example.com)"));
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createContainsPanel("Payload", "Contains:", payloadContainsField, null));
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createSignalPanel());
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createResponsePanel());
        manualPanel.add(Box.createVerticalStrut(5));
        manualPanel.add(createHighlightPanel());

        setManualControlsEnabled(false);
        return manualPanel;
    }

    private JPanel createStatusCodePanel() {
        JPanel statusCodePanel = createTitledPanel("Status Code");

        JPanel hideStatusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        hideStatusRow.add(new JLabel("Hide codes:"));
        hideStatusCodesField.setToolTipText("Comma-separated, e.g., 404,403,500");
        hideStatusRow.add(hideStatusCodesField);
        hideStatusRow.add(new JLabel("(e.g. 404,403,500)"));
        statusCodePanel.add(hideStatusRow);

        JPanel showStatusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        showStatusRow.add(new JLabel("Show only:"));
        showOnlyStatusCodesField.setToolTipText("Comma-separated, e.g., 200,302");
        showStatusRow.add(showOnlyStatusCodesField);
        showStatusRow.add(new JLabel("(e.g. 200,302)"));
        statusCodePanel.add(showStatusRow);

        return statusCodePanel;
    }

    private JPanel createLengthPanel() {
        JPanel lengthPanel = createTitledPanel("Content Length (bytes)");

        JPanel lengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        lengthRow.add(new JLabel("Min:"));
        minLengthField.setToolTipText("Minimum bytes");
        lengthRow.add(minLengthField);
        lengthRow.add(new JLabel("Max:"));
        maxLengthField.setToolTipText("Maximum bytes");
        lengthRow.add(maxLengthField);
        lengthRow.add(new JLabel("(e.g. 1000 or 5000)"));
        lengthPanel.add(lengthRow);

        JPanel hideLengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        hideLengthRow.add(new JLabel("Hide lengths:"));
        hideContentLengthsField.setToolTipText("Comma-separated, e.g., 0,1234,5678");
        hideLengthRow.add(hideContentLengthsField);
        lengthPanel.add(hideLengthRow);

        JPanel showLengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        showLengthRow.add(new JLabel("Show only:"));
        showOnlyContentLengthsField.setToolTipText("Comma-separated, e.g., 200,500");
        showLengthRow.add(showOnlyContentLengthsField);
        lengthPanel.add(showLengthRow);

        return lengthPanel;
    }

    private JPanel createContainsPanel(String title, String label, JTextField field, String helperText) {
        JPanel panel = createTitledPanel(title);

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row.add(new JLabel(label));
        row.add(field);
        if (helperText != null) {
            row.add(new JLabel(helperText));
        }
        panel.add(row);
        return panel;
    }

    private JPanel createHighlightPanel() {
        JPanel highlightPanel = createTitledPanel("Highlight Color");
        JPanel highlightRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        highlightRow.add(new JLabel("Show only:"));
        highlightRow.add(highlightColorFilter);
        highlightPanel.add(highlightRow);
        return highlightPanel;
    }

    private JPanel createResponsePanel() {
        JPanel responsePanel = createTitledPanel("Response");

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row.add(new JLabel("Contains:"));
        row.add(responseContainsField);
        responseRegexCheckbox.setToolTipText("Treat the response filter as a regular expression.");
        row.add(responseRegexCheckbox);
        responsePanel.add(row);
        JPanel inverseRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        responseDoesNotContainCheckbox.setToolTipText(
            "Show only responses that do not contain or match the entered value.");
        inverseRow.add(responseDoesNotContainCheckbox);
        responsePanel.add(inverseRow);
        return responsePanel;
    }

    private JPanel createSignalPanel() {
        JPanel signalPanel = createTitledPanel("Signal");
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row.add(new JLabel("Contains:"));
        row.add(signalContainsField);
        signalRegexCheckbox.setToolTipText("Treat the signal filter as a regular expression.");
        row.add(signalRegexCheckbox);
        signalPanel.add(row);
        return signalPanel;
    }

    private JPanel createSectionPanel(String title) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        return panel;
    }

    private JPanel createTitledPanel(String title) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    private void setManualControlsEnabled(boolean enabled) {
        hideStatusCodesField.setEnabled(enabled);
        showOnlyStatusCodesField.setEnabled(enabled);
        minLengthField.setEnabled(enabled);
        maxLengthField.setEnabled(enabled);
        hideContentLengthsField.setEnabled(enabled);
        showOnlyContentLengthsField.setEnabled(enabled);
        contentTypeField.setEnabled(enabled);
        hostContainsField.setEnabled(enabled);
        payloadContainsField.setEnabled(enabled);
        signalContainsField.setEnabled(enabled);
        signalRegexCheckbox.setEnabled(enabled);
        responseContainsField.setEnabled(enabled);
        responseRegexCheckbox.setEnabled(enabled);
        responseDoesNotContainCheckbox.setEnabled(enabled);
        highlightColorFilter.setEnabled(enabled);
        applyFilterButton.setEnabled(enabled);
    }

    private void applyManualFilters() {
        String responseFilter = emptyToNull(responseContainsField.getText());
        String signalFilter = emptyToNull(signalContainsField.getText());
        if (responseRegexCheckbox.isSelected() && responseFilter != null) {
            if (!isValidRegex(responseFilter)) {
                return;
            }
        }
        if (signalRegexCheckbox.isSelected() && signalFilter != null) {
            if (!isValidRegex(signalFilter)) {
                return;
            }
        }

        filterConfig.setHiddenStatusCodes(parseIntegerSet(hideStatusCodesField.getText(), "status code"));
        filterConfig.setShownStatusCodes(parseIntegerSet(showOnlyStatusCodesField.getText(), "status code"));
        filterConfig.setMinContentLength(parseInteger(minLengthField.getText(), "min length"));
        filterConfig.setMaxContentLength(parseInteger(maxLengthField.getText(), "max length"));
        filterConfig.setHiddenContentLengths(parseIntegerSet(hideContentLengthsField.getText(), "content length"));
        filterConfig.setShownContentLengths(parseIntegerSet(showOnlyContentLengthsField.getText(), "content length"));
        filterConfig.setContentTypeFilter(emptyToNull(contentTypeField.getText()));
        filterConfig.setHostContainsFilter(emptyToNull(hostContainsField.getText()));
        filterConfig.setPayloadContainsFilter(emptyToNull(payloadContainsField.getText()));
        filterConfig.setSignalContainsFilter(signalFilter);
        filterConfig.setSignalContainsRegex(signalRegexCheckbox.isSelected());
        filterConfig.setResponseContainsFilter(responseFilter);
        filterConfig.setResponseContainsRegex(responseRegexCheckbox.isSelected());
        filterConfig.setResponseMatchInverted(responseDoesNotContainCheckbox.isSelected());
        filterChangeListener.run();
    }

    private Set<Integer> parseIntegerSet(String input, String label) {
        Set<Integer> values = new HashSet<>();
        if (input == null || input.trim().isEmpty()) {
            return values;
        }

        for (String token : input.split(",")) {
            try {
                values.add(Integer.parseInt(token.trim()));
            } catch (NumberFormatException e) {
                errorLogger.accept("Invalid " + label + ": " + token.trim());
            }
        }

        return values;
    }

    private Integer parseInteger(String input, String label) {
        String trimmed = input == null ? "" : input.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        try {
            return Integer.parseInt(trimmed);
        } catch (NumberFormatException e) {
            errorLogger.accept("Invalid " + label + ": " + trimmed);
            return null;
        }
    }

    private String emptyToNull(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean isValidRegex(String regex) {
        try {
            Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            return true;
        } catch (PatternSyntaxException e) {
            errorLogger.accept("Invalid response regex: " + e.getDescription());
            return false;
        }
    }
}
