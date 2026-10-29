package com.bypassfuzzer.burp.ui.session;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Map;
import java.util.TreeMap;

/** Edits a local copy so closing the dialog does not change the Sweep configuration. */
final class OpenApiVariablesEditor extends JPanel {
    private final JTextArea values = new JTextArea(14, 52);
    private final JLabel status = new JLabel("Values override matching spec parameters. Changes apply when you click OK.");
    private final Map<String, String> examples;

    OpenApiVariablesEditor(Map<String, String> current, Map<String, String> examples) {
        super(new BorderLayout(0, 8));
        this.examples = Map.copyOf(examples);
        Map<String, String> entries = new TreeMap<>();
        examples.keySet().forEach(name -> entries.put(name, ""));
        entries.putAll(current);
        display(entries);
        add(new JLabel("Variables from the imported spec. Enter one name=value per line, e.g. tenantId=123."),
            BorderLayout.NORTH);
        add(new JScrollPane(values), BorderLayout.CENTER);
        JPanel actions = new JPanel(new BorderLayout(0, 8));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JButton fill = new JButton("Fill empty with examples");
        fill.setToolTipText("Fill blank values from spec examples/defaults or generated samples. Existing values are kept.");
        fill.addActionListener(event -> fillEmptyWithExamples());
        buttons.add(fill);
        actions.add(buttons, BorderLayout.NORTH);
        actions.add(status, BorderLayout.SOUTH);
        add(actions, BorderLayout.SOUTH);
    }

    Map<String, String> variables() {
        Map<String, String> entries = new TreeMap<>();
        for (String line : values.getText().split("\\R")) {
            if (line.isBlank()) continue;
            int separator = line.indexOf('=');
            if (separator <= 0 || line.substring(0, separator).trim().isEmpty()) {
                throw new IllegalArgumentException("Each variable needs a name=value entry.");
            }
            entries.put(line.substring(0, separator).trim(), line.substring(separator + 1));
        }
        return entries;
    }

    private void fillEmptyWithExamples() {
        try {
            Map<String, String> entries = variables();
            int filled = 0;
            for (var example : new TreeMap<>(examples).entrySet()) {
                if (entries.getOrDefault(example.getKey(), "").isEmpty() && !example.getValue().isEmpty()) {
                    entries.put(example.getKey(), example.getValue());
                    filled++;
                }
            }
            display(entries);
            status.setText("Filled " + filled + " empty value(s). Conflicting suggestions stay blank.");
        } catch (IllegalArgumentException e) {
            status.setText(e.getMessage());
        }
    }

    private void display(Map<String, String> entries) {
        StringBuilder text = new StringBuilder();
        entries.forEach((name, value) -> text.append(name).append('=').append(value).append('\n'));
        values.setText(text.toString());
        values.setCaretPosition(0);
    }
}
