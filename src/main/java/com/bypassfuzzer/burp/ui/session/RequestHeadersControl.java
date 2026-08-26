package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.ConfiguredHeaderParser;
import com.bypassfuzzer.burp.http.UserAgentMode;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;

/** Per-panel editor for headers that should be included with generated requests. */
final class RequestHeadersControl {

    private final Component parent;
    private final JButton button = new JButton();
    private final JCheckBox userAgentRandomizationCheckBox;
    private final JComboBox<String> userAgentStyleComboBox;
    private List<ConfiguredHeader> headers = List.of();
    private Runnable onChange = () -> { };

    RequestHeadersControl(Component parent) {
        this.parent = parent;
        button.setToolTipText("Configure headers to send with every request in this mode.");
        button.addActionListener(event -> openEditor());
        userAgentRandomizationCheckBox = new JCheckBox("Randomize User-Agent for every request", false);
        userAgentStyleComboBox = new JComboBox<>(new String[]{
            "Synthetic tokens (recommended)",
            "Browser-like variants"
        });
        userAgentStyleComboBox.setEnabled(false);
        userAgentRandomizationCheckBox.addActionListener(event -> {
            userAgentStyleComboBox.setEnabled(userAgentRandomizationCheckBox.isSelected());
            updateLabel();
            onChange.run();
        });
        updateLabel();
    }

    JButton button() {
        return button;
    }

    List<ConfiguredHeader> headers() {
        return headers;
    }

    void setEnabled(boolean enabled) {
        button.setEnabled(enabled);
    }

    void setHeaders(List<ConfiguredHeader> headers) {
        this.headers = headers == null ? List.of() : List.copyOf(headers);
        updateLabel();
        onChange.run();
    }

    UserAgentMode userAgentMode() {
        if (!userAgentRandomizationCheckBox.isSelected()) {
            return UserAgentMode.DISABLED;
        }
        return userAgentStyleComboBox.getSelectedIndex() == 1
            ? UserAgentMode.BROWSER_LIKE
            : UserAgentMode.SYNTHETIC;
    }

    void setUserAgentMode(UserAgentMode mode) {
        UserAgentMode effective = mode == null ? UserAgentMode.DISABLED : mode;
        userAgentRandomizationCheckBox.setSelected(effective != UserAgentMode.DISABLED);
        userAgentStyleComboBox.setSelectedIndex(
            effective == UserAgentMode.BROWSER_LIKE ? 1 : 0);
        userAgentStyleComboBox.setEnabled(userAgentRandomizationCheckBox.isSelected());
        updateLabel();
        onChange.run();
    }

    void setOnChange(Runnable onChange) {
        this.onChange = onChange == null ? () -> { } : onChange;
    }

    private void openEditor() {
        UserAgentMode originalUserAgentMode = userAgentMode();
        JTextArea editor = new JTextArea(ConfiguredHeaderParser.format(headers), 12, 62);
        editor.setLineWrap(false);
        JScrollPane scrollPane = new JScrollPane(editor);
        scrollPane.setPreferredSize(new Dimension(700, 280));
        JPanel content = new JPanel(new BorderLayout(0, 8));
        content.add(scrollPane, BorderLayout.CENTER);
        content.add(buildUserAgentPanel(), BorderLayout.SOUTH);
        int result = JOptionPane.showConfirmDialog(
            parent,
            content,
            "Request Headers - one Name: value per line",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            setUserAgentMode(originalUserAgentMode);
            return;
        }
        try {
            setHeaders(ConfiguredHeaderParser.parse(editor.getText()));
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(parent, e.getMessage(), "Invalid Request Header",
                JOptionPane.ERROR_MESSAGE);
        }
        updateLabel();
        onChange.run();
    }

    private JPanel buildUserAgentPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createTitledBorder("User-Agent handling"));
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        controls.add(userAgentRandomizationCheckBox);
        controls.add(new JLabel("Style:"));
        controls.add(userAgentStyleComboBox);
        panel.add(controls, BorderLayout.NORTH);
        panel.add(new JLabel(
            "<html>Synthetic uses valid non-browser product tokens; Browser-like varies Chrome, Firefox, and Safari shapes.<br>"
                + "When enabled, this replaces the Browser User-Agent preset and fixed User-Agent headers.</html>"
        ), BorderLayout.SOUTH);
        return panel;
    }

    private void updateLabel() {
        String userAgentLabel = switch (userAgentMode()) {
            case SYNTHETIC -> "; UA synthetic";
            case BROWSER_LIKE -> "; UA browser-like";
            default -> "";
        };
        button.setText("Request Headers... (" + headers.size() + userAgentLabel + ")");
        button.setToolTipText(userAgentMode() == UserAgentMode.DISABLED
            ? "Configure headers to send with every request in this mode."
            : "User-Agent randomization is enabled and overrides fixed User-Agent values.");
    }
}
