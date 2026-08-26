package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shared component that owns the throttle-related fields and the dialog. Request pacing is automatic
 * and adaptive (per host), so the only controls left are the in-flight concurrency caps and which
 * responses count as a rate-limit signal. Each tool embeds {@link #button()} in its options panel.
 */
public class ThrottleSettingsControl {

    private final JTextField concurrencyField;         // null if not shown
    private final JTextField perHostConcurrencyField;  // null if not shown
    private final JTextField throttleStatusCodesField;
    private final JCheckBox rideHardCheckbox;
    private final JButton throttleButton;
    private final String concurrencyLabel;
    private final JComboBox<String> pauseModeComboBox;
    private final JTextField fixedPauseSecondsField;
    private final boolean showGlobalPause;

    public ThrottleSettingsControl(ThrottleDefaults defaults) {
        this.concurrencyLabel = defaults.concurrencyLabel();
        this.showGlobalPause = defaults.showGlobalPause();

        concurrencyField = defaults.concurrency() >= 0
            ? new JTextField(String.valueOf(defaults.concurrency()), 5) : null;
        perHostConcurrencyField = defaults.perHostConcurrency() >= 0
            ? new JTextField(String.valueOf(defaults.perHostConcurrency()), 4) : null;
        throttleStatusCodesField = new JTextField(formatStatusCodes(defaults.throttleStatusCodes()), 10);
        rideHardCheckbox = new JCheckBox("Ride hard (fastest; blocked requests are retried)",
            defaults.posture() != ThrottleSettings.Posture.CONSERVATIVE);
        rideHardCheckbox.setToolTipText(
            "On: probe close to the rate limit for maximum speed; any blocked (throttled) requests are "
            + "automatically retried. Off (cautious): hold a wider margin so fewer requests are blocked, "
            + "at some cost to speed.");
        pauseModeComboBox = new JComboBox<>(new String[]{
            "No global pause (adaptive)", "Fixed pause", "Smart Pause"
        });
        pauseModeComboBox.setToolTipText(
            "Choose per-host adaptive pacing alone, a fixed run-wide cooldown, or an automatic smart cooldown.");
        pauseModeComboBox.setSelectedIndex(switch (defaults.pauseMode()) {
            case FIXED -> 1;
            case SMART -> 2;
            default -> 0;
        });
        fixedPauseSecondsField = new JTextField(String.valueOf(Math.max(1L,
            defaults.fixedPauseMillis() / 1_000L)), 5);
        pauseModeComboBox.addActionListener(e -> updatePauseFieldState());

        throttleButton = new JButton("Throttle...");
        throttleButton.setToolTipText("Configure in-flight concurrency and which responses signal a rate limit. "
            + "Pacing is automatic and adaptive.");
        throttleButton.addActionListener(e -> openThrottleDialog());
        updatePauseFieldState();
    }

    /** Returns the "Throttle..." button for embedding in host panel. */
    public JButton button() {
        return throttleButton;
    }

    public int concurrency() {
        return concurrencyField != null ? parsePositiveInt(concurrencyField, 1) : 1;
    }

    public int perHostConcurrency() {
        return perHostConcurrencyField != null ? parsePositiveInt(perHostConcurrencyField, 1) : 1;
    }

    public Set<Integer> throttleStatusCodes() {
        return SessionInputParsers.parseStatusCodes(throttleStatusCodesField.getText());
    }

    public String throttleStatusCodesText() {
        return throttleStatusCodesField.getText();
    }

    /** The selected pacing posture: ride hard (default) vs. cautious. */
    public ThrottleSettings.Posture posture() {
        return rideHardCheckbox.isSelected()
            ? ThrottleSettings.Posture.RIDE_HARD : ThrottleSettings.Posture.CONSERVATIVE;
    }

    public ThrottleSettings.PauseMode pauseMode() {
        if (!showGlobalPause) return ThrottleSettings.PauseMode.OFF;
        return switch (pauseModeComboBox.getSelectedIndex()) {
            case 1 -> ThrottleSettings.PauseMode.FIXED;
            case 2 -> ThrottleSettings.PauseMode.SMART;
            default -> ThrottleSettings.PauseMode.OFF;
        };
    }

    public long fixedPauseMillis() {
        return parsePositiveInt(fixedPauseSecondsField, 30) * 1_000L;
    }

    public void setEnabled(boolean enabled) {
        throttleStatusCodesField.setEnabled(enabled);
        rideHardCheckbox.setEnabled(enabled);
        pauseModeComboBox.setEnabled(enabled && showGlobalPause);
        fixedPauseSecondsField.setEnabled(enabled && showGlobalPause
            && pauseMode() == ThrottleSettings.PauseMode.FIXED);
        throttleButton.setEnabled(enabled);
        if (concurrencyField != null) concurrencyField.setEnabled(enabled);
        if (perHostConcurrencyField != null) perHostConcurrencyField.setEnabled(enabled);
    }

    private void openThrottleDialog() {
        Window owner = SwingUtilities.getWindowAncestor(throttleButton);
        JDialog dialog = new JDialog(owner, "Throttle settings", Dialog.ModalityType.MODELESS);
        JPanel content = new JPanel();
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        JTextArea adaptiveNote = new JTextArea(
            "Request pacing is automatic. Each host is driven adaptively just under its own rate "
            + "limit — there are no delay or requests-per-second knobs to tune. The settings below "
            + "bound how many requests may be in flight at once and which responses count as a rate "
            + "limit.");
        adaptiveNote.setEditable(false);
        adaptiveNote.setLineWrap(true);
        adaptiveNote.setWrapStyleWord(true);
        adaptiveNote.setOpaque(false);
        adaptiveNote.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        content.add(adaptiveNote);

        if (concurrencyField != null) {
            JPanel concurrencyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            concurrencyRow.add(new JLabel(concurrencyLabel + ":"));
            concurrencyRow.add(concurrencyField);
            if (perHostConcurrencyField != null) {
                concurrencyRow.add(new JLabel("Per-host:"));
                concurrencyRow.add(perHostConcurrencyField);
            } else {
                JLabel concurrencyHelp = new JLabel("(parallel attack families)");
                concurrencyHelp.setFont(concurrencyHelp.getFont().deriveFont(Font.ITALIC, 11f));
                concurrencyHelp.setForeground(Color.GRAY);
                concurrencyRow.add(concurrencyHelp);
            }
            content.add(concurrencyRow);
        }

        JPanel codesRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        codesRow.add(new JLabel("Throttle response codes:"));
        codesRow.add(throttleStatusCodesField);
        JLabel codesHelp = new JLabel("(comma-separated, e.g., 429,503)");
        codesHelp.setFont(codesHelp.getFont().deriveFont(Font.ITALIC, 11f));
        codesHelp.setForeground(Color.GRAY);
        codesRow.add(codesHelp);
        content.add(codesRow);

        content.add(Box.createVerticalStrut(8));
        JPanel postureRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        postureRow.add(rideHardCheckbox);
        content.add(postureRow);

        if (showGlobalPause) {
            content.add(Box.createVerticalStrut(8));
            JPanel pauseRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            pauseRow.add(new JLabel("Throttle pause mode:"));
            pauseRow.add(pauseModeComboBox);
            pauseRow.add(new JLabel("Fixed seconds:"));
            pauseRow.add(fixedPauseSecondsField);
            content.add(pauseRow);

            JTextArea pauseHelp = new JTextArea(
                "No global pause (adaptive) adjusts each host's rate independently and does not pause "
                + "the entire run; "
                + "a Retry-After response still pauses that individual host. "
                + "Fixed pause stops all hosts after any throttle response for the chosen time. "
                + "Smart Pause tolerates isolated throttles, pauses a saturated host after a sustained "
                + "streak or high rolling throttle ratio, and pauses the whole Sweep only when saturation "
                + "spans multiple hosts. It uses escalating 10-120 second cooldowns, then requires five "
                + "successful recovery probes before reopening. Retry-After is always honored.");
            pauseHelp.setEditable(false);
            pauseHelp.setLineWrap(true);
            pauseHelp.setWrapStyleWord(true);
            pauseHelp.setOpaque(false);
            content.add(pauseHelp);
        }

        content.add(Box.createVerticalStrut(6));

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonRow.add(closeButton);
        content.add(buttonRow);

        dialog.setContentPane(content);
        dialog.setSize(620, showGlobalPause ? 430 : 260);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private void updatePauseFieldState() {
        fixedPauseSecondsField.setEnabled(showGlobalPause
            && pauseModeComboBox.getSelectedIndex() == 1 && throttleButton.isEnabled());
    }

    private static String formatStatusCodes(Set<Integer> codes) {
        if (codes == null || codes.isEmpty()) {
            return "429,503";
        }
        return codes.stream()
            .sorted()
            .map(String::valueOf)
            .collect(Collectors.joining(","));
    }

    private static int parsePositiveInt(JTextField field, int fallback) {
        try {
            return Math.max(1, Integer.parseInt(field.getText().trim()));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
