package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.http.ConfiguredHeader;

import javax.swing.*;
import java.awt.*;
import java.util.Set;

public class RunOptionsPanel extends JPanel {

    private final JCheckBox collaboratorCheckbox;
    private final JCheckBox fuzzExistingCookiesCheckbox;
    private final ThrottleSettingsControl throttleControl;
    private final RequestHeadersControl requestHeadersControl;
    private long userAgentRandomizationSeed;

    public RunOptionsPanel(FuzzerConfig config, boolean collaboratorAvailable) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Options"));

        JPanel collabRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        collaboratorCheckbox = new JCheckBox("Include Collaborator payloads in headers?", config.isEnableCollaboratorPayloads());
        JLabel collabInfoIcon = null;
        if (!collaboratorAvailable) {
            collaboratorCheckbox.setEnabled(false);
            collaboratorCheckbox.setSelected(false);
            collaboratorCheckbox.setToolTipText("Burp Collaborator is not available. Requires Burp Suite Professional with Collaborator configured.");

            collabInfoIcon = new JLabel("\u24d8");
            collabInfoIcon.setForeground(new Color(100, 100, 100));
            collabInfoIcon.setToolTipText("Burp Collaborator is not available. Requires Burp Suite Professional with Collaborator configured.");
            collabInfoIcon.setCursor(new Cursor(Cursor.HAND_CURSOR));
        }
        collabRow.add(collaboratorCheckbox);
        if (collabInfoIcon != null) {
            collabRow.add(collabInfoIcon);
        }
        add(collabRow);

        JPanel fuzzCookiesRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        fuzzExistingCookiesCheckbox = new JCheckBox("Debug Cookies: also fuzz existing cookies in request", config.isEnableFuzzExistingCookies());
        fuzzExistingCookiesCheckbox.setToolTipText("When enabled, tries debug values on cookies already in the request");
        fuzzCookiesRow.add(fuzzExistingCookiesCheckbox);
        add(fuzzCookiesRow);

        throttleControl = new ThrottleSettingsControl(ThrottleDefaults.forBypassFuzzer(config));

        JPanel throttleButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        throttleButtonRow.add(throttleControl.button());
        add(throttleButtonRow);

        JPanel headersRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        requestHeadersControl = new RequestHeadersControl(this);
        requestHeadersControl.setHeaders(config.getRequestHeaders());
        requestHeadersControl.setUserAgentMode(config.getUserAgentMode());
        userAgentRandomizationSeed = config.getUserAgentRandomizationSeed();
        headersRow.add(requestHeadersControl.button());
        add(headersRow);
    }

    public boolean isCollaboratorEnabled() {
        return collaboratorCheckbox.isSelected();
    }

    public void setCollaboratorEnabled(boolean enabled) {
        collaboratorCheckbox.setSelected(enabled);
    }

    public boolean isFuzzExistingCookiesEnabled() {
        return fuzzExistingCookiesCheckbox.isSelected();
    }

    public String concurrencyText() {
        return String.valueOf(throttleControl.concurrency());
    }

    public int perHostConcurrency() { return throttleControl.perHostConcurrency(); }

    public String throttleStatusCodesText() {
        return throttleControl.throttleStatusCodesText();
    }

    public com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture posture() {
        return throttleControl.posture();
    }

    public com.bypassfuzzer.burp.core.throttle.ThrottleSettings.PauseMode pauseMode() {
        return throttleControl.pauseMode();
    }

    public long fixedPauseMillis() { return throttleControl.fixedPauseMillis(); }

    public java.util.List<ConfiguredHeader> requestHeaders() {
        return requestHeadersControl.headers();
    }

    public com.bypassfuzzer.burp.http.UserAgentMode userAgentMode() {
        return requestHeadersControl.userAgentMode();
    }

    public long userAgentRandomizationSeed() {
        if (userAgentMode() == com.bypassfuzzer.burp.http.UserAgentMode.DISABLED) return 0L;
        if (userAgentRandomizationSeed == 0L) {
            userAgentRandomizationSeed = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        }
        return userAgentRandomizationSeed;
    }

    public void setControlsEnabled(boolean enabled, boolean collaboratorAvailable) {
        fuzzExistingCookiesCheckbox.setEnabled(enabled);
        throttleControl.setEnabled(enabled);
        requestHeadersControl.setEnabled(enabled);
        collaboratorCheckbox.setEnabled(enabled && collaboratorAvailable);
    }
}
