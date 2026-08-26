package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.http.ConfiguredHeader;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import java.awt.FlowLayout;

/**
 * IDOR-specific execution options.
 */
public class IdorRunOptionsPanel extends JPanel {

    private final ThrottleSettingsControl throttleControl;
    private final RequestHeadersControl requestHeadersControl;
    private long userAgentRandomizationSeed;

    public IdorRunOptionsPanel(IdorRunOptions defaults) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("IDOR Options"));

        throttleControl = new ThrottleSettingsControl(ThrottleDefaults.forIdor(defaults));

        JPanel throttleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        throttleRow.add(throttleControl.button());
        add(throttleRow);

        JPanel headersRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        requestHeadersControl = new RequestHeadersControl(this);
        requestHeadersControl.setHeaders(defaults.requestHeaders());
        requestHeadersControl.setUserAgentMode(defaults.userAgentMode());
        userAgentRandomizationSeed = defaults.userAgentRandomizationSeed();
        headersRow.add(requestHeadersControl.button());
        add(headersRow);
    }

    public IdorRunOptions collect() {
        return new IdorRunOptions(
            throttleControl.throttleStatusCodes(),
            throttleControl.concurrency(),
            throttleControl.perHostConcurrency(),
            throttleControl.posture(),
            throttleControl.pauseMode(),
            throttleControl.fixedPauseMillis(),
            requestHeadersControl.headers(),
            requestHeadersControl.userAgentMode(),
            effectiveUserAgentSeed()
        );
    }

    private long effectiveUserAgentSeed() {
        if (requestHeadersControl.userAgentMode() == com.bypassfuzzer.burp.http.UserAgentMode.DISABLED) {
            return 0L;
        }
        if (userAgentRandomizationSeed == 0L) {
            userAgentRandomizationSeed = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        }
        return userAgentRandomizationSeed;
    }

    public void setControlsEnabled(boolean enabled) {
        throttleControl.setEnabled(enabled);
        requestHeadersControl.setEnabled(enabled);
    }
}
