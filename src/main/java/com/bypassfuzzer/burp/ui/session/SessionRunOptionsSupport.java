package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.session.SessionRunOptions;

/**
 * Shared collection logic for attack-selection and run-options panels.
 */
public final class SessionRunOptionsSupport {

    private SessionRunOptionsSupport() {
    }

    public static SessionRunOptions collect(AttackSelectionPanel attackSelectionPanel, RunOptionsPanel runOptionsPanel) {
        int concurrency;
        try {
            concurrency = Math.max(1, Integer.parseInt(runOptionsPanel.concurrencyText().trim()));
        } catch (NumberFormatException e) {
            concurrency = 1;
        }

        return new SessionRunOptions(
            attackSelectionPanel.isHeaderAttackEnabled(),
            attackSelectionPanel.isPathAttackEnabled(),
            attackSelectionPanel.isVerbAttackEnabled(),
            attackSelectionPanel.isParamAttackEnabled(),
            attackSelectionPanel.isTrailingDotAttackEnabled(),
            attackSelectionPanel.isTrailingSlashAttackEnabled(),
            attackSelectionPanel.isExtensionAttackEnabled(),
            attackSelectionPanel.isContentTypeAttackEnabled(),
            attackSelectionPanel.isEncodingAttackEnabled(),
            attackSelectionPanel.isProtocolAttackEnabled(),
            attackSelectionPanel.isCaseAttackEnabled(),
            runOptionsPanel.isCollaboratorEnabled(),
            attackSelectionPanel.isCookieParamAttackEnabled(),
            runOptionsPanel.isFuzzExistingCookiesEnabled(),
            concurrency,
            runOptionsPanel.perHostConcurrency(),
            SessionInputParsers.parseStatusCodes(runOptionsPanel.throttleStatusCodesText()),
            runOptionsPanel.posture(),
            runOptionsPanel.pauseMode(),
            runOptionsPanel.fixedPauseMillis(),
            runOptionsPanel.requestHeaders(),
            runOptionsPanel.userAgentMode(),
            runOptionsPanel.userAgentRandomizationSeed()
        );
    }
}
