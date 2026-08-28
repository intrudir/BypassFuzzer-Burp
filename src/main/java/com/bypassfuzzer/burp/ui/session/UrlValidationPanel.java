package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationCandidateFinder;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationEngine;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationOptions;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationPayload;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationPayloadGenerator;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationCandidate;
import com.bypassfuzzer.burp.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.ui.dashboard.ActivitySnapshot;
import com.bypassfuzzer.burp.ui.dashboard.ActivityState;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Dedicated session tab for URL validation bypass testing.
 */
public class UrlValidationPanel extends JPanel {

    private static final int CONFIG_LEFT_PANEL_WIDTH = 560;

    private final MontoyaApi api;
    private final HttpRequest originalRequest;
    private final UrlValidationEngine engine;
    private final UrlValidationCandidateFinder candidateFinder = new UrlValidationCandidateFinder();
    private final UrlValidationPayloadGenerator payloadGenerator = new UrlValidationPayloadGenerator();
    private final GlobalTrafficGovernor globalGovernor;

    private JButton startButton;
    private JButton stopButton;
    private JButton pauseButton;
    private JButton configButton;
    private JButton resetRequestButton;
    private JButton viewPayloadsButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private JLabel configWarningLabel;
    private UrlValidationOptionsPanel optionsPanel;
    private SessionResultsWorkspace resultsWorkspace;
    private HttpRequestEditor requestEditor;
    private JDialog configDialog;
    private volatile boolean shuttingDown = false;
    private volatile boolean stopRequested = false;
    private volatile boolean hasStarted = false;

    public UrlValidationPanel(MontoyaApi api, HttpRequest request) {
        this(api, request, new GlobalTrafficGovernor());
    }

    public UrlValidationPanel(MontoyaApi api, HttpRequest request,
                              GlobalTrafficGovernor globalGovernor) {
        super(new BorderLayout(0, 8));
        this.api = api;
        this.originalRequest = request;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.engine = new UrlValidationEngine(api, this.globalGovernor);
        initializeUi();
        applyFilters();
    }

    public void cleanup() {
        shuttingDown = true;
        engine.cleanup();
        if (resultsWorkspace != null) {
            resultsWorkspace.cleanup();
        }
        if (configDialog != null) {
            configDialog.dispose();
        }
    }

    public ActivitySnapshot activitySnapshot(String id, String mode, String target) {
        ActivityState state;
        if (shuttingDown) state = ActivityState.DISPOSED;
        else if (resultsWorkspace.isRetryRunning()) {
            state = resultsWorkspace.isRetryPaused() ? ActivityState.PAUSED : ActivityState.RETRYING;
        } else if (engine.isRunning()) state = engine.isPaused() ? ActivityState.PAUSED : ActivityState.RUNNING;
        else if (stopRequested) state = ActivityState.STOPPED;
        else state = hasStarted ? ActivityState.COMPLETED : ActivityState.IDLE;
        long httpSent = totalHttpRequestsSent();
        int sent = (int) Math.min(Integer.MAX_VALUE, httpSent);
        int recorded = resultsWorkspace.allResultsCount();
        return new ActivitySnapshot(id, mode, target, state,
            recorded + " result" + (recorded == 1 ? "" : "s") + "; " + httpSent + " HTTP sent", sent);
    }

    public void pauseActivity() {
        if (resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.pauseThrottleRetry();
            pauseButton.setText("Resume");
            statusLabel.setText(resultsWorkspace.retryStatusText());
        } else if (engine.isRunning() && !engine.isPaused()) togglePause();
    }

    public void resumeActivity() {
        if (resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.resumeThrottleRetry();
            pauseButton.setText("Pause");
            statusLabel.setText(resultsWorkspace.retryStatusText());
        } else if (engine.isRunning() && engine.isPaused()) togglePause();
    }

    public void stopActivity() {
        if (resultsWorkspace.isRetryRunning()) resultsWorkspace.stopThrottleRetry();
        else if (engine.isRunning()) stopValidation();
    }

    private void initializeUi() {
        requestEditor = api.userInterface().createHttpRequestEditor();
        requestEditor.setRequest(originalRequest);
        optionsPanel = new UrlValidationOptionsPanel(originalRequest, isCollaboratorAvailable());

        add(buildHeaderPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
    }

    private JPanel buildHeaderPanel() {
        JPanel headerPanel = new JPanel(new BorderLayout(0, 6));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 0, 8));

        JPanel actionRow = new JPanel(new BorderLayout());
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopValidation());
        pauseButton = new JButton("Pause");
        pauseButton.setEnabled(false);
        pauseButton.addActionListener(e -> togglePause());

        configButton = new JButton("Configure Attack");
        configButton.addActionListener(e -> openConfigDialog());

        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());

        buttonRow.add(stopButton);
        buttonRow.add(pauseButton);
        buttonRow.add(configButton);
        buttonRow.add(clearButton);

        statusLabel = new JLabel("Open Configure Attack, place {INJECT} markers in the request, then run URL validation payloads.");
        actionRow.add(buttonRow, BorderLayout.WEST);
        actionRow.add(statusLabel, BorderLayout.CENTER);

        warningLabel = createWarningLabel();

        headerPanel.add(actionRow, BorderLayout.NORTH);
        headerPanel.add(warningLabel, BorderLayout.SOUTH);
        return headerPanel;
    }

    private JSplitPane buildCenterPanel() {
        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.URL_VALIDATION,
            true,
            globalGovernor
        );
        resultsWorkspace.setResultsChangedListener(ignored -> updateResultStatus());
        return resultsWorkspace.component();
    }

    private JScrollPane wrapSidebarTab(JPanel panel) {
        JScrollPane scrollPane = new JScrollPane(panel);
        scrollPane.setBorder(null);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        return scrollPane;
    }

    private JPanel buildSetupPanel() {
        JPanel setupPanel = new JPanel();
        setupPanel.setLayout(new BoxLayout(setupPanel, BoxLayout.Y_AXIS));
        setupPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        setupPanel.add(optionsPanel);
        setupPanel.add(Box.createVerticalStrut(8));
        configWarningLabel = createWarningLabel();
        configWarningLabel.setAlignmentX(LEFT_ALIGNMENT);
        setupPanel.add(configWarningLabel);
        setupPanel.add(buildSetupActions());
        return setupPanel;
    }

    private JPanel buildSetupActions() {
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 10));
        actionsPanel.setAlignmentX(LEFT_ALIGNMENT);

        viewPayloadsButton = new JButton("View Payloads");
        viewPayloadsButton.addActionListener(e -> openPayloadPreviewDialog());

        JButton copyPayloadsButton = new JButton("Copy Payloads");
        copyPayloadsButton.addActionListener(e -> copyPayloadsToClipboard());

        actionsPanel.add(viewPayloadsButton);
        actionsPanel.add(javax.swing.Box.createHorizontalStrut(6));
        actionsPanel.add(copyPayloadsButton);
        return actionsPanel;
    }

    private JDialog buildConfigDialog() {
        JDialog dialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Configure Attack", false);
        dialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
        dialog.setContentPane(buildConfigDialogContent());
        dialog.setSize(new Dimension(1180, 760));
        dialog.setMinimumSize(new Dimension(900, 560));
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        return dialog;
    }

    private JSplitPane buildConfigDialogContent() {
        JScrollPane setupScrollPane = wrapSidebarTab(buildSetupPanel());
        setupScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        setupScrollPane.setMinimumSize(new Dimension(CONFIG_LEFT_PANEL_WIDTH, 300));
        setupScrollPane.setPreferredSize(new Dimension(CONFIG_LEFT_PANEL_WIDTH, 300));

        JSplitPane configSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, setupScrollPane, buildRequestWorkbench());
        configSplit.setDividerSize(6);
        configSplit.setResizeWeight(0.0);
        configSplit.setBorder(null);
        SwingUtilities.invokeLater(() -> configSplit.setDividerLocation(CONFIG_LEFT_PANEL_WIDTH));
        return configSplit;
    }

    private JPanel buildRequestWorkbench() {
        JPanel requestPanel = new JPanel(new BorderLayout(0, 8));
        requestPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel workbenchHeader = new JPanel();
        workbenchHeader.setLayout(new BoxLayout(workbenchHeader, BoxLayout.Y_AXIS));
        workbenchHeader.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Request Workbench"),
            BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));

        JTextArea descriptionLabel = new JTextArea("This is the exact request that URL Validation will send.");
        descriptionLabel.setEditable(false);
        descriptionLabel.setFocusable(false);
        descriptionLabel.setOpaque(false);
        descriptionLabel.setLineWrap(true);
        descriptionLabel.setWrapStyleWord(true);
        descriptionLabel.setBorder(null);
        descriptionLabel.setAlignmentX(LEFT_ALIGNMENT);
        JPanel requestButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        requestButtons.setAlignmentX(LEFT_ALIGNMENT);

        startButton = new JButton("Start URL Validation");
        startButton.addActionListener(e -> startValidation());
        resetRequestButton = new JButton("Reset Request");
        resetRequestButton.addActionListener(e -> resetEditedRequest());

        requestButtons.add(startButton);
        requestButtons.add(resetRequestButton);
        workbenchHeader.add(descriptionLabel);
        workbenchHeader.add(requestButtons);

        requestPanel.add(workbenchHeader, BorderLayout.NORTH);
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        return requestPanel;
    }

    private void startValidation() {
        if (resultsWorkspace.isRetryRunning()) {
            statusLabel.setText("Wait for the throttled-request retry pass to finish.");
            return;
        }
        HttpRequest activeRequest = currentRequest();
        UrlValidationOptions options = collectOptions();
        if (options == null) {
            return;
        }
        if (!options.useCollaboratorPayloads() && options.normalizedAttackerHost().isBlank()) {
            showWarning("Enter an attacker host before starting.");
            return;
        }

        if (!hasRunnableTargets(activeRequest, options)) {
            return;
        }

        hideWarnings();
        stopRequested = false;
        setControlsEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("URL validation fuzzing in progress...");
        resultsWorkspace.configureThrottleRetries(options.throttleSettings());
        resultsWorkspace.setPrimaryRunActive(true);

        boolean started = engine.start(activeRequest, options, this::addResult, this::handleCompletion);
        if (!started) {
            resultsWorkspace.setPrimaryRunActive(false);
            updateIdleUi("Unable to start URL validation fuzzing");
            return;
        }
        hasStarted = true;
        pauseButton.setText("Pause");
        pauseButton.setEnabled(true);

        if (configDialog != null) {
            configDialog.setVisible(false);
        }
        showWarning("Using marker " + options.normalizedMarkerText() + " in the edited request.");
    }

    private void stopValidation() {
        stopRequested = true;
        engine.stop();
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        pauseButton.setEnabled(false);
        statusLabel.setText("Stopping URL validation fuzzing...");
    }

    private void togglePause() {
        if (!engine.isRunning()) return;
        if (engine.isPaused()) {
            engine.resume();
            pauseButton.setText("Pause");
            statusLabel.setText("URL validation resumed...");
        } else {
            engine.pause();
            pauseButton.setText("Resume");
            statusLabel.setText("Paused. Already-sent requests may still finish; no new requests will be sent.");
        }
    }

    private void clearResults() {
        resultsWorkspace.clear();
        statusLabel.setText("Results cleared");
    }

    private void addResult(AttackResult result) {
        resultsWorkspace.enqueueResult(result);
    }

    private void updateResultStatus() {
        long totalSent = totalHttpRequestsSent();
        int recorded = resultsWorkspace.allResultsCount();
        int showing = resultsWorkspace.shownResultsCount();
        statusLabel.setText(engine.isPaused()
            ? "Paused (" + metrics(totalSent, recorded, showing) + ")"
            : engine.isRunning()
                ? "URL Validation... (" + metrics(totalSent, recorded, showing) + ")"
                : "Completed: " + metrics(totalSent, recorded, showing));
    }

    private void handleCompletion() {
        resultsWorkspace.afterPendingResults(() -> {
            resultsWorkspace.setPrimaryRunActive(false);
            if (shuttingDown) {
                startButton.setEnabled(false);
                stopButton.setEnabled(false);
                pauseButton.setEnabled(false);
                return;
            }

            long totalSent = totalHttpRequestsSent();
            int recorded = resultsWorkspace.allResultsCount();
            int showing = resultsWorkspace.shownResultsCount();
            updateIdleUi((stopRequested ? "Stopped: " : "Completed: ")
                + metrics(totalSent, recorded, showing));
        });
    }

    private long totalHttpRequestsSent() {
        return engine.httpRequestsSent() + resultsWorkspace.retryRequestCount();
    }

    private String metrics(long sent, int recorded, int showing) {
        return sent + " HTTP request(s) sent; " + recorded + " result(s) recorded"
            + (showing == recorded ? "" : ", showing " + showing);
    }

    private void applyFilters() {
        resultsWorkspace.applyFilters();
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        pauseButton.setText("Pause");
        pauseButton.setEnabled(false);
        setControlsEnabled(true);
    }

    private void setControlsEnabled(boolean enabled) {
        if (shuttingDown) {
            return;
        }

        optionsPanel.setControlsEnabled(enabled);
        startButton.setEnabled(enabled);
        configButton.setEnabled(enabled);
        resetRequestButton.setEnabled(enabled);
        viewPayloadsButton.setEnabled(enabled);
    }

    private UrlValidationOptions collectOptions() {
        return new UrlValidationOptions(
            optionsPanel.markerText(),
            optionsPanel.allowedHostText(),
            optionsPanel.attackerHostText(),
            optionsPanel.useCollaboratorPayloads(),
            optionsPanel.attackerScheme(),
            optionsPanel.payloadFamilies(),
            optionsPanel.attackSettings(),
            optionsPanel.encodings(),
            SessionInputParsers.parseStatusCodes(optionsPanel.throttleStatusCodesText()),
            optionsPanel.concurrency(),
            optionsPanel.perHostConcurrency(),
            optionsPanel.posture(),
            optionsPanel.pauseMode(),
            optionsPanel.fixedPauseMillis(),
            optionsPanel.requestHeaders(),
            optionsPanel.userAgentMode(),
            optionsPanel.userAgentRandomizationSeed()
        );
    }

    private void showWarning(String text) {
        warningLabel.setText(text);
        warningLabel.setVisible(true);
        if (configWarningLabel != null) {
            configWarningLabel.setText(text);
            configWarningLabel.setVisible(true);
        }
    }

    private void hideWarnings() {
        warningLabel.setVisible(false);
        if (configWarningLabel != null) {
            configWarningLabel.setVisible(false);
        }
    }

    private void resetEditedRequest() {
        requestEditor.setRequest(originalRequest);
    }

    private HttpRequest currentRequest() {
        HttpRequest editedRequest = requestEditor.getRequest();
        return editedRequest == null ? originalRequest : editedRequest;
    }

    private void openConfigDialog() {
        if (configDialog == null) {
            configDialog = buildConfigDialog();
        }

        configDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        configDialog.setVisible(true);
        configDialog.toFront();
        configDialog.requestFocus();
    }

    private void openPayloadPreviewDialog() {
        UrlValidationOptions options = collectOptions();
        if (options == null) {
            return;
        }
        if (!options.useCollaboratorPayloads() && options.normalizedAttackerHost().isBlank()) {
            showWarning("Enter an attacker host before viewing payloads.");
            return;
        }
        if (options.normalizedPayloadFamilies().isEmpty()) {
            showWarning("Select at least one payload family before viewing payloads.");
            return;
        }
        if (options.normalizedAttackSettings().isEmpty()) {
            showWarning("Select at least one attack setting before viewing payloads.");
            return;
        }

        UrlValidationCandidate previewCandidate = new UrlValidationCandidate(
            options.normalizedMarkerText(),
            options.normalizedMarkerText(),
            "marker",
            (request, newValue) -> request
        );
        java.util.List<UrlValidationPayload> payloads = payloadGenerator.generate(previewCandidate, options);

        JTextArea payloadText = new JTextArea(renderPayloadPreview(payloads));
        payloadText.setEditable(false);
        payloadText.setLineWrap(false);
        payloadText.setWrapStyleWord(false);
        payloadText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadText.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(payloadText);
        scrollPane.setPreferredSize(new Dimension(860, 520));

        JDialog previewDialog = new JDialog(configDialog, "Payload Preview (" + payloads.size() + ")", false);
        previewDialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        previewDialog.setLayout(new BorderLayout(0, 8));

        JLabel header = new JLabel(
            "Previewing " + payloads.size() + " payloads for "
                + options.normalizedPayloadFamilies().stream().map(Object::toString).collect(Collectors.joining(", "))
                + " with " + options.effectiveEncodings().stream().map(UrlValidationEncoding::label).collect(Collectors.joining(", "))
        );
        header.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));

        previewDialog.add(header, BorderLayout.NORTH);
        previewDialog.add(scrollPane, BorderLayout.CENTER);
        previewDialog.pack();
        previewDialog.setLocationRelativeTo(configDialog);
        previewDialog.setVisible(true);
    }

    private void copyPayloadsToClipboard() {
        UrlValidationOptions options = collectOptions();
        if (options == null) return;

        UrlValidationCandidate candidate = new UrlValidationCandidate(
            options.normalizedMarkerText(), options.normalizedMarkerText(), "marker",
            (request, newValue) -> request
        );
        java.util.List<UrlValidationPayload> payloads = payloadGenerator.generate(candidate, options);
        String text = payloads.stream()
            .map(UrlValidationPayload::value)
            .collect(Collectors.joining(System.lineSeparator()));
        java.awt.Toolkit.getDefaultToolkit()
            .getSystemClipboard()
            .setContents(new java.awt.datatransfer.StringSelection(text), null);

        javax.swing.JOptionPane.showMessageDialog(
            configDialog,
            payloads.size() + " payloads copied to clipboard.",
            "Copied",
            javax.swing.JOptionPane.INFORMATION_MESSAGE
        );
    }

    private String renderPayloadPreview(java.util.List<UrlValidationPayload> payloads) {
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("%-14s %-16s %-15s %s%n", "Family", "Category", "Encoding", "Payload"));
        builder.append(String.format("%-14s %-16s %-15s %s%n", "------", "--------", "--------", "-------"));
        for (UrlValidationPayload payload : payloads) {
            // Sanitize control chars so they don't break the fixed-width display.
            // The actual payload sent on the wire is unaffected — this is display-only.
            String displayValue = payload.value()
                .replace("\r\n", "\\r\\n").replace("\n", "\\n")
                .replace("\r", "\\r").replace("\t", "\\t");
            builder.append(String.format(
                "%-14s %-16s %-15s %s%n",
                payload.family().displayName(),
                payload.category(),
                payload.encoding().label(),
                displayValue
            ));
        }
        return builder.toString();
    }

    private boolean hasRunnableTargets(HttpRequest request, UrlValidationOptions options) {
        int markerCount = candidateFinder.countMarkerOccurrences(request, options.normalizedMarkerText());
        if (markerCount == 0) {
            showWarning("Add " + options.normalizedMarkerText() + " to the request editor, then start again.");
            return false;
        }
        if (options.normalizedPayloadFamilies().isEmpty()) {
            showWarning("Select at least one payload family before starting.");
            return false;
        }
        if (options.normalizedAttackSettings().isEmpty()) {
            showWarning("Select at least one attack setting before starting.");
            return false;
        }
        return true;
    }

    private boolean isCollaboratorAvailable() {
        return CollaboratorSupport.isAvailable(api);
    }
    private JLabel createWarningLabel() {
        JLabel label = new JLabel("");
        label.setForeground(new java.awt.Color(204, 102, 0));
        label.setVisible(false);
        return label;
    }
}
